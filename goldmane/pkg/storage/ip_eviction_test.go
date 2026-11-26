// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage_test

import (
	"cmp"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
)

// ipSetModel is a reference for a DiachronicFlow's source IP set. For each tracked IP, windows
// holds the starts of the windows it was seen in, and lastSeen holds the newest window start it
// has been recorded in, even after rollover drops that window.
type ipSetModel struct {
	windows  map[string]map[int64]bool
	lastSeen map[string]int64
}

func newIPSetModel() *ipSetModel {
	return &ipSetModel{windows: map[string]map[int64]bool{}, lastSeen: map[string]int64{}}
}

// add records ips in the window at start, then keeps the MaxIPsPerFlow most recently seen IPs,
// dropping the lower address among equally recent ones. It does this the slow, obvious way, by
// ranking every IP, so it can check the real flow's faster eviction.
func (m *ipSetModel) add(ips []string, start int64) {
	// Record each IP as seen in this window, and move its lastSeen forward if this window is newer.
	for _, ip := range ips {
		// The real flow skips empty addresses, so the model does too.
		if ip == "" {
			continue
		}

		// Check whether the model has seen this IP before. If it hasn't, give it an empty set of
		// windows before recording this one.
		if m.windows[ip] == nil {
			m.windows[ip] = map[int64]bool{}
		}
		m.windows[ip][start] = true
		m.lastSeen[ip] = max(m.lastSeen[ip], start)
	}

	// Rank every tracked IP from least to most recently seen, so the front of the list is what the
	// real flow should evict.
	ranked := make([]string, 0, len(m.lastSeen))
	for ip := range m.lastSeen {
		ranked = append(ranked, ip)
	}
	slices.SortFunc(ranked, func(a, b string) int {
		// If the two were last seen in different windows, the older one ranks lower. Otherwise we
		// fall back to comparing addresses, as the real flow does.
		if m.lastSeen[a] != m.lastSeen[b] {
			return cmp.Compare(m.lastSeen[a], m.lastSeen[b])
		}
		return strings.Compare(a, b)
	})

	// Forget the lowest-ranked IPs beyond the cap. When the set fits, this range is empty.
	for _, ip := range ranked[:max(0, len(ranked)-storage.MaxIPsPerFlow)] {
		m.forget(ip)
	}
}

// rollover drops every window that ends at or before limiter, and any IP left with no windows.
func (m *ipSetModel) rollover(limiter int64) {
	for ip, starts := range m.windows {
		// Forget each window this IP was seen in that ended at or before the limiter.
		for s := range starts {
			// A window ends at its start plus the interval, so it has expired if that's at or
			// before the limiter.
			if s+ipTestInterval <= limiter {
				delete(starts, s)
			}
		}

		// An IP with no windows left drops out of the set entirely.
		if len(starts) == 0 {
			m.forget(ip)
		}
	}
}

func (m *ipSetModel) forget(ip string) {
	delete(m.windows, ip)
	delete(m.lastSeen, ip)
}

// windowIPs returns the sorted IPs the model holds for the window at start.
func (m *ipSetModel) windowIPs(start int64) []string {
	var ips []string
	for ip, starts := range m.windows {
		if starts[start] {
			ips = append(ips, ip)
		}
	}
	slices.Sort(ips)
	return ips
}

// TestDiachronicFlow_IPSetEvictionMatchesModel drives a flow and the reference model with the same
// random updates, including repeats, late arrivals, duplicates, empty addresses and rollovers, and
// checks every live window reports the model's IPs after each step.
func TestDiachronicFlow_IPSetEvictionMatchesModel(t *testing.T) {
	// A fixed seed makes every run identical, so a failing trial can be reproduced.
	rng := rand.New(rand.NewPCG(1, 2))
	for trial := range 200 {
		// Each trial starts a fresh flow and model. Its address pool ranges from half the cap to
		// several times it, so some trials never evict and others evict on most updates.
		key := ipTestFlowKey()
		flow := storage.NewDiachronicFlow(key, 0)
		model := newIPSetModel()
		pool := 50 + rng.IntN(400)
		var limiter int64

		// Each step sends one random update, sometimes rolls over, then compares recent windows.
		// Steps start at 8 so the eight windows we look back over are never negative.
		for step := 8; step < 68; step++ {
			// A quarter of updates land in the current window, and the rest arrive one to three
			// windows late.
			window := step - rng.IntN(4)

			// Build a batch of addresses drawn from the pool. Drawing with replacement gives us
			// duplicates, and about one address in fifty is blanked to cover empty addresses.
			ips := make([]string, rng.IntN(150))
			for i := range ips {
				n := rng.IntN(pool)
				ips[i] = fmt.Sprintf("10.0.%d.%d", n/256, n%256)
				if rng.IntN(50) == 0 {
					ips[i] = ""
				}
			}

			// Send the same update to the flow and the model.
			addIPs(flow, key, window, ips...)
			model.add(ips, int64(window*ipTestInterval))

			// On about one step in five, roll both over to a limiter a few windows back, so old
			// windows expire. Like the real ring, the limiter never moves backward.
			if rng.IntN(5) == 0 {
				limiter = max(limiter, int64((step-4-rng.IntN(4))*ipTestInterval))
				flow.Rollover(limiter)
				model.rollover(limiter)
			}

			// Compare the current window and the eight before it. That can reach past the oldest
			// window a rollover keeps, so we also check rolled-over windows come back empty.
			for w := step - 8; w <= step; w++ {
				start := int64(w * ipTestInterval)

				// Check whether the flow has anything for this window. If Aggregate returns nil, it
				// holds no IPs there, which the model reports as an empty list.
				var got []string
				if f := flow.Aggregate(start, start+ipTestInterval); f != nil {
					got = f.SourceIps
				}
				require.Equal(t, model.windowIPs(start), got, "trial %d step %d window %d", trial, step, w)
			}
		}
	}
}

// TestDiachronicFlow_IPSetEvictionLargerThanCap covers an update that brings more new IPs than
// the cap into a full set, so more than MaxIPsPerFlow IPs are evicted at once. The older window
// should lose every IP, and the new window should keep only its highest addresses.
func TestDiachronicFlow_IPSetEvictionLargerThanCap(t *testing.T) {
	const extraIPs = 50

	// Fill the set in window 0, then send window 1 extraIPs more new addresses than the cap.
	key := ipTestFlowKey()
	flow := storage.NewDiachronicFlow(key, 0)
	addIPs(flow, key, 0, distinctIPs(0, storage.MaxIPsPerFlow)...)
	incoming := distinctIPs(1000, storage.MaxIPsPerFlow+extraIPs)
	addIPs(flow, key, 1, incoming...)

	// Every IP from window 0 is older than the new ones, so window 0 loses them all. The new IPs
	// are equally recent, so window 1 drops its extraIPs lowest addresses.
	require.Nil(t, flow.Aggregate(0, ipTestInterval).SourceIps)
	want := slices.Sorted(slices.Values(incoming))[extraIPs:]
	require.Equal(t, want, flow.Aggregate(ipTestInterval, 2*ipTestInterval).SourceIps)
}

// ringHistory is how many windows Goldmane keeps by default, an hour of history. The benchmarks
// roll their flow over at that depth, as the ring would.
const ringHistory = 240

// rollOverLikeRing rolls flow over after adding window, dropping the oldest window once the flow
// holds more than ringHistory of them, as the ring would.
func rollOverLikeRing(flow *storage.DiachronicFlow, window int) {
	// Check whether the flow has filled its history yet.
	if window >= ringHistory {
		// It has, so the window ringHistory back from this one expires.
		flow.Rollover(int64((window - ringHistory) * ipTestInterval))
	}
}

// BenchmarkDiachronicFlow_AddFlowNewIPsIntoFullSet adds a flow per window to a full IP set,
// carrying a few addresses the set has never seen plus some it already tracks, so each new IP
// evicts one tracked IP.
func BenchmarkDiachronicFlow_AddFlowNewIPsIntoFullSet(b *testing.B) {
	// repeated is how many already-tracked IPs each update carries alongside the new ones.
	const repeated = 10
	for _, newPerUpdate := range []int{1, 2, 5, 10, 25} {
		b.Run(fmt.Sprintf("new=%d", newPerUpdate), func(b *testing.B) {
			// Build the addresses up front, so the benchmark doesn't time it. With 131072 of them, a
			// run takes a long time to wrap around, and by then the set evicted those IPs long ago.
			key := ipTestFlowKey()
			ips := distinctIPs(0, 1<<17)
			ipAt := func(i int) string { return ips[i%len(ips)] }

			// Fill the set with one IP per window, so every entry has a different lastSeen.
			flow := storage.NewDiachronicFlow(key, 0)
			for w := range storage.MaxIPsPerFlow {
				addIPs(flow, key, w, ipAt(w))
			}

			next, window := storage.MaxIPsPerFlow, storage.MaxIPsPerFlow
			batch := make([]string, 0, repeated+newPerUpdate)
			b.ReportAllocs()
			for b.Loop() {
				// Each update carries the repeated most recently added IPs, which are still in the
				// set, followed by newPerUpdate addresses it has never seen.
				batch = batch[:0]
				for i := next - repeated; i < next+newPerUpdate; i++ {
					batch = append(batch, ipAt(i))
				}
				addIPs(flow, key, window, batch...)
				rollOverLikeRing(flow, window)
				next += newPerUpdate
				window++
			}
		})
	}
}

// BenchmarkDiachronicFlow_AddFlowChurningIPs adds a flow per window carrying MaxIPsPerFlow
// addresses the full set has never seen, rolling over as the ring would, so every update evicts
// the whole set.
func BenchmarkDiachronicFlow_AddFlowChurningIPs(b *testing.B) {
	// Build more batches than ringHistory, so by the time a batch comes around again, rollover has
	// removed its IPs and they arrive as new.
	key := ipTestFlowKey()
	batches := make([][]string, 256)
	for i := range batches {
		batches[i] = distinctIPs(i*storage.MaxIPsPerFlow, storage.MaxIPsPerFlow)
	}
	flow := storage.NewDiachronicFlow(key, 0)

	b.ReportAllocs()
	var window int
	for b.Loop() {
		addIPs(flow, key, window, batches[window%len(batches)]...)
		rollOverLikeRing(flow, window)
		window++
	}
}
