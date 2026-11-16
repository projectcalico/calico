// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
)

// ipSetModel is a reference for a DiachronicFlow's source IP set: each tracked IP maps to the
// window starts it was seen in, and lastSeen is the newest of those at the time it was recorded.
type ipSetModel struct {
	windows  map[string]map[int64]bool
	lastSeen map[string]int64
}

func newIPSetModel() *ipSetModel {
	return &ipSetModel{windows: map[string]map[int64]bool{}, lastSeen: map[string]int64{}}
}

// add records ips in the window at start, then keeps the MaxIPsPerFlow most recently seen IPs,
// dropping the lower address among equally recent ones.
func (m *ipSetModel) add(ips []string, start int64) {
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		if m.windows[ip] == nil {
			m.windows[ip] = map[int64]bool{}
		}
		m.windows[ip][start] = true
		m.lastSeen[ip] = max(m.lastSeen[ip], start)
	}
	ranked := make([]string, 0, len(m.lastSeen))
	for ip := range m.lastSeen {
		ranked = append(ranked, ip)
	}
	slices.SortFunc(ranked, func(a, b string) int {
		if m.lastSeen[a] != m.lastSeen[b] {
			return int(m.lastSeen[a] - m.lastSeen[b])
		}
		return strings.Compare(a, b)
	})
	for _, ip := range ranked[:max(0, len(ranked)-storage.MaxIPsPerFlow)] {
		m.forget(ip)
	}
}

// rollover drops every window that ends at or before limiter, and any IP left with no windows.
func (m *ipSetModel) rollover(limiter int64) {
	for ip, starts := range m.windows {
		for s := range starts {
			if s+ipTestInterval <= limiter {
				delete(starts, s)
			}
		}
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
	defer setupTest(t)()

	rng := rand.New(rand.NewPCG(1, 2))
	for trial := range 200 {
		key := ipTestFlowKey()
		flow := storage.NewDiachronicFlow(key, 0)
		model := newIPSetModel()
		pool := 50 + rng.IntN(400)
		var limiter int64

		for step := 8; step < 68; step++ {
			window := step - rng.IntN(4)
			ips := make([]string, rng.IntN(150))
			for i := range ips {
				n := rng.IntN(pool)
				ips[i] = fmt.Sprintf("10.0.%d.%d", n/256, n%256)
				if rng.IntN(50) == 0 {
					ips[i] = ""
				}
			}
			addIPs(flow, key, window, ips...)
			model.add(ips, int64(window*ipTestInterval))

			if rng.IntN(5) == 0 {
				limiter = max(limiter, int64((step-4-rng.IntN(4))*ipTestInterval))
				flow.Rollover(limiter)
				model.rollover(limiter)
			}

			for w := step - 8; w <= step; w++ {
				start := int64(w * ipTestInterval)
				var got []string
				if f := flow.Aggregate(start, start+ipTestInterval); f != nil {
					got = f.SourceIps
				}
				require.Equal(t, model.windowIPs(start), got, "trial %d step %d window %d", trial, step, w)
			}
		}
	}
}

// BenchmarkDiachronicFlow_AddFlowChurningIPs adds a flow per window carrying MaxIPsPerFlow
// addresses the full set has never seen, rolling over as the ring would, so every update evicts
// the whole set.
func BenchmarkDiachronicFlow_AddFlowChurningIPs(b *testing.B) {
	const history = 240
	k := ipTestFlowKey()
	batches := make([][]string, 256)
	for i := range batches {
		batches[i] = distinctIPs(i*storage.MaxIPsPerFlow, storage.MaxIPsPerFlow)
	}
	df := storage.NewDiachronicFlow(k, 0)

	b.ReportAllocs()
	var window int
	for b.Loop() {
		addIPs(df, k, window, batches[window%len(batches)]...)
		if window >= history {
			df.Rollover(int64((window - history) * ipTestInterval))
		}
		window++
	}
}
