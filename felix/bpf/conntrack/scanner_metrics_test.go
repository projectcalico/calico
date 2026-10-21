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

package conntrack_test

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/conntrack/cleanupv1"
	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/mock"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
)

// On a dual-stack node the v4 and v6 scanners must not overwrite each other's metrics.
func TestScannerMetricsPerIPFamily(t *testing.T) {
	now := mocktime.StartKTime

	v4Params := conntrack.MapParams
	v4Params.MaxEntries = 1000
	v4Map := mock.NewMockMap(v4Params)
	// Three live entries and one expired one.
	for i, lastSeen := range []time.Duration{now, now, now, now - time.Hour} {
		k := conntrack.NewKey(conntrack.ProtoUDP, net.ParseIP("10.0.0.1").To4(), uint16(1000+i),
			net.ParseIP("10.0.0.2").To4(), 53)
		v := conntrack.NewValueNormal(lastSeen, 0, conntrack.Leg{}, conntrack.Leg{})
		if err := v4Map.Update(k.AsBytes(), v.AsBytes()); err != nil {
			t.Fatal(err)
		}
	}

	v6Params := conntrack.MapParamsV6
	v6Params.MaxEntries = 2000
	v6Map := mock.NewMockMap(v6Params)
	k6 := conntrack.NewKeyV6(conntrack.ProtoUDP, net.ParseIP("fd00::1"), 1000, net.ParseIP("fd00::2"), 53)
	v6 := conntrack.NewValueV6Normal(now, 0, conntrack.Leg{}, conntrack.Leg{})
	if err := v6Map.Update(k6.AsBytes(), v6.AsBytes()); err != nil {
		t.Fatal(err)
	}

	lc := conntrack.NewLivenessScanner(timeouts.DefaultTimeouts(), false, 4,
		conntrack.WithTimeShim(mocktime.New()))
	s4 := conntrack.NewScanner(v4Map, conntrack.KeyFromBytes, conntrack.ValueFromBytes,
		nil, "Disabled", nil, 4, nil, lc)
	s6 := conntrack.NewScanner(v6Map, conntrack.KeyV6FromBytes, conntrack.ValueV6FromBytes,
		nil, "Disabled", nil, 6, nil)

	// Counters are process-global and other tests in this binary scan too, so compare deltas.
	before := gatherByFamily(t)
	s4.Scan()
	s6.Scan()
	after := gatherByFamily(t)

	gauges := map[string]float64{
		"felix_bpf_conntrack_used/4":        4,
		"felix_bpf_conntrack_used/6":        1,
		"felix_bpf_conntrack_cleaned/4":     1,
		"felix_bpf_conntrack_cleaned/6":     0,
		"felix_bpf_conntrack_expired/4":     1,
		"felix_bpf_conntrack_max_entries/4": 1000,
		"felix_bpf_conntrack_max_entries/6": 2000,
	}
	for name, want := range gauges {
		if v, ok := after[name]; !ok || v != want {
			t.Errorf("%s = %v (present %v), want %v", name, v, ok, want)
		}
	}
	counterDeltas := map[string]float64{
		"felix_bpf_conntrack_sweeps/4":        1,
		"felix_bpf_conntrack_sweeps/6":        1,
		"felix_bpf_conntrack_cleaned_total/4": 1,
		"felix_bpf_conntrack_cleaned_total/6": 0,
	}
	for name, want := range counterDeltas {
		if d := after[name] - before[name]; d != want {
			t.Errorf("%s increased by %v, want %v", name, d, want)
		}
	}
}

// A failing BPF cleaner must not panic the sweep, and its batch is not counted as cleaned.
func TestScannerSurvivesBPFCleanerError(t *testing.T) {
	now := mocktime.StartKTime
	ctMap := mock.NewMockMap(conntrack.MapParams)
	k := conntrack.NewKey(conntrack.ProtoUDP, net.ParseIP("10.0.0.1").To4(), 1000,
		net.ParseIP("10.0.0.2").To4(), 53)
	v := conntrack.NewValueNormal(now-time.Hour, 0, conntrack.Leg{}, conntrack.Leg{})
	if err := ctMap.Update(k.AsBytes(), v.AsBytes()); err != nil {
		t.Fatal(err)
	}

	cleaner := &failingCleaner{}
	lc := conntrack.NewLivenessScanner(timeouts.DefaultTimeouts(), false, 4,
		conntrack.WithTimeShim(mocktime.New()))
	s := conntrack.NewScanner(ctMap, conntrack.KeyFromBytes, conntrack.ValueFromBytes,
		nil, "Disabled", mock.NewMockMap(cleanupv1.MapParams), 4, cleaner, lc)

	s.Scan()

	if cleaner.runs == 0 {
		t.Fatal("BPF cleaner was not run")
	}
	if v := gatherByFamily(t)["felix_bpf_conntrack_cleaned/4"]; v != 0 {
		t.Errorf("felix_bpf_conntrack_cleaned/4 = %v, want 0", v)
	}
}

// Live entries visited after a full batch must not trigger more BPF cleaner runs.
func TestScannerRunsBPFCleanerOncePerBatch(t *testing.T) {
	now := mocktime.StartKTime
	ctMap := &orderedMap{Map: mock.NewMockMap(conntrack.MapParams)}
	// Expired entries sort before live ones, so every live entry is visited after the batch fills.
	addEntries := func(firstOctet byte, n int, lastSeen time.Duration) {
		for i := 0; i < n; i++ {
			src := net.IPv4(10, firstOctet, byte(i>>8), byte(i)).To4()
			k := conntrack.NewKey(conntrack.ProtoUDP, src, 1000, net.ParseIP("10.255.0.1").To4(), 53)
			v := conntrack.NewValueNormal(lastSeen, 0, conntrack.Leg{}, conntrack.Leg{})
			if err := ctMap.Update(k.AsBytes(), v.AsBytes()); err != nil {
				t.Fatal(err)
			}
		}
	}
	addEntries(0, 1000, now-time.Hour)
	addEntries(1, 100, now)

	cleaner := &failingCleaner{}
	lc := conntrack.NewLivenessScanner(timeouts.DefaultTimeouts(), false, 4,
		conntrack.WithTimeShim(mocktime.New()))
	s := conntrack.NewScanner(ctMap, conntrack.KeyFromBytes, conntrack.ValueFromBytes,
		nil, "Disabled", mock.NewMockMap(cleanupv1.MapParams), 4, cleaner, lc)

	s.Scan()

	// One run for the full batch, one for the final flush.
	if cleaner.runs != 2 {
		t.Errorf("BPF cleaner ran %d times, want 2", cleaner.runs)
	}
}

type failingCleaner struct {
	runs int
}

func (c *failingCleaner) Run(...conntrack.RunOpt) (*conntrack.CleanupContext, error) {
	c.runs++
	return nil, errors.New("injected failure")
}

func (c *failingCleaner) Close() error {
	return nil
}

// orderedMap iterates in key order; mock.Map iterates in Go map order.
type orderedMap struct {
	*mock.Map
}

func (m *orderedMap) Iter(f maps.IterCallback) error {
	var keys []string
	for k := range m.Contents {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if f([]byte(k), []byte(m.Contents[k])) == maps.IterDelete {
			delete(m.Contents, k)
		}
	}
	return nil
}

func gatherByFamily(t *testing.T) map[string]float64 {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() != "ip_version" {
					continue
				}
				name := fmt.Sprintf("%s/%s", mf.GetName(), l.GetValue())
				switch {
				case m.GetGauge() != nil:
					out[name] = m.GetGauge().GetValue()
				case m.GetCounter() != nil:
					out[name] = m.GetCounter().GetValue()
				}
			}
		}
	}
	return out
}
