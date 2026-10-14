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
	"fmt"
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/mock"
)

// On a dual-stack node the v4 and v6 scanners must not overwrite each other's metrics.
func TestScannerMetricsPerIPFamily(t *testing.T) {
	v4Params := conntrack.MapParams
	v4Params.MaxEntries = 1000
	v4Map := mock.NewMockMap(v4Params)
	for i := range 3 {
		k := conntrack.NewKey(conntrack.ProtoUDP, net.ParseIP("10.0.0.1").To4(), uint16(1000+i),
			net.ParseIP("10.0.0.2").To4(), 53)
		v := conntrack.NewValueNormal(0, 0, conntrack.Leg{}, conntrack.Leg{})
		if err := v4Map.Update(k.AsBytes(), v.AsBytes()); err != nil {
			t.Fatal(err)
		}
	}

	v6Params := conntrack.MapParamsV6
	v6Params.MaxEntries = 2000
	v6Map := mock.NewMockMap(v6Params)
	k6 := conntrack.NewKeyV6(conntrack.ProtoUDP, net.ParseIP("fd00::1"), 1000, net.ParseIP("fd00::2"), 53)
	v6 := conntrack.NewValueV6Normal(0, 0, conntrack.Leg{}, conntrack.Leg{})
	if err := v6Map.Update(k6.AsBytes(), v6.AsBytes()); err != nil {
		t.Fatal(err)
	}

	s4 := conntrack.NewScanner(v4Map, conntrack.KeyFromBytes, conntrack.ValueFromBytes,
		nil, "Disabled", nil, 4, nil)
	s6 := conntrack.NewScanner(v6Map, conntrack.KeyV6FromBytes, conntrack.ValueV6FromBytes,
		nil, "Disabled", nil, 6, nil)
	s4.Scan()
	s6.Scan()

	expect := map[string]float64{
		"felix_bpf_conntrack_used/4":        3,
		"felix_bpf_conntrack_used/6":        1,
		"felix_bpf_conntrack_max_entries/4": 1000,
		"felix_bpf_conntrack_max_entries/6": 2000,
	}
	got := gatherByFamily(t)
	for name, want := range expect {
		if v, ok := got[name]; !ok || v != want {
			t.Errorf("%s = %v (present %v), want %v", name, v, ok, want)
		}
	}
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
				if l.GetName() == "ip_family" && m.GetGauge() != nil {
					out[fmt.Sprintf("%s/%s", mf.GetName(), l.GetValue())] = m.GetGauge().GetValue()
				}
			}
		}
	}
	return out
}
