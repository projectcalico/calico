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

package bgp

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseBIRDRouteOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   []BIRDRoute
	}{
		{
			name:   "network not in table",
			output: "BIRD 1.6.8 ready.\nNetwork not in table\n",
			want:   nil,
		},
		{
			name: "single BGP via route, best",
			output: `BIRD 1.6.8 ready.
10.244.0.64/32     via 172.16.8.2 on eth0 [bgp_node0 16:22:38] * (100/0) [AS65000i]
	Type: BGP unicast univ
	BGP.origin: IGP
	BGP.local_pref: 100
	BGP.community: (65000,100)
`,
			want: []BIRDRoute{
				{NextHop: "172.16.8.2", Preference: 100, LocalPref: 100, Community: "(65000,100)", Best: true},
			},
		},
		{
			name: "local device route contested with stale BGP route",
			output: `BIRD v0.3.3+birdv1.6.8 ready.
192.168.130.67/32  dev cali3cab184f37f [kernel1 22:35:57] * (150)
	Type: device unicast univ
                   via 172.16.8.3 on l2tpeth0 [Mesh_172_16_8_3 22:35:20] (100/0) [AS64512i]
	Type: BGP unicast univ
	BGP.origin: IGP
	BGP.local_pref: 2147482623
`,
			want: []BIRDRoute{
				{Iface: "cali3cab184f37f", Device: true, Preference: 150, Best: true},
				{NextHop: "172.16.8.3", Preference: 100, LocalPref: 2147482623, Best: false},
			},
		},
		// The next three fixtures are literal captures from a three-container BIRD lab
		// (calico/bird v0.3.3+birdv1.6.8) reproducing the live-migration black-hole: a peer
		// advertising 10.99.0.1/32 with the workload IP 192.168.99.7 as NEXT_HOP, against a
		// node holding both a local "cali99" device route for the workload and a stale BGP
		// route for it from the migration source.
		{
			name: "recursive route black-holed: next hop resolves only via another BGP route",
			output: `BIRD v0.3.3+birdv1.6.8 ready.
10.99.0.1/32       unreachable [tor 15:24:05 from 10.55.0.2] * (100/-) [AS65001i]
	Type: BGP unicast univ
	BGP.origin: IGP
	BGP.as_path: 65001
	BGP.next_hop: 192.168.99.7
	BGP.local_pref: 100
`,
			want: []BIRDRoute{
				{Unreachable: true, Preference: 100, BGPNextHop: "192.168.99.7", LocalPref: 100, Best: true},
			},
		},
		{
			name: "recursive route resolved through the local workload veth",
			output: `BIRD v0.3.3+birdv1.6.8 ready.
10.99.0.1/32       via 192.168.99.7 on cali99 [tor 15:25:07 from 10.55.0.2] * (100/0) [AS65001i]
	Type: BGP unicast univ
	BGP.origin: IGP
	BGP.as_path: 65001
	BGP.next_hop: 192.168.99.7
	BGP.local_pref: 100
`,
			want: []BIRDRoute{
				{NextHop: "192.168.99.7", Preference: 100, BGPNextHop: "192.168.99.7", LocalPref: 100, Best: true},
			},
		},
		{
			name: "stale BGP route beats the local device route (pre-fix contest)",
			output: `BIRD v0.3.3+birdv1.6.8 ready.
192.168.99.7/32    via 10.55.0.4 on eth0 [src 15:24:05] * (100/0) [i]
	Type: BGP unicast univ
	BGP.origin: IGP
	BGP.as_path:
	BGP.next_hop: 10.55.0.4
	BGP.local_pref: 100
                   dev cali99 [kernel1 15:24:03] (10)
	Type: inherit unicast univ
	Kernel.source: 3
	Kernel.metric: 512
`,
			want: []BIRDRoute{
				{NextHop: "10.55.0.4", Preference: 100, BGPNextHop: "10.55.0.4", LocalPref: 100, Best: true},
				{Iface: "cali99", Device: true, Preference: 10},
			},
		},
		{
			name: "device route at kernel default preference",
			output: `BIRD v0.3.3+birdv1.6.8 ready.
192.168.130.67/32  dev cali3cab184f37f [kernel1 22:35:57] * (10)
	Type: device unicast univ
`,
			want: []BIRDRoute{
				{Iface: "cali3cab184f37f", Device: true, Preference: 10, Best: true},
			},
		},
		{
			name: "two via routes, non-best second",
			output: `BIRD 1.6.8 ready.
10.244.0.64/32     via 172.16.8.2 on eth0 [bgp_node0 16:22:38] * (100/0) [AS65000i]
	Type: BGP unicast univ
	BGP.local_pref: 2147483135
	BGP.community: (65000,100)
                   via 172.16.8.4 on eth0 [bgp_node2 16:21:49] (100/0) [AS65000i]
	Type: BGP unicast univ
	BGP.local_pref: 100
`,
			want: []BIRDRoute{
				{NextHop: "172.16.8.2", Preference: 100, LocalPref: 2147483135, Community: "(65000,100)", Best: true},
				{NextHop: "172.16.8.4", Preference: 100, LocalPref: 100, Best: false},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseBIRDRouteOutput(tt.output)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseBIRDRouteOutput() =\n%+v\nwant\n%+v", got, tt.want)
			}
		})
	}
}

func TestGenerateBIRDPeersConfWithRecursiveRoute(t *testing.T) {
	conf := GenerateBIRDPeersConfWithRecursiveRoute(
		"192.168.0.0/16",
		[]string{"172.18.0.3", "172.18.0.4"},
		RecursiveRoute{Prefix: "10.99.0.1/32", NextHop: "192.168.130.67"},
	)

	// One static declaration, resolvable via the first node.
	if want := "route 10.99.0.1/32 via 172.18.0.3;"; !strings.Contains(conf, want) {
		t.Errorf("config missing %q:\n%s", want, conf)
	}
	// Every peer must impose the workload IP as NEXT_HOP, or the receiving node has nothing to
	// resolve recursively and the test the config exists for silently passes for the wrong
	// reason.
	if got := strings.Count(conf, "bgp_next_hop = 192.168.130.67;"); got != 2 {
		t.Errorf("bgp_next_hop assignments = %d, want one per peer (2):\n%s", got, conf)
	}
	for _, ip := range []string{"172.18.0.3", "172.18.0.4"} {
		if want := "neighbor " + ip + " as 64512;"; !strings.Contains(conf, want) {
			t.Errorf("config missing %q:\n%s", want, conf)
		}
	}
	// The per-peer export filter must override the template's "export none", not sit alongside
	// it: BIRD takes the protocol's own option, but a stray template-level export would mean the
	// prefix is never advertised at all.
	if strings.Count(conf, "export none;") != 1 {
		t.Errorf("expected exactly one template-level 'export none;':\n%s", conf)
	}

	// Without a recursive route the output must be unchanged from the plain generator.
	plain := GenerateBIRDPeersConf("192.168.0.0/16", []string{"172.18.0.3"})
	if strings.Contains(plain, "bgp_next_hop") || strings.Contains(plain, "static_recursive") {
		t.Errorf("plain config should not contain recursive-route config:\n%s", plain)
	}
}
