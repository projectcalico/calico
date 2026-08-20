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
