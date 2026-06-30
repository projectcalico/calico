// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package calico

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/projectcalico/calico/confd/pkg/backends/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
)

// Test_generateIPIPTunnelRoutes pins the per-node recursive IPIP tunnel-route
// behaviour used when BIRD programs cluster routes on upstream BIRD 3 (which has
// no per-route device attribute / krt_tunnel). It is exact for single-mode
// clusters and intentionally over-encapsulates in mixed Always+CrossSubnet mode
// - a documented limitation, since a node's single "<ip>/32 via tunl0" route
// cannot distinguish the destination pool. Clusters needing per-pool-accurate
// cross-subnet behaviour should let Felix program the routes (ProgramClusterRoutes).
func Test_generateIPIPTunnelRoutes(t *testing.T) {
	const (
		localIP     = "10.0.0.1" // this node
		sameSubnet  = "10.0.0.2" // remote node inside the local subnet
		otherSubnet = "10.1.0.2" // remote node outside the local subnet
		localCIDR   = "10.0.0.0/24"
	)
	tunnel := func(ips ...string) []string {
		out := make([]string, 0, len(ips))
		for _, ip := range ips {
			out = append(out, fmt.Sprintf("%s/32 via \"tunl0\"", ip))
		}
		return out
	}

	for _, tc := range []struct {
		name     string
		pools    []ippoolTestCase
		expected []string
	}{
		{
			name:     "Always only tunnels to every remote node",
			pools:    []ippoolTestCase{{cidr: "192.168.0.0/16", ipipMode: encap.Always}},
			expected: tunnel(sameSubnet, otherSubnet),
		},
		{
			name:     "CrossSubnet only tunnels only to remote-subnet nodes",
			pools:    []ippoolTestCase{{cidr: "192.168.0.0/16", ipipMode: encap.CrossSubnet}},
			expected: tunnel(otherSubnet),
		},
		{
			// Documented limitation: an Always pool forces a tunnel to every
			// node, so the co-existing CrossSubnet pool's same-subnet node is
			// encapsulated too (a performance regression, not a connectivity
			// break). See generateIPIPTunnelRoutes' doc comment.
			name: "mixed Always+CrossSubnet tunnels to every node (limitation)",
			pools: []ippoolTestCase{
				{cidr: "192.168.0.0/16", ipipMode: encap.Always},
				{cidr: "172.16.0.0/16", ipipMode: encap.CrossSubnet},
			},
			expected: tunnel(sameSubnet, otherSubnet),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			originalNodeName := NodeName
			NodeName = "test-node-ipip"
			defer func() { NodeName = originalNodeName }()

			cache := ippoolTestCasesToKVPairs(t, tc.pools, 4)
			cache[fmt.Sprintf("/calico/bgp/v1/host/%s/ip_addr_v4", NodeName)] = localIP
			cache["/calico/bgp/v1/host/node-same/ip_addr_v4"] = sameSubnet
			cache["/calico/bgp/v1/host/node-other/ip_addr_v4"] = otherSubnet
			cache[fmt.Sprintf("/calico/bgp/v1/host/%s/network_v4", NodeName)] = localCIDR

			c := newTestClient(cache, nil)
			config := &types.BirdBGPConfig{NodeName: NodeName, NodeIP: localIP}

			if err := c.generateIPIPTunnelRoutes(c.getBGPProcessorContext(), config, 4); err != nil {
				t.Fatalf("generateIPIPTunnelRoutes: %v", err)
			}
			if !reflect.DeepEqual(config.IPIPTunnelRoutes, tc.expected) {
				t.Errorf("IPIPTunnelRoutes mismatch:\n got=%#v\nwant=%#v", config.IPIPTunnelRoutes, tc.expected)
			}
		})
	}

	// IPIP is IPv4-only: the IPv6 path must never emit tunnel routes.
	t.Run("IPv6 generates no tunnel routes", func(t *testing.T) {
		originalNodeName := NodeName
		NodeName = "test-node-ipip"
		defer func() { NodeName = originalNodeName }()

		cache := ippoolTestCasesToKVPairs(t, []ippoolTestCase{{cidr: "dead:beef::/64", ipipMode: encap.Always}}, 6)
		c := newTestClient(cache, nil)
		config := &types.BirdBGPConfig{NodeName: NodeName}

		if err := c.generateIPIPTunnelRoutes(c.getBGPProcessorContext(), config, 6); err != nil {
			t.Fatalf("generateIPIPTunnelRoutes v6: %v", err)
		}
		if len(config.IPIPTunnelRoutes) != 0 {
			t.Errorf("expected no IPIP tunnel routes for IPv6, got %#v", config.IPIPTunnelRoutes)
		}
	})
}
