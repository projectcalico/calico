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

package utils

import (
	"testing"

	"github.com/onsi/gomega"
)

type testNode struct {
	name        string
	ips         []string
	annotations map[string]string
}

func buildNodesInfo(nodes ...testNode) *nodesInfo {
	n := &nodesInfo{ips: map[IPFamily][]string{}, tunnelIPs: map[IPFamily][]string{}}
	for _, tn := range nodes {
		n.addNode(tn.name, tn.name, tn.ips, tn.annotations)
	}
	return n
}

func TestCheckFamilies(t *testing.T) {
	dual := []IPFamily{IPv4, IPv6}
	for _, tc := range []struct {
		name     string
		nodes    []testNode
		families []IPFamily
		n        int
		wantErr  string
	}{
		{
			name:     "every used node has each family",
			nodes:    []testNode{{name: "a", ips: []string{"10.0.0.1", "fd00::1"}}, {name: "b", ips: []string{"fd00::2", "10.0.0.2"}}},
			families: dual,
			n:        2,
		},
		{
			name:     "a node's extra family is ignored",
			nodes:    []testNode{{name: "a", ips: []string{"10.0.0.1", "fd00::1"}}, {name: "b", ips: []string{"10.0.0.2"}}},
			families: []IPFamily{IPv4},
			n:        2,
		},
		{
			name:     "a used node missing a family",
			nodes:    []testNode{{name: "a", ips: []string{"10.0.0.1", "fd00::1"}}, {name: "b", ips: []string{"10.0.0.2"}}},
			families: dual,
			n:        2,
			wantErr:  "node b has no IPv6 InternalIP (has [10.0.0.2]), but the cluster's IP pools include IPv6",
		},
		{
			name:     "an unused node missing a family",
			nodes:    []testNode{{name: "a", ips: []string{"10.0.0.1", "fd00::1"}}, {name: "b", ips: []string{"10.0.0.2", "fd00::2"}}, {name: "c", ips: []string{"10.0.0.3"}}},
			families: dual,
			n:        2,
		},
		{
			name:     "every gap is reported",
			nodes:    []testNode{{name: "a", ips: []string{"fd00::1"}}, {name: "b", ips: []string{"10.0.0.2"}}},
			families: dual,
			n:        2,
			wantErr:  "node a has no IPv4 InternalIP (has [fd00::1]), but the cluster's IP pools include IPv4; node b has no IPv6",
		},
		{
			name:     "fewer nodes than used",
			nodes:    []testNode{{name: "a", ips: []string{"10.0.0.1"}}},
			families: []IPFamily{IPv4},
			n:        2,
			wantErr:  "need 2 nodes, have 1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			err := buildNodesInfo(tc.nodes...).CheckFamilies(tc.families, tc.n)
			if tc.wantErr != "" {
				g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(tc.wantErr)))
				return
			}
			g.Expect(err).NotTo(gomega.HaveOccurred())
		})
	}
}

// A node missing a family must keep its slot, or every later node's address
// would be attributed to the wrong node.
func TestGetIPsStaysAlignedWithNames(t *testing.T) {
	g := gomega.NewWithT(t)
	n := buildNodesInfo(
		testNode{name: "a", ips: []string{"10.0.0.1"}},
		testNode{name: "b", ips: []string{"10.0.0.2", "fd00::2"}},
	)
	g.Expect(n.GetNames()).To(gomega.Equal([]string{"a", "b"}))
	g.Expect(n.GetIPs(IPv4)).To(gomega.Equal([]string{"10.0.0.1", "10.0.0.2"}))
	g.Expect(n.GetIPs(IPv6)).To(gomega.Equal([]string{"", "fd00::2"}))
}

func TestGetTunnelIPs(t *testing.T) {
	g := gomega.NewWithT(t)
	n := buildNodesInfo(
		testNode{name: "ipip", ips: []string{"10.0.0.1"}, annotations: map[string]string{
			nodeBgpIpv4IPIPTunnelAddrAnnotation:  "192.168.0.1",
			nodeBgpIpv4VXLANTunnelAddrAnnotation: "192.168.0.2",
		}},
		testNode{name: "vxlan-dual", ips: []string{"10.0.0.2", "fd00::2"}, annotations: map[string]string{
			nodeBgpIpv4VXLANTunnelAddrAnnotation: "192.168.1.1",
			nodeBgpIpv6VXLANTunnelAddrAnnotation: "fd00:10::1",
		}},
		testNode{name: "none", ips: []string{"10.0.0.3"}},
	)
	g.Expect(n.GetTunnelIPs(IPv4)).To(gomega.Equal([]string{"192.168.0.1", "192.168.1.1", ""}))
	g.Expect(n.GetTunnelIPs(IPv6)).To(gomega.Equal([]string{"", "fd00:10::1", ""}))
}
