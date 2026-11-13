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

package networking

import (
	"testing"

	"github.com/onsi/gomega"
)

// Blank entries stand for a node with no tunnel IP; they and unparseable entries
// must be dropped rather than become bad CIDRs in the policy.
func TestIngressHostCIDRs(t *testing.T) {
	g := gomega.NewWithT(t)
	got := ingressHostCIDRs([]string{"10.0.0.1", "", "fd00::1", "10.0.0.1", "not-an-ip", "192.168.5.1"})
	g.Expect(got).To(gomega.Equal([]string{"10.0.0.1/32", "fd00::1/128", "192.168.5.1/32"}))
}

// IPv6's header is 20 bytes bigger, so every sample window must sit 20 bytes
// lower for the same MTU, or the IPv6 samples straddle the boundary off-centre.
func TestGeneratePacketLengthsShiftsForIPv6Header(t *testing.T) {
	g := gomega.NewWithT(t)
	get4, post4, udp4 := generatePacketLengths(1450, 20)
	get6, post6, udp6 := generatePacketLengths(1450, 40)

	g.Expect(get6).To(gomega.HaveLen(len(get4)))
	g.Expect(post6).To(gomega.HaveLen(len(post4)))
	g.Expect(udp6).To(gomega.HaveLen(len(udp4)))
	for _, pair := range [][2][]int{{get4, get6}, {post4, post6}, {udp4, udp6}} {
		v4, v6 := pair[0], pair[1]
		g.Expect(v6[0]).To(gomega.Equal(10), "small sample is family-independent")
		for i := 1; i < len(v4); i++ {
			if v4[i] == 10000 {
				g.Expect(v6[i]).To(gomega.Equal(10000), "large sample is family-independent")
				continue
			}
			g.Expect(v6[i]).To(gomega.Equal(v4[i] - 20))
		}
	}
	// The largest UDP sample must still fit in one IPv6 packet.
	g.Expect(udp6[len(udp6)-1] + 40).To(gomega.BeNumerically("<=", 1450))
}
