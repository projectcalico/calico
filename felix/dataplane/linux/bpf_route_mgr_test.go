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

package intdataplane

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/wireguard"
)

var _ = Describe("BPF route manager", func() {
	// remoteWorkloadFlags programs a remote-workload route in a no-encap pool and
	// returns the flags the manager computed for it.
	remoteWorkloadFlags := func(ipFamily proto.IPVersion, wgV4, wgV6 bool) routes.Flags {
		config := &Config{
			Hostname: "node-local",
			Wireguard: wireguard.Config{
				Enabled:   wgV4,
				EnabledV6: wgV6,
			},
		}
		m := newBPFRouteManager(config, &bpfmap.IPMaps{}, ipFamily, logutils.NewSummarizer("test"))

		dst := "10.0.1.0/26"
		nodeIP := "172.16.0.2"
		if ipFamily == proto.IPVersion_IPV6 {
			dst = "fdcc:10:1::/122"
			nodeIP = "fdcc:172:16::2"
		}

		m.onRouteUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_NO_ENCAP,
			Dst:         dst,
			DstNodeName: "node-remote",
			DstNodeIp:   nodeIP,
		})

		route := m.calculateRoute(ip.MustParseCIDROrIP(dst))
		Expect(route).NotTo(BeNil())
		return route.Flags()
	}

	// Wireguard is enabled per address family, so the tunnelled flag must follow
	// the family the route belongs to, not either family's setting.
	It("should only flag remote workloads tunnelled for the family wireguard is enabled for", func() {
		By("enabling wireguard for IPv4 only")
		Expect(remoteWorkloadFlags(proto.IPVersion_IPV4, true, false) & routes.FlagTunneled).
			To(Equal(routes.FlagTunneled))
		Expect(remoteWorkloadFlags(proto.IPVersion_IPV6, true, false) & routes.FlagTunneled).
			To(BeZero())

		By("enabling wireguard for IPv6 only")
		Expect(remoteWorkloadFlags(proto.IPVersion_IPV4, false, true) & routes.FlagTunneled).
			To(BeZero())
		Expect(remoteWorkloadFlags(proto.IPVersion_IPV6, false, true) & routes.FlagTunneled).
			To(Equal(routes.FlagTunneled))

		By("disabling wireguard for both families")
		Expect(remoteWorkloadFlags(proto.IPVersion_IPV4, false, false) & routes.FlagTunneled).
			To(BeZero())
		Expect(remoteWorkloadFlags(proto.IPVersion_IPV6, false, false) & routes.FlagTunneled).
			To(BeZero())

		By("enabling wireguard for both families")
		Expect(remoteWorkloadFlags(proto.IPVersion_IPV4, true, true) & routes.FlagTunneled).
			To(Equal(routes.FlagTunneled))
		Expect(remoteWorkloadFlags(proto.IPVersion_IPV6, true, true) & routes.FlagTunneled).
			To(Equal(routes.FlagTunneled))
	})
})
