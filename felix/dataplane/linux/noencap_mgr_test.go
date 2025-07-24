// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
)

var _ = Describe("NoEncap Manager", func() {
	var (
		noencapMgr *noEncapManager
		rt         *mockRouteTable
		dataplane  *mockTunnelDataplane
	)

	const (
		externalCIDR = "10.10.10.0/24"
	)

	BeforeEach(func() {
		rt = &mockRouteTable{
			currentRoutes: map[string][]routetable.Target{},
		}

		la := netlink.NewLinkAttrs()
		la.Name = "eth0"
		opRecorder := logutils.NewSummarizer("test")

		dataplane = &mockTunnelDataplane{
			links:          []netlink.Link{&mockLink{attrs: la}},
			tunnelLinkName: dataplanedefs.IPIPIfaceName,
		}
		noencapMgr = newNoEncapManagerWithSims(
			rt,
			4,
			Config{
				Hostname:             "node1",
				ProgramClusterRoutes: true,
				DeviceRouteProtocol:  dataplanedefs.DefaultRouteProto,
			},
			opRecorder,
			dataplane,
		)
	})

	It("successfully adds a route to the noEncap interface", func() {
		noencapMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		noencapMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "172.0.2.2",
		})

		noencapMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(noencapMgr.routeMgr.parentDeviceAddr).NotTo(BeZero())
		Expect(noencapMgr.routeMgr.parentDevice).NotTo(BeEmpty())
		noEncapDev, err := noencapMgr.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(noEncapDev).NotTo(BeNil())

		link, addr, err := noencapMgr.device(noEncapDev)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).To(BeNil())
		Expect(addr).To(BeZero())

		Expect(noEncapDev).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		noencapMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_NO_ENCAP,
			Dst:         "192.168.0.3/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.0.2.2",
			SameSubnet:  true,
		})

		noencapMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_NO_ENCAP,
			Dst:         "192.168.0.100/26",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		noencapMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_NO_ENCAP,
			Dst:         "192.168.0.10/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = noencapMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
		Expect(rt.currentRoutes["eth0"][0]).To(Equal(
			routetable.Target{
				Type:     "noencap",
				CIDR:     ip.MustParseCIDROrIP("192.168.0.0/26"),
				GW:       ip.FromString("172.0.2.2"),
				Protocol: 80,
			}))
	})
})
