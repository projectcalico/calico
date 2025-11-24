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
		noencapMgr, noencapMgrV6 *noEncapManager
		rt                       *mockRouteTable
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

		noencapMgr = newNoEncapManagerWithSims(
			rt,
			4,
			Config{
				Hostname:             "node1",
				ProgramClusterRoutes: true,
				DeviceRouteProtocol:  dataplanedefs.DefaultRouteProto,
			},
			opRecorder,
			&mockTunnelDataplane{
				links:     []netlink.Link{&mockLink{attrs: la}},
				ipVersion: 4,
			},
		)
		noencapMgrV6 = newNoEncapManagerWithSims(
			rt,
			6,
			Config{
				Hostname:             "node1",
				ProgramClusterRoutes: true,
				DeviceRouteProtocol:  dataplanedefs.DefaultRouteProto,
			},
			opRecorder,
			&mockTunnelDataplane{
				links:     []netlink.Link{&mockLink{attrs: la}},
				ipVersion: 6,
			},
		)
	})

	It("successfully adds a route to the noEncap interface", func() {
		noencapMgr.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		noencapMgr.OnUpdate(&proto.HostMetadataV4V6Update{
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
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = noencapMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(0))

		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(rt.currentRoutes[routetable.InterfaceNone][0]).To(Equal(
			routetable.Target{
				Type:     "blackhole",
				CIDR:     ip.MustParseCIDROrIP("192.168.0.100/26"),
				Protocol: 80,
			}))

		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
		Expect(rt.currentRoutes["eth0"][0]).To(Equal(
			routetable.Target{
				Type:     "noencap",
				CIDR:     ip.MustParseCIDROrIP("192.168.0.0/26"),
				GW:       ip.FromString("172.0.2.2"),
				Protocol: 80,
			}))
	})

	It("successfully adds a IPv6 route to the noEncap interface", func() {
		noencapMgrV6.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "node1",
			Ipv6Addr: "fc00:10:96::2",
		})
		noencapMgrV6.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "node2",
			Ipv6Addr: "fc00:10:10::1",
		})

		noencapMgrV6.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(noencapMgrV6.routeMgr.parentDeviceAddr).NotTo(BeZero())
		Expect(noencapMgrV6.routeMgr.parentDevice).NotTo(BeEmpty())
		noEncapDev, err := noencapMgrV6.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(noEncapDev).NotTo(BeNil())

		link, addr, err := noencapMgrV6.device(noEncapDev)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).To(BeNil())
		Expect(addr).To(BeZero())

		Expect(noEncapDev).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		noencapMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_NO_ENCAP,
			Dst:         "dead:beef::2:10/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::1",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		noencapMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_NO_ENCAP,
			Dst:         "dead:beef::10:30/128",
			DstNodeName: "node1",
			DstNodeIp:   "fc00:10:96::2",
			SameSubnet:  true,
		})

		noencapMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_NO_ENCAP,
			Dst:         "dead:beef::1:30/112",
			DstNodeName: "node1",
			DstNodeIp:   "fc00:10:96::2",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))

		err = noencapMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(0))

		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(rt.currentRoutes[routetable.InterfaceNone][0]).To(Equal(
			routetable.Target{
				Type:     "blackhole",
				CIDR:     ip.MustParseCIDROrIP("dead:beef::1:30/112"),
				Protocol: 80,
			}))

		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
		Expect(rt.currentRoutes["eth0"][0]).To(Equal(
			routetable.Target{
				Type:     "noencap",
				CIDR:     ip.MustParseCIDROrIP("dead:beef::2:10/112"),
				GW:       ip.FromString("fc00:10:10::1"),
				Protocol: 80,
			}))
	})
})
