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
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/dataplane/linux/dptest"
	"github.com/projectcalico/calico/felix/dataplane/linux/ipip/ipipdefs"
	"github.com/projectcalico/calico/felix/dataplane/linux/vxlan/vxlandefs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/lib/logrusr"
)

var _ = Describe("Route manager", func() {
	var (
		rt        *dptest.MockRouteTable
		dataplane *mocknetlink.MockNetlinkDataplane
		dpConfig  dataplanedefs.Config
		routeMgr  *routeManager
	)

	BeforeEach(func() {
		rt = dptest.NewMockRouteTable()

		dataplane = mocknetlink.New()
		_, err := dataplane.NewMockNetlink()
		Expect(err).NotTo(HaveOccurred())
		eth0 := dataplane.AddIface(2, "eth0", true, true)
		Expect(dataplane.AddrAdd(eth0, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(172, 0, 0, 2)}})).To(Succeed())
		dataplane.ResetDeltas()

		dpConfig = dataplanedefs.Config{
			Hostname:     "node1",
			MaxIPSetSize: 5,
			// The IPIP and no-encap managers only program routes when Felix, rather than
			// confd and BIRD, owns the cluster routes for that encapsulation.
			ProgramIPIPClusterRoutes:    true,
			ProgramNoEncapClusterRoutes: true,
		}

		routeMgr = newRouteManager(
			rt,
			routetable.RouteClassVXLANTunnel,
			routetable.RouteClassVXLANSameSubnet,
			proto.IPPoolType_VXLAN,
			vxlandefs.VXLANIfaceNameV4,
			4,
			1400,
			dpConfig,
			logrusr.NewSummarizer("test"),
			dataplane,
		)
		routeMgr.setTunnelRouteFunc(func(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
			return &routetable.Target{
				Type:     routetable.TargetTypeVXLAN,
				RouteKey: routetable.RouteKey{CIDR: cidr},
				GW:       ip.FromString("10.0.0.1"),
			}
		})
	})

	Describe("with VXLAN, IPIP and no-encap managers sharing one route table", func() {
		// This mirrors the way int_dataplane wires the managers up: they all
		// program the same main route table, and they all see every route update.
		var managers []dataplanedefs.Manager

		localBlock := func(poolType proto.IPPoolType, dst string) *proto.RouteUpdate {
			return &proto.RouteUpdate{
				Types:       proto.RouteType_LOCAL_WORKLOAD,
				IpPoolType:  poolType,
				Dst:         dst,
				DstNodeName: "node1",
			}
		}

		BeforeEach(func() {
			vxlanMgr := newVXLANManagerWithShims(
				dpsets.NewMockIPSets(),
				rt,
				&dptest.MockVXLANFDB{},
				vxlandefs.VXLANIfaceNameV4,
				4,
				1400,
				dpConfig,
				logrusr.NewSummarizer("test"),
				dataplane,
			)
			ipipMgr := newIPIPManagerWithShims(
				rt,
				ipipdefs.IPIPIfaceName,
				4,
				1400,
				dpConfig,
				logrusr.NewSummarizer("test"),
				dataplane,
			)
			noEncapMgr := newNoEncapManagerWithSims(
				rt,
				4,
				dpConfig,
				logrusr.NewSummarizer("test"),
				dataplane,
			)
			managers = []dataplanedefs.Manager{vxlanMgr, ipipMgr, noEncapMgr}

			// Each manager gets a local IPAM block from each type of pool; it
			// should only program a blackhole route for the block that belongs
			// to its own type of pool.
			for _, m := range managers {
				m.OnUpdate(localBlock(proto.IPPoolType_VXLAN, "10.0.1.0/26"))
				m.OnUpdate(localBlock(proto.IPPoolType_IPIP, "10.0.2.0/26"))
				m.OnUpdate(localBlock(proto.IPPoolType_NO_ENCAP, "10.0.3.0/26"))
			}
			for _, m := range managers {
				Expect(m.CompleteDeferredWork()).To(Succeed())
			}
		})

		It("should keep the blackhole routes of every manager", func() {
			// Each manager owns its own route class, so no manager's SetRoutes
			// call can delete another manager's blackhole routes.
			Expect(rt.CIDRsForClass(routetable.RouteClassBlackholeVXLAN, routetable.InterfaceNone)).To(
				ConsistOf("10.0.1.0/26"))
			Expect(rt.CIDRsForClass(routetable.RouteClassBlackholeIPIP, routetable.InterfaceNone)).To(
				ConsistOf("10.0.2.0/26"))
			Expect(rt.CIDRsForClass(routetable.RouteClassBlackholeNoEncap, routetable.InterfaceNone)).To(
				ConsistOf("10.0.3.0/26"))
		})

		It("should remove only its own blackhole routes when a block goes away", func() {
			for _, m := range managers {
				m.OnUpdate(&proto.RouteRemove{Dst: "10.0.2.0/26"})
			}
			for _, m := range managers {
				Expect(m.CompleteDeferredWork()).To(Succeed())
			}

			Expect(rt.CIDRsForClass(routetable.RouteClassBlackholeIPIP, routetable.InterfaceNone)).To(BeEmpty())
			Expect(rt.CIDRsForClass(routetable.RouteClassBlackholeVXLAN, routetable.InterfaceNone)).To(
				ConsistOf("10.0.1.0/26"))
			Expect(rt.CIDRsForClass(routetable.RouteClassBlackholeNoEncap, routetable.InterfaceNone)).To(
				ConsistOf("10.0.3.0/26"))
		})
	})

	Describe("parent interface address updates", func() {
		// The device-sync goroutine drains tunnelChangedC and takes
		// parentDeviceLock itself, so updateParentIfaceAddr must not block while
		// holding that lock: if it did, back-to-back updates from the dataplane
		// main loop would deadlock against the goroutine.
		It("should not block when the device-sync goroutine hasn't drained the channel", func() {
			routeMgr.updateParentIfaceAddr("172.0.0.2")

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				routeMgr.updateParentIfaceAddr("172.0.0.3")
			}()
			Eventually(done).Should(BeClosed())

			// ...and the lock must be free for the device-sync goroutine.
			addrRead := make(chan string)
			go func() {
				defer GinkgoRecover()
				addrRead <- routeMgr.parentIfaceAddr()
			}()
			Eventually(addrRead).Should(Receive(Equal("172.0.0.3")))
		})

		It("should kick the device-sync goroutine", func() {
			routeMgr.updateParentIfaceAddr("172.0.0.2")
			Expect(routeMgr.tunnelChangedC).To(Receive())
			Expect(routeMgr.parentIfaceAddr()).To(Equal("172.0.0.2"))
		})
	})

	Describe("parent device updates", func() {
		BeforeEach(func() {
			routeMgr.OnParentDeviceUpdate("eth0")
			routeMgr.OnUpdate(&proto.RouteUpdate{
				Types:       proto.RouteType_REMOTE_WORKLOAD,
				IpPoolType:  proto.IPPoolType_VXLAN,
				Dst:         "10.0.1.0/26",
				DstNodeName: "node2",
				DstNodeIp:   "172.0.0.3",
				SameSubnet:  true,
			})
			Expect(routeMgr.CompleteDeferredWork()).To(Succeed())
			Expect(rt.CIDRsForClass(routetable.RouteClassVXLANSameSubnet, "eth0")).To(
				ConsistOf("10.0.1.0/26"))
		})

		// No caller has a use for an empty parent device name; treating it as a
		// device change would tear down the same-subnet routes of the device we
		// are actually using.
		It("should ignore an empty parent device name", func() {
			Expect(routeMgr.OnParentDeviceUpdate("")).To(BeFalse())

			Expect(routeMgr.parentDevice).To(Equal("eth0"))
			Expect(rt.CIDRsForClass(routetable.RouteClassVXLANSameSubnet, "eth0")).To(
				ConsistOf("10.0.1.0/26"))
		})

		It("should move the same-subnet routes when the parent device changes", func() {
			Expect(routeMgr.OnParentDeviceUpdate("eth1")).To(BeTrue())
			Expect(routeMgr.CompleteDeferredWork()).To(Succeed())

			Expect(rt.CIDRsForClass(routetable.RouteClassVXLANSameSubnet, "eth0")).To(BeEmpty())
			Expect(rt.CIDRsForClass(routetable.RouteClassVXLANSameSubnet, "eth1")).To(
				ConsistOf("10.0.1.0/26"))
		})
	})

	Describe("local IPAM block classification", func() {
		// CIDRFromString returns a nil CIDR alongside its error, so a route with
		// an unparseable destination must not reach the CIDR-dependent checks.
		It("should not panic on a route with an unparseable destination", func() {
			Expect(routeMgr.routeIsLocalBlock(&proto.RouteUpdate{
				Types:      proto.RouteType_LOCAL_WORKLOAD,
				IpPoolType: proto.IPPoolType_VXLAN,
				Dst:        "not-a-cidr",
			})).To(BeFalse())
		})

		It("should treat a block CIDR as a local block but not an exact route", func() {
			Expect(routeMgr.routeIsLocalBlock(&proto.RouteUpdate{
				Types:      proto.RouteType_LOCAL_WORKLOAD,
				IpPoolType: proto.IPPoolType_VXLAN,
				Dst:        "10.0.1.0/26",
			})).To(BeTrue())
			Expect(routeMgr.routeIsLocalBlock(&proto.RouteUpdate{
				Types:      proto.RouteType_LOCAL_WORKLOAD,
				IpPoolType: proto.IPPoolType_VXLAN,
				Dst:        "10.0.1.1/32",
			})).To(BeFalse())
		})
	})
})

var _ = DescribeTable("vxlanLinksIncompat",
	func(l1, l2 *netlink.Vxlan, expected string) {
		Expect(vxlanLinksIncompat(l1, l2)).To(Equal(expected))
	},
	Entry("identical legacy devices", &netlink.Vxlan{
		VxlanId: 4096, VtepDevIndex: 2, Port: 4789,
	}, &netlink.Vxlan{
		VxlanId: 4096, VtepDevIndex: 2, Port: 4789,
	}, ""),
	Entry("identical flow-based devices", &netlink.Vxlan{
		FlowBased: true, Port: 4789,
	}, &netlink.Vxlan{
		FlowBased: true, Port: 4789,
	}, ""),
	Entry("legacy to flow-based (iptables to eBPF)", &netlink.Vxlan{
		VxlanId: 4096, VtepDevIndex: 2, Port: 4789,
	}, &netlink.Vxlan{
		FlowBased: true, Port: 4789,
	}, "flow-based mode: false vs true"),
	Entry("flow-based to legacy (eBPF to iptables)", &netlink.Vxlan{
		FlowBased: true, Port: 4789,
	}, &netlink.Vxlan{
		VxlanId: 4096, VtepDevIndex: 2, Port: 4789,
	}, "flow-based mode: true vs false"),
	Entry("flow-based without to with VNI filter (upgrade)", &netlink.Vxlan{
		FlowBased: true, Port: 4789,
	}, &netlink.Vxlan{
		FlowBased: true, VniFilter: true, Port: 4789,
	}, "vni filter: false vs true"),
	Entry("identical VNI-filtering devices", &netlink.Vxlan{
		FlowBased: true, VniFilter: true, Port: 4789,
	}, &netlink.Vxlan{
		FlowBased: true, VniFilter: true, Port: 4789,
	}, ""),
	Entry("VNI mismatch", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789,
	}, &netlink.Vxlan{
		VxlanId: 4097, Port: 4789,
	}, "vni: 4096 vs 4097"),
	Entry("port mismatch", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789,
	}, &netlink.Vxlan{
		VxlanId: 4096, Port: 4790,
	}, "port: 4789 vs 4790"),
	Entry("GBP mismatch", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, GBP: true,
	}, &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, GBP: false,
	}, "gbp: true vs false"),
	Entry("L2miss mismatch", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, L2miss: true,
	}, &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, L2miss: false,
	}, "l2miss: true vs false"),
	Entry("identical source-port range", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, PortLow: 49152, PortHigh: 65535,
	}, &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, PortLow: 49152, PortHigh: 65535,
	}, ""),
	Entry("source-port range mismatch (low)", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, PortLow: 49152, PortHigh: 65535,
	}, &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, PortLow: 32768, PortHigh: 65535,
	}, "source port range: [49152,65535] vs [32768,65535]"),
	Entry("source-port range mismatch (high)", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, PortLow: 49152, PortHigh: 65535,
	}, &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, PortLow: 49152, PortHigh: 60000,
	}, "source port range: [49152,65535] vs [49152,60000]"),
	Entry("configured source-port range replaces kernel defaults", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, PortLow: 49152, PortHigh: 65535,
	}, &netlink.Vxlan{
		VxlanId: 4096, Port: 4789,
	}, "source port range: [49152,65535] vs [0,0]"),
	Entry("unset desired source-port range leaves the existing range unchanged", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789,
	}, &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, PortLow: 49152, PortHigh: 65535,
	}, ""),
)
