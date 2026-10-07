// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"context"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/vxlanfdb"
	"github.com/projectcalico/calico/lib/logrusr"
)

type mockVXLANFDB struct {
	setVTEPsCalls int
	currentVTEPs  []vxlanfdb.VTEP
}

func (t *mockVXLANFDB) SetVTEPs(targets []vxlanfdb.VTEP) {
	logrus.WithFields(logrus.Fields{
		"targets": targets,
	}).Debug("SetVTEPs")
	t.currentVTEPs = targets
	t.setVTEPsCalls++
}

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
)

var _ = Describe("VXLANManager", func() {
	var (
		vxlanMgr, vxlanMgrV6 *vxlanManager
		rt                   *mockRouteTable
		fdb                  *mockVXLANFDB
	)

	BeforeEach(func() {
		rt = &mockRouteTable{
			currentRoutes: map[string][]routetable.Target{},
		}

		fdb = &mockVXLANFDB{}

		opRecorder := logrusr.NewSummarizer("test")

		dataplane := mocknetlink.New()
		_, err := dataplane.NewMockNetlink()
		Expect(err).NotTo(HaveOccurred())
		dataplane.ImmediateLinkUp = true
		eth0 := dataplane.AddIface(2, "eth0", true, true)
		Expect(dataplane.AddrAdd(eth0, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(172, 0, 0, 2)}})).To(Succeed())
		dataplane.ResetDeltas()

		dataplaneV6 := mocknetlink.New()
		_, err = dataplaneV6.NewMockNetlink()
		Expect(err).NotTo(HaveOccurred())
		dataplaneV6.ImmediateLinkUp = true
		eth0V6 := dataplaneV6.AddIface(2, "eth0", true, true)
		Expect(dataplaneV6.AddrAdd(eth0V6, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("fc00:10:96::2")}})).To(Succeed())
		dataplaneV6.ResetDeltas()

		dpConfig := Config{
			MaxIPSetSize:       5,
			Hostname:           "node1",
			ExternalNodesCidrs: []string{"10.0.0.0/24"},
			RulesConfig: rules.Config{
				VXLANVNI:  1,
				VXLANPort: 20,
			},
		}
		vxlanMgr = newVXLANManagerWithShims(
			dpsets.NewMockIPSets(),
			rt,
			fdb,
			dataplanedefs.VXLANIfaceNameV4,
			4,
			4444,
			dpConfig,
			opRecorder,
			dataplane,
		)

		dpConfigV6 := Config{
			MaxIPSetSize:       5,
			Hostname:           "node1",
			ExternalNodesCidrs: []string{"fd00:10:244::/112"},
			RulesConfig: rules.Config{
				VXLANVNI:  1,
				VXLANPort: 20,
			},
		}
		vxlanMgrV6 = newVXLANManagerWithShims(
			dpsets.NewMockIPSets(),
			rt,
			fdb,
			dataplanedefs.VXLANIfaceNameV6,
			6,
			6666,
			dpConfigV6,
			opRecorder,
			dataplaneV6,
		)
	})

	It("successfully adds a route to the parent interface", func() {
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})

		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.80.0/32",
			ParentDeviceIp: "172.0.12.1",
		})

		localVTEP := vxlanMgr.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		vxlanMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(vxlanMgr.myVTEP).NotTo(BeNil())
		Expect(vxlanMgr.routeMgr.parentDevice).NotTo(BeEmpty())

		parent, err := vxlanMgr.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(parent).NotTo(BeNil())

		link, addr, err := vxlanMgr.device(parent)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = vxlanMgr.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(parent).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.1/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.2/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.8.8.8",
		})

		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.0/26",
			DstNodeName: "node1",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.1/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.8.8.7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes["vxlan.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes["vxlan.calico"]).To(HaveLen(1))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(rt.currentRoutes["eth0"]).NotTo(BeNil())

		mac, err := net.ParseMAC("00:0a:95:9d:68:16")
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.currentVTEPs).To(ConsistOf(vxlanfdb.VTEP{
			HostIP:    ip.FromString("172.0.12.1"),
			TunnelIP:  ip.FromString("10.0.80.0"),
			TunnelMAC: mac,
		}))
		Expect(fdb.setVTEPsCalls).To(Equal(1))
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.setVTEPsCalls).To(Equal(1))
	})

	It("successfully adds a IPv6 route to the parent interface", func() {
		vxlanMgrV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node1",
			MacV6:            "00:0a:74:9d:68:16",
			Ipv6Addr:         "fd00:10:244::",
			ParentDeviceIpv6: "fc00:10:96::2",
		})

		vxlanMgrV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node2",
			MacV6:            "00:0a:95:9d:68:16",
			Ipv6Addr:         "fd00:10:96::/112",
			ParentDeviceIpv6: "fc00:10:10::1",
		})

		localVTEP := vxlanMgrV6.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		vxlanMgrV6.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(vxlanMgrV6.myVTEP).NotTo(BeNil())
		Expect(vxlanMgrV6.routeMgr.parentDevice).NotTo(BeEmpty())

		parent, err := vxlanMgrV6.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(parent).NotTo(BeNil())

		link, addr, err := vxlanMgrV6.device(parent)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = vxlanMgrV6.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(parent).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
			SameSubnet:  true,
		})

		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::2/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
		})

		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::/112",
			DstNodeName: "node1",
			DstNodeIp:   "fc00:10:10::8",
			SameSubnet:  true,
		})

		// Borrowed /128 should not be programmed as blackhole.
		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/128",
			DstNodeName: "node1",
			DstNodeIp:   "fc00:10:10::7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes["vxlan-v6.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes["vxlan-v6.calico"]).To(HaveLen(1))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(rt.currentRoutes["eth0"]).NotTo(BeNil())

		mac, err := net.ParseMAC("00:0a:95:9d:68:16")
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.currentVTEPs).To(ConsistOf(vxlanfdb.VTEP{
			HostIP:    ip.FromString("fc00:10:10::1"),
			TunnelIP:  ip.FromString("fd00:10:96::"),
			TunnelMAC: mac,
		}))
		Expect(fdb.setVTEPsCalls).To(Equal(1))
		err = vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.setVTEPsCalls).To(Equal(1))
	})

	It("should fall back to programming tunneled routes if the parent device is not known", func() {
		parentNameC := make(chan string)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go vxlanMgr.keepVXLANDeviceInSync(ctx, 1400, false, 1*time.Second, parentNameC)

		By("Sending another node's VTEP and route.")
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.80.0/32",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.1/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(vxlanMgr.routeMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(1))

		By("Sending another local VTEP.")
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		localVTEP := vxlanMgr.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		// Note: parent name is sent after configuration so this receive
		// ensures we don't race.
		Eventually(parentNameC, "2s").Should(Receive(Equal("eth0")))
		vxlanMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		err = vxlanMgr.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(vxlanMgr.routeMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(0))
	})

	It("IPv6: should fall back to programming tunneled routes if the parent device is not known", func() {
		parentNameC := make(chan string)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go vxlanMgrV6.keepVXLANDeviceInSync(ctx, 1400, false, 1*time.Second, parentNameC)

		By("Sending another node's VTEP and route.")
		vxlanMgrV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node2",
			MacV6:            "00:0a:95:9d:68:16",
			Ipv6Addr:         "fd00:10:96::/112",
			ParentDeviceIpv6: "fc00:10:10::1",
		})
		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
			SameSubnet:  true,
		})

		err := vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(vxlanMgrV6.routeMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(1))

		By("Sending another local VTEP.")
		vxlanMgrV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node1",
			MacV6:            "00:0a:74:9d:68:16",
			Ipv6Addr:         "fd00:10:244::",
			ParentDeviceIpv6: "fc00:10:96::2",
		})
		localVTEP := vxlanMgrV6.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		// Note: parent name is sent after configuration so this receive
		// ensures we don't race.
		Eventually(parentNameC, "2s").Should(Receive(Equal("eth0")))
		vxlanMgrV6.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		err = vxlanMgrV6.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(vxlanMgrV6.routeMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(0))
	})

	It("should program directly connected routes for remote VTEPs with borrowed IP addresses", func() {
		By("Sending a borrowed tunnel IP address")
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.1.1/32",
			DstNodeName: "node2",
			DstNodeIp:   "172.16.0.1",
			Borrowed:    true,
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect a directly connected route to the borrowed IP.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4][0]).To(Equal(
			routetable.Target{
				RouteKey: routetable.RouteKey{
					CIDR: ip.MustParseCIDROrIP("10.0.1.1/32"),
				},
				MTU: 4444,
			}))

		// Delete the route.
		vxlanMgr.OnUpdate(&proto.RouteRemove{
			Dst: "10.0.1.1/32",
		})

		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect no routes.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(0))
	})

	It("IPv6: should program directly connected routes for remote VTEPs with borrowed IP addresses", func() {
		By("Sending a borrowed tunnel IP address")
		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
			Borrowed:    true,
		})

		err := vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect a directly connected route to the borrowed IP.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6][0]).To(Equal(
			routetable.Target{
				RouteKey: routetable.RouteKey{
					CIDR: ip.MustParseCIDROrIP("fc00:10:244::1/112"),
				},
				MTU: 6666,
			}))

		// Delete the route.
		vxlanMgrV6.OnUpdate(&proto.RouteRemove{
			Dst: "fc00:10:244::1/112",
		})

		err = vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect no routes.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(0))
	})

	It("should only program black hole routes for local endpoints", func() {
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})

		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.80.0/32",
			ParentDeviceIp: "172.0.12.1",
		})

		localVTEP := vxlanMgr.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		vxlanMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(vxlanMgr.myVTEP).NotTo(BeNil())
		Expect(vxlanMgr.routeMgr.parentDevice).NotTo(BeEmpty())

		parent, err := vxlanMgr.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(parent).NotTo(BeNil())

		link, addr, err := vxlanMgr.device(parent)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = vxlanMgr.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(parent).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.0/26",
			DstNodeName: "node1",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.1/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.8.8.7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes["vxlan.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes["vxlan.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1)) // Black hole route
	})

	It("IPv6: should only program black hole routes for local endpoints", func() {
		vxlanMgrV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node1",
			MacV6:            "00:0a:74:9d:68:16",
			Ipv6Addr:         "fd00:10:244::",
			ParentDeviceIpv6: "fc00:10:96::2",
		})

		vxlanMgrV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node2",
			MacV6:            "00:0a:95:9d:68:16",
			Ipv6Addr:         "fd00:10:96::/112",
			ParentDeviceIpv6: "fc00:10:10::1",
		})

		localVTEP := vxlanMgrV6.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		vxlanMgrV6.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(vxlanMgrV6.myVTEP).NotTo(BeNil())
		Expect(vxlanMgrV6.routeMgr.parentDevice).NotTo(BeEmpty())

		parent, err := vxlanMgrV6.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(parent).NotTo(BeNil())

		link, addr, err := vxlanMgrV6.device(parent)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = vxlanMgrV6.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(parent).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::/112",
			DstNodeName: "node1",
			DstNodeIp:   "fc00:10:10::8",
			SameSubnet:  true,
		})

		// Borrowed /128 should not be programmed as blackhole.
		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/128",
			DstNodeName: "node1",
			DstNodeIp:   "fc00:10:10::7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes["vxlan-v6.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes["vxlan-v6.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1)) // Black hole route
	})

	It("should program directly connected routes for remote VTEPs", func() {
		By("Sending a non-borrowed tunnel IP address")
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL | proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.1.1/32",
			DstNodeName: "node2",
			DstNodeIp:   "172.16.0.1",
			Borrowed:    false,
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect a directly connected route for the remote VTEP.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4][0]).To(Equal(
			routetable.Target{
				RouteKey: routetable.RouteKey{
					CIDR: ip.MustParseCIDROrIP("10.0.1.1/32"),
				},
				MTU: 4444,
			}))

		// Delete the route.
		vxlanMgr.OnUpdate(&proto.RouteRemove{
			Dst: "10.0.1.1/32",
		})

		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect no routes.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(0))
	})

	It("IPv6: should program directly connected routes for remote VTEPs", func() {
		By("Sending a non-borrowed tunnel IP address")
		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL | proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
			Borrowed:    false,
		})

		err := vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect a directly connected route for the remote VTEP.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6][0]).To(Equal(
			routetable.Target{
				RouteKey: routetable.RouteKey{
					CIDR: ip.MustParseCIDROrIP("fc00:10:244::1/112"),
				},
				MTU: 6666,
			}))

		// Delete the route.
		vxlanMgrV6.OnUpdate(&proto.RouteRemove{
			Dst: "fc00:10:244::1/112",
		})

		err = vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect no routes.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(0))
	})
})

var _ = Describe("VXLANManager in BPF mode", func() {
	var (
		dataplane *mocknetlink.MockNetlinkDataplane
		dpConfig  Config
	)

	BeforeEach(func() {
		dataplane = mocknetlink.New()
		_, err := dataplane.NewMockNetlink()
		Expect(err).NotTo(HaveOccurred())
		dataplane.ImmediateLinkUp = true
		eth0 := dataplane.AddIface(2, "eth0", true, true)
		Expect(dataplane.AddrAdd(eth0, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(172, 0, 0, 2)}})).To(Succeed())
		dataplane.ResetDeltas()

		dpConfig = Config{
			MaxIPSetSize: 5,
			Hostname:     "node1",
			BPFEnabled:   true,
			RulesConfig: rules.Config{
				VXLANVNI:  4096,
				VXLANPort: 4789,
			},
		}
	})

	newMgr := func(opts ...vxlanMgrOption) *vxlanManager {
		mgr := newVXLANManagerWithShims(
			dpsets.NewMockIPSets(),
			&mockRouteTable{currentRoutes: map[string][]routetable.Target{}},
			&mockVXLANFDB{},
			dataplanedefs.VXLANIfaceNameV4,
			4,
			0,
			dpConfig,
			logrusr.NewSummarizer("test"),
			dataplane,
			opts...,
		)
		mgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		mgr.routeMgr.OnParentDeviceUpdate("eth0")
		return mgr
	}

	configure := func(mgr *vxlanManager) error {
		parent, err := mgr.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		link, addr, err := mgr.device(parent)
		Expect(err).NotTo(HaveOccurred())
		return mgr.routeMgr.configureTunnelDevice(link, addr, 0, false)
	}

	configureDevice := func(opts ...vxlanMgrOption) error {
		return configure(newMgr(opts...))
	}

	vxlanDevice := func() (*netlink.Vxlan, *mocknetlink.MockLink) {
		ml := dataplane.NameToLink[dataplanedefs.VXLANIfaceNameV4]
		Expect(ml).NotTo(BeNil())
		vx, ok := ml.ConcreteLink.(*netlink.Vxlan)
		Expect(ok).To(BeTrue())
		return vx, ml
	}

	addExistingDevice := func(vniFilter bool, vnis ...uint32) {
		la := netlink.NewLinkAttrs()
		la.Name = dataplanedefs.VXLANIfaceNameV4
		vx := &netlink.Vxlan{LinkAttrs: la, FlowBased: true, VniFilter: vniFilter, Port: 4789}
		Expect(dataplane.LinkAdd(vx)).To(Succeed())
		for _, vni := range vnis {
			Expect(dataplane.BridgeVniAdd(vx, vni)).To(Succeed())
		}
		dataplane.ResetDeltas()
	}

	It("creates a plain flow-based device without the VNI filter option", func() {
		Expect(configureDevice()).To(Succeed())
		vx, ml := vxlanDevice()
		Expect(vx.FlowBased).To(BeTrue())
		Expect(vx.VniFilter).To(BeFalse())
		Expect(ml.VNIs).To(BeNil())
	})

	It("creates a VNI-filtering device that accepts only the overlay and NAT VNIs", func() {
		Expect(configureDevice(vxlanMgrWithVNIFilter())).To(Succeed())
		vx, ml := vxlanDevice()
		Expect(vx.FlowBased).To(BeTrue())
		Expect(vx.VniFilter).To(BeTrue())
		Expect(ml.VNIs.Slice()).To(ConsistOf(uint32(4096), uint32(0xca11c0)))
	})

	It("recreates an existing plain flow-based device with the VNI filter", func() {
		addExistingDevice(false)
		Expect(configureDevice(vxlanMgrWithVNIFilter())).To(Succeed())
		Expect(dataplane.NumLinkDeleteCalls).To(Equal(1))
		vx, ml := vxlanDevice()
		Expect(vx.VniFilter).To(BeTrue())
		Expect(ml.VNIs.Slice()).To(ConsistOf(uint32(4096), uint32(0xca11c0)))
	})

	It("removes stale VNIs from an existing VNI-filtering device", func() {
		addExistingDevice(true, 4096, 7777)
		Expect(configureDevice(vxlanMgrWithVNIFilter())).To(Succeed())
		Expect(dataplane.NumLinkDeleteCalls).To(Equal(0))
		_, ml := vxlanDevice()
		Expect(ml.VNIs.Slice()).To(ConsistOf(uint32(4096), uint32(0xca11c0)))
	})

	It("removes a stale VNI range in one call", func() {
		addExistingDevice(true, 4096)
		vx := dataplane.NameToLink[dataplanedefs.VXLANIfaceNameV4].ConcreteLink
		Expect(dataplane.BridgeVniAddRange(vx, 1, 100000)).To(Succeed())
		dataplane.ResetDeltas()

		Expect(configureDevice(vxlanMgrWithVNIFilter())).To(Succeed())
		Expect(dataplane.NumBridgeVniDelCalls).To(Equal(1))
		_, ml := vxlanDevice()
		Expect(ml.VNIs.Slice()).To(ConsistOf(uint32(4096), uint32(0xca11c0)))
	})

	It("keeps a range that holds only wanted VNIs", func() {
		dpConfig.RulesConfig.VXLANVNI = 0xca11bf
		addExistingDevice(true, 0xca11bf, 0xca11c0)
		Expect(configureDevice(vxlanMgrWithVNIFilter())).To(Succeed())
		Expect(dataplane.NumBridgeVniDelCalls).To(Equal(0))
		_, ml := vxlanDevice()
		Expect(ml.VNIs.Slice()).To(ConsistOf(uint32(0xca11bf), uint32(0xca11c0)))
	})

	It("reconciles the VNI filter only when the device is new", func() {
		mgr := newMgr(vxlanMgrWithVNIFilter())
		Expect(configure(mgr)).To(Succeed())
		Expect(dataplane.NumBridgeVniListCalls).To(Equal(1))

		Expect(configure(mgr)).To(Succeed())
		Expect(dataplane.NumBridgeVniListCalls).To(Equal(1), "unchanged device should not be re-checked")

		By("recreating the device")
		Expect(dataplane.LinkDel(dataplane.NameToLink[dataplanedefs.VXLANIfaceNameV4])).To(Succeed())
		Expect(configure(mgr)).To(Succeed())
		Expect(dataplane.NumBridgeVniListCalls).To(Equal(2))
		_, ml := vxlanDevice()
		Expect(ml.VNIs.Slice()).To(ConsistOf(uint32(4096), uint32(0xca11c0)))
	})

	It("returns an error if the VNI filter cannot be listed", func() {
		dataplane.FailuresToSimulate = mocknetlink.FailNextBridgeVni
		Expect(configureDevice(vxlanMgrWithVNIFilter())).To(MatchError(ContainSubstring("VNI filter")))
	})
})
