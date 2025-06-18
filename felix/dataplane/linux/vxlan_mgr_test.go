// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/vxlanfdb"
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

		la := netlink.NewLinkAttrs()
		la.Name = "eth0"
		opRecorder := logutils.NewSummarizer("test")

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
			&mockTunnelDataplane{
				links:          []netlink.Link{&mockLink{attrs: la}},
				tunnelLinkName: dataplanedefs.VXLANIfaceNameV4,
				ipVersion:      4,
			},
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
			&mockTunnelDataplane{
				links:          []netlink.Link{&mockLink{attrs: la}},
				tunnelLinkName: dataplanedefs.VXLANIfaceNameV6,
				ipVersion:      6,
			},
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
			DstNodeName: "node0",
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
			DstNodeName: "node0",
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
				CIDR: ip.MustParseCIDROrIP("10.0.1.1/32"),
				MTU:  4444,
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
				CIDR: ip.MustParseCIDROrIP("fc00:10:244::1/112"),
				MTU:  6666,
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
