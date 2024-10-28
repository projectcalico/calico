// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

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
	log "github.com/sirupsen/logrus"
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

type mockVXLANDataplane struct {
	links     []netlink.Link
	ipVersion uint8
}

func (m *mockVXLANDataplane) LinkByName(name string) (netlink.Link, error) {
	la := netlink.NewLinkAttrs()
	la.Name = "vxlan"
	link := &netlink.Vxlan{
		LinkAttrs:    la,
		VxlanId:      1,
		Port:         20,
		VtepDevIndex: 2,
		SrcAddr:      ip.FromString("172.0.0.2").AsNetIP(),
	}

	la.Name = "vxlan-v6"
	if m.ipVersion == 6 {
		link = &netlink.Vxlan{
			LinkAttrs:    la,
			VxlanId:      1,
			Port:         20,
			VtepDevIndex: 2,
			SrcAddr:      ip.FromString("fc00:10:96::2").AsNetIP(),
		}
	}

	return link, nil
}

func (m *mockVXLANDataplane) LinkSetMTU(link netlink.Link, mtu int) error {
	return nil
}

func (m *mockVXLANDataplane) LinkSetUp(link netlink.Link) error {
	return nil
}

func (m *mockVXLANDataplane) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	l := []netlink.Addr{{
		IPNet: &net.IPNet{
			IP: net.IPv4(172, 0, 0, 2),
		},
	}}

	if m.ipVersion == 6 {
		l = []netlink.Addr{{
			IPNet: &net.IPNet{
				IP: net.ParseIP("fc00:10:96::2"),
			},
		}}
	}
	return l, nil
}

func (m *mockVXLANDataplane) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	return nil
}

func (m *mockVXLANDataplane) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	return nil
}

func (m *mockVXLANDataplane) LinkList() ([]netlink.Link, error) {
	return m.links, nil
}

func (m *mockVXLANDataplane) LinkAdd(netlink.Link) error {
	return nil
}

func (m *mockVXLANDataplane) LinkDel(netlink.Link) error {
	return nil
}

type mockVXLANFDB struct {
	setVTEPsCalls int
	currentVTEPs  []vxlanfdb.VTEP
}

func (t *mockVXLANFDB) SetVTEPs(targets []vxlanfdb.VTEP) {
	log.WithFields(log.Fields{
		"targets": targets,
	}).Debug("SetVTEPs")
	t.currentVTEPs = targets
	t.setVTEPsCalls++
}

var _ = Describe("VXLANManager", func() {
	var manager, managerV6 *vxlanManager
	var rt *mockRouteTable
	var fdb *mockVXLANFDB

	BeforeEach(func() {
		rt = &mockRouteTable{
			currentRoutes: map[string][]routetable.Target{},
		}

		fdb = &mockVXLANFDB{}

		la := netlink.NewLinkAttrs()
		la.Name = "eth0"
		opRecorder := logutils.NewSummarizer("test")
		manager = newVXLANManagerWithShims(
			dpsets.NewMockIPSets(),
			rt,
			fdb,
			"vxlan.calico",
			Config{
				MaxIPSetSize:       5,
				Hostname:           "node1",
				ExternalNodesCidrs: []string{"10.0.0.0/24"},
				RulesConfig: rules.Config{
					VXLANVNI:  1,
					VXLANPort: 20,
				},
			},
			opRecorder,
			&mockVXLANDataplane{
				links:     []netlink.Link{&mockLink{attrs: la}},
				ipVersion: 4,
			},
			4,
		)

		managerV6 = newVXLANManagerWithShims(
			dpsets.NewMockIPSets(),
			rt,
			fdb,
			"vxlan-v6.calico",
			Config{
				MaxIPSetSize:       5,
				Hostname:           "node1",
				ExternalNodesCidrs: []string{"fd00:10:244::/112"},
				RulesConfig: rules.Config{
					VXLANVNI:  1,
					VXLANPort: 20,
				},
			},
			opRecorder,
			&mockVXLANDataplane{
				links:     []netlink.Link{&mockLink{attrs: la}},
				ipVersion: 6,
			},
			6,
		)
	})

	It("successfully adds a route to the parent interface", func() {
		manager.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})

		manager.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.80.0/32",
			ParentDeviceIp: "172.0.12.1",
		})

		localVTEP := manager.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		err := manager.configureVXLANDevice(50, localVTEP, false)
		Expect(err).NotTo(HaveOccurred())
		manager.OnParentNameUpdate("eth0")

		Expect(manager.myVTEP).NotTo(BeNil())
		Expect(manager.parentIfaceName).NotTo(BeEmpty())
		parent, err := manager.getLocalVTEPParent()

		Expect(parent).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		manager.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.1/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		manager.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.2/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.8.8.8",
		})

		manager.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.0/26",
			DstNodeName: "node0",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		manager.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.1/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.8.8.7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes["vxlan.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = manager.CompleteDeferredWork()
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
		err = manager.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.setVTEPsCalls).To(Equal(1))
	})

	It("successfully adds a IPv6 route to the parent interface", func() {
		managerV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node1",
			MacV6:            "00:0a:74:9d:68:16",
			Ipv6Addr:         "fd00:10:244::",
			ParentDeviceIpv6: "fc00:10:96::2",
		})

		managerV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node2",
			MacV6:            "00:0a:95:9d:68:16",
			Ipv6Addr:         "fd00:10:96::/112",
			ParentDeviceIpv6: "fc00:10:10::1",
		})

		localVTEP := managerV6.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		err := managerV6.configureVXLANDevice(50, localVTEP, false)
		Expect(err).NotTo(HaveOccurred())
		managerV6.OnParentNameUpdate("eth0")

		Expect(managerV6.myVTEP).NotTo(BeNil())
		Expect(managerV6.parentIfaceName).NotTo(BeEmpty())
		parent, err := managerV6.getLocalVTEPParent()

		Expect(parent).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		managerV6.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
			SameSubnet:  true,
		})

		managerV6.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::2/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
		})

		managerV6.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::/112",
			DstNodeName: "node0",
			DstNodeIp:   "fc00:10:10::8",
			SameSubnet:  true,
		})

		// Borrowed /128 should not be programmed as blackhole.
		managerV6.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/128",
			DstNodeName: "node1",
			DstNodeIp:   "fc00:10:10::7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes["vxlan-v6.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = managerV6.CompleteDeferredWork()
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
		err = managerV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.setVTEPsCalls).To(Equal(1))
	})

	It("should fall back to programming tunneled routes if the parent device is not known", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		parentNameC := make(chan string)
		go manager.KeepVXLANDeviceInSync(ctx, 1400, false, 1*time.Second, parentNameC)

		By("Sending another node's VTEP and route.")
		manager.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.80.0/32",
			ParentDeviceIp: "172.0.12.1",
		})
		manager.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.1/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		err := manager.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(manager.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(1))

		By("Sending another local VTEP.")
		manager.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		localVTEP := manager.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		// Note: parent name is sent after configuration so this receive
		// ensures we don't race.
		Eventually(parentNameC, "2s").Should(Receive(Equal("eth0")))
		manager.OnParentNameUpdate("eth0")

		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		err = manager.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(manager.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(0))
	})

	It("IPv6: should fall back to programming tunneled routes if the parent device is not known", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		parentNameC := make(chan string)
		go managerV6.KeepVXLANDeviceInSync(ctx, 1400, false, 1*time.Second, parentNameC)

		By("Sending another node's VTEP and route.")
		managerV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node2",
			MacV6:            "00:0a:95:9d:68:16",
			Ipv6Addr:         "fd00:10:96::/112",
			ParentDeviceIpv6: "fc00:10:10::1",
		})
		managerV6.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
			SameSubnet:  true,
		})

		err := managerV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(managerV6.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(1))

		By("Sending another local VTEP.")
		managerV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node1",
			MacV6:            "00:0a:74:9d:68:16",
			Ipv6Addr:         "fd00:10:244::",
			ParentDeviceIpv6: "fc00:10:96::2",
		})
		localVTEP := managerV6.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		// Note: parent name is sent after configuration so this receive
		// ensures we don't race.
		Eventually(parentNameC, "2s").Should(Receive(Equal("eth0")))
		managerV6.OnParentNameUpdate("eth0")

		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		err = managerV6.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(managerV6.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(0))
	})
})
