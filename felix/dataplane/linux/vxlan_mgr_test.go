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
	"net"
	"time"

	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
)

type mockVXLANDataplane struct {
	links []netlink.Link
}

func (m *mockVXLANDataplane) LinkByName(name string) (netlink.Link, error) {
	return &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: "vxlan",
		},
		VxlanId:      1,
		Port:         20,
		VtepDevIndex: 2,
		SrcAddr:      ip.FromString("172.0.0.2").AsNetIP()}, nil
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
	},
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

var _ = Describe("VXLANManager", func() {
	var manager *vxlanManager
	var rt, brt, prt *mockRouteTable

	BeforeEach(func() {
		rt = &mockRouteTable{
			currentRoutes:   map[string][]routetable.Target{},
			currentL2Routes: map[string][]routetable.L2Target{},
		}
		brt = &mockRouteTable{
			currentRoutes:   map[string][]routetable.Target{},
			currentL2Routes: map[string][]routetable.L2Target{},
		}
		prt = &mockRouteTable{
			currentRoutes:   map[string][]routetable.Target{},
			currentL2Routes: map[string][]routetable.L2Target{},
		}

		manager = newVXLANManagerWithShims(
			common.NewMockIPSets(),
			rt, brt,
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
			&mockVXLANDataplane{
				links: []netlink.Link{&mockLink{attrs: netlink.LinkAttrs{Name: "eth0"}}},
			},
			4,
			func(interfacePrefixes []string, ipVersion uint8, vxlan bool, netlinkTimeout time.Duration,
				deviceRouteSourceAddress net.IP, deviceRouteProtocol netlink.RouteProtocol, removeExternalRoutes bool) routeTable {
				return prt
			},
		)
	})

	It("successfully adds a route to the parent interface", func() {
		manager.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node1",
			Mac:              "00:0a:74:9d:68:16",
			Ipv4Addr:         "10.0.0.0",
			ParentDeviceIpv4: "172.0.0.2",
		})

		manager.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node2",
			Mac:              "00:0a:95:9d:68:16",
			Ipv4Addr:         "10.0.80.0/32",
			ParentDeviceIpv4: "172.0.12.1",
		})

		localVTEP := manager.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		manager.noEncapRouteTable = prt

		err := manager.configureVXLANDevice(50, localVTEP, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(manager.myVTEP).NotTo(BeNil())
		Expect(manager.noEncapRouteTable).NotTo(BeNil())
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
		Expect(brt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = manager.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(rt.currentRoutes["vxlan.calico"]).To(HaveLen(1))
		Expect(brt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(prt.currentRoutes["eth0"]).NotTo(BeNil())
	})

	It("adds the route to the default table on next try when the parent route table is not immediately found", func() {
		go manager.KeepVXLANDeviceInSync(1400, false, 1*time.Second)
		manager.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node2",
			Mac:              "00:0a:95:9d:68:16",
			Ipv4Addr:         "10.0.80.0/32",
			ParentDeviceIpv4: "172.0.12.1",
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

		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(Equal("no encap route table not set, will defer adding routes"))
		Expect(manager.routesDirty).To(BeTrue())

		manager.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node1",
			Mac:              "00:0a:74:9d:68:16",
			Ipv4Addr:         "10.0.0.0",
			ParentDeviceIpv4: "172.0.0.2",
		})

		time.Sleep(2 * time.Second)

		localVTEP := manager.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		err = manager.configureVXLANDevice(50, localVTEP, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(prt.currentRoutes["eth0"]).To(HaveLen(0))
		err = manager.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(manager.routesDirty).To(BeFalse())
		Expect(prt.currentRoutes["eth0"]).To(HaveLen(1))
	})
})
