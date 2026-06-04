// Copyright (c) 2017-2026 Tigera, Inc. All rights reserved.
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
	"context"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
)

var _ = Describe("IPIPManager", func() {
	var (
		ipipMgr   *ipipManager
		rt        *mockRouteTable
		dataplane *mocknetlink.MockNetlinkDataplane
	)

	BeforeEach(func() {
		rt = &mockRouteTable{
			currentRoutes: map[string][]routetable.Target{},
		}

		opRecorder := logutils.NewSummarizer("test")

		dataplane = mocknetlink.New()
		_, err := dataplane.NewMockNetlink()
		Expect(err).NotTo(HaveOccurred())
		dataplane.ImmediateLinkUp = true
		eth0 := dataplane.AddIface(2, "eth0", true, true)
		Expect(dataplane.AddrAdd(eth0, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(172, 0, 0, 2)}})).To(Succeed())
		dataplane.ResetDeltas()

		ipipMgr = newIPIPManagerWithShims(
			rt, dataplanedefs.IPIPIfaceName,
			4,
			1400,
			Config{
				MaxIPSetSize:       1024,
				Hostname:           "node1",
				ExternalNodesCidrs: []string{"10.10.10.0/24"},
				RulesConfig: rules.Config{
					IPIPTunnelAddress: net.ParseIP("192.168.0.1"),
				},
				ProgramClusterRoutes: true,
				DeviceRouteProtocol:  dataplanedefs.DefaultRouteProto,
			},
			opRecorder,
			dataplane,
		)
	})

	It("should configure tunnel properly", func() {
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		ipipMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(ipipMgr.routeMgr.parentDeviceAddr).NotTo(BeZero())
		Expect(ipipMgr.routeMgr.parentDevice).NotTo(BeEmpty())
		noEncapDev, err := ipipMgr.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(noEncapDev).NotTo(BeNil())

		link, addr, err := ipipMgr.device(noEncapDev)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = ipipMgr.routeMgr.configureTunnelDevice(link, addr, 1400, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(noEncapDev).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		tunnelLink := dataplane.NameToLink[dataplanedefs.IPIPIfaceName]
		Expect(tunnelLink).ToNot(BeNil())
		Expect(tunnelLink.LinkAttrs.MTU).To(Equal(1400))
		Expect(tunnelLink.LinkAttrs.Flags).To(Equal(net.FlagUp))
		Expect(tunnelLink.Addrs).To(HaveLen(1))
		Expect(tunnelLink.Addrs[0].IP.String()).To(Equal("192.168.0.1"))

		dataplane.ResetDeltas()
		err = ipipMgr.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(dataplane.NumLinkAddCalls).To(BeZero())
		Expect(dataplane.NumLinkSetUpCalls).To(BeZero())
		Expect(dataplane.NumLinkSetMTUCalls).To(Equal(1))
		Expect(tunnelLink.LinkAttrs.MTU).To(Equal(50))
		Expect(dataplane.AddedAddrs.Len()).To(BeZero())
		Expect(dataplane.DeletedAddrs.Len()).To(BeZero())

		dataplane.ResetDeltas()
		err = ipipMgr.routeMgr.configureTunnelDevice(link, addr, 1500, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(dataplane.NumLinkAddCalls).To(BeZero())
		Expect(dataplane.NumLinkSetUpCalls).To(BeZero())
		Expect(tunnelLink.LinkAttrs.MTU).To(Equal(1500))
		Expect(tunnelLink.Addrs).To(HaveLen(1))
		Expect(tunnelLink.Addrs[0].IP.String()).To(Equal("192.168.0.1"))

		dataplane.ResetDeltas()
		err = ipipMgr.routeMgr.configureTunnelDevice(link, "", 1500, false)
		Expect(err).To(HaveOccurred())
		Expect(dataplane.NameToLink[dataplanedefs.IPIPIfaceName]).ToNot(BeNil())
		Expect(dataplane.NumLinkAddCalls).To(BeZero())
		Expect(dataplane.NumLinkSetUpCalls).To(BeZero())
		Expect(tunnelLink.LinkAttrs.MTU).To(Equal(1500))
		Expect(tunnelLink.LinkAttrs.Flags).To(Equal(net.FlagUp))
		Expect(tunnelLink.Addrs).To(HaveLen(1))
		Expect(tunnelLink.Addrs[0].IP.String()).To(Equal("192.168.0.1"))
	})

	It("successfully adds a route to the noEncap interface", func() {
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "172.0.2.2",
		})

		ipipMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(ipipMgr.routeMgr.parentDeviceAddr).NotTo(BeZero())
		Expect(ipipMgr.routeMgr.parentDevice).NotTo(BeEmpty())
		noEncapDev, err := ipipMgr.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(noEncapDev).NotTo(BeNil())

		link, addr, err := ipipMgr.device(noEncapDev)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = ipipMgr.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(noEncapDev).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.3/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.0.2.2",
			SameSubnet:  true,
		})

		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.2/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.0.2.2",
		})

		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.100/26",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.10/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = ipipMgr.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(1))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(rt.currentRoutes["eth0"]).NotTo(BeNil())
	})

	It("should fall back to programming tunneled routes if the noEncap device is not known", func() {
		dataDeviceC := make(chan string)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go ipipMgr.keepIPIPDeviceInSync(ctx, 1400, false, 1*time.Second, dataDeviceC)

		By("Sending another node's route.")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "10.0.0.2",
		})
		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.10.0/26",
			DstNodeName: "node2",
			DstNodeIp:   "10.0.0.2",
			SameSubnet:  true,
		})

		err := ipipMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(ipipMgr.routeMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(1))

		By("Sending another local node update.")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		localAddr := ipipMgr.routeMgr.parentIfaceAddr()
		Expect(localAddr).NotTo(BeNil())

		// Note: no encap device name is sent after configuration so this receive
		// ensures we don't race.

		By("waiting")
		Eventually(dataDeviceC, "2s").Should(Receive(Equal("eth0")))
		ipipMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		err = ipipMgr.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(ipipMgr.routeMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
	})

	It("should program routes for remote endpoints with borrowed IP addresses", func() {
		By("Sending host updates")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "172.0.2.2",
		})

		By("Sending a borrowed tunnel IP address")
		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "10.0.1.1/32",
			DstNodeName: "node2",
			DstNodeIp:   "172.0.2.2",
			Borrowed:    true,
		})

		err := ipipMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect a directly connected route to the borrowed IP.
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName][0]).To(Equal(
			routetable.Target{
				Type: "onlink",
				RouteKey: routetable.RouteKey{
					CIDR: ip.MustParseCIDROrIP("10.0.1.1/32"),
				},
				GW:       ip.FromString("172.0.2.2"),
				Protocol: 80,
			}))

		// Delete the route.
		ipipMgr.OnUpdate(&proto.RouteRemove{
			Dst: "10.0.1.1/32",
		})

		err = ipipMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect no routes.
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
	})

	It("should only program black hole routes for local endpoints", func() {
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "172.0.2.2",
		})

		ipipMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(ipipMgr.routeMgr.parentDeviceAddr).NotTo(BeZero())
		Expect(ipipMgr.routeMgr.parentDevice).NotTo(BeEmpty())
		noEncapDev, err := ipipMgr.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(noEncapDev).NotTo(BeNil())

		link, addr, err := ipipMgr.device(noEncapDev)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = ipipMgr.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(noEncapDev).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.100/26",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.10/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))

		err = ipipMgr.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1)) // Black hole route
	})

	It("should program routes for remote tunnel endpoint", func() {
		By("Sending host updates")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "172.0.2.2",
		})

		By("Sending a tunnel IP address")
		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL | proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "10.0.1.1/32",
			DstNodeName: "node2",
			DstNodeIp:   "172.0.2.2",
			Borrowed:    false,
		})

		err := ipipMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect one exact route.
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName][0]).To(Equal(
			routetable.Target{
				Type: "onlink",
				RouteKey: routetable.RouteKey{
					CIDR: ip.MustParseCIDROrIP("10.0.1.1/32"),
				},
				GW:       ip.FromString("172.0.2.2"),
				Protocol: 80,
			}))

		// Delete the route.
		ipipMgr.OnUpdate(&proto.RouteRemove{
			Dst: "10.0.1.1/32",
		})

		err = ipipMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect no routes.
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
	})
})
