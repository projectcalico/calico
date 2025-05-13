// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("RouteManager for ipip pools", func() {
	var (
		ipipMgr  *ipipManager
		routeMgr *routeManager
		rt       *mockRouteTable
		ipSets   *dpsets.MockIPSets
	)

	BeforeEach(func() {
		ipSets = dpsets.NewMockIPSets()
		rt = &mockRouteTable{
			currentRoutes: map[string][]routetable.Target{},
		}

		la := netlink.NewLinkAttrs()
		la.Name = "eth0"
		opRecorder := logutils.NewSummarizer("test")

		dpConfig := Config{
			MaxIPSetSize:       1024,
			Hostname:           "node1",
			ExternalNodesCidrs: []string{"10.10.10.0/24"},
			RulesConfig: rules.Config{
				IPIPTunnelAddress: net.ParseIP("192.168.0.1"),
			},
			ProgramRoutes:       true,
			DeviceRouteProtocol: dataplanedefs.DefaultRouteProto,
		}
		routeMgr = newRouteManagerWithShims(
			rt,
			proto.IPPoolType_IPIP,
			dataplanedefs.IPIPIfaceName,
			4,
			1400,
			dpConfig,
			opRecorder,
			&mockIPIPDataplane{
				links:          []netlink.Link{&mockLink{attrs: la}},
				tunnelLinkName: dataplanedefs.IPIPIfaceName,
				//ipVersion:      4,
			},
		)
		ipipMgr = newIPIPManager(
			ipSets, routeMgr, dataplanedefs.IPIPIfaceName,
			4,
			1400,
			dpConfig,
			opRecorder,
		)
		//ipipMgr.updateRouteManager(routeMgr)
	})

	It("successfully adds a route to the noEncap interface", func() {
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "10.0.0.1",
		})
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "10.0.1.1",
		})

		routeMgr.OnDataDeviceUpdate("eth0")

		Expect(routeMgr.dataDeviceAddr).NotTo(BeZero())
		Expect(routeMgr.dataDevice).NotTo(BeEmpty())
		noEncapDev, err := routeMgr.detectDataIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(noEncapDev).NotTo(BeNil())

		link, addr, err := ipipMgr.device(noEncapDev)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(noEncapDev).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.3/26",
			DstNodeName: "node2",
			DstNodeIp:   "10.0.1.1",
			SameSubnet:  true,
		})

		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.2/26",
			DstNodeName: "node2",
			DstNodeIp:   "10.0.1.1",
		})

		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.100/26",
			DstNodeName: "node1",
			DstNodeIp:   "10.0.0.1",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.10/32",
			DstNodeName: "node1",
			DstNodeIp:   "10.0.0.7",
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
		go ipipMgr.KeepIPIPDeviceInSync(1400, false, 1*time.Second, dataDeviceC)

		By("Sending another node's route.")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "10.0.0.2",
		})
		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "172.0.0.1/26",
			DstNodeName: "node2",
			DstNodeIp:   "10.0.0.2",
			SameSubnet:  true,
		})

		err := ipipMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(ipipMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(1))

		By("Sending another local node update.")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "10.0.0.1",
		})
		localAddr := routeMgr.dataIfaceAddr()
		Expect(localAddr).NotTo(BeNil())

		// Note: no encap device name is sent after configuration so this receive
		// ensures we don't race.

		By("waiting")
		Eventually(dataDeviceC, "2s").Should(Receive(Equal("eth0")))
		routeMgr.OnDataDeviceUpdate("eth0")

		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		err = ipipMgr.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(ipipMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
	})
})

var _ = Describe("ipipManager all-hosts IP set updates", func() {
	var (
		ipipMgr  *ipipManager
		routeMgr *routeManager
		ipSets   *dpsets.MockIPSets
		rt       *mockRouteTable
	)

	const (
		externalCIDR = "11.0.0.1/32"
	)

	BeforeEach(func() {
		ipSets = dpsets.NewMockIPSets()
		rt = &mockRouteTable{
			currentRoutes: map[string][]routetable.Target{},
		}

		la := netlink.NewLinkAttrs()
		la.Name = "eth0"
		opRecorder := logutils.NewSummarizer("test")

		dpConfig := Config{
			MaxIPSetSize:       1024,
			Hostname:           "host1",
			ExternalNodesCidrs: []string{externalCIDR},
		}
		routeMgr = newRouteManagerWithShims(
			rt,
			proto.IPPoolType_IPIP,
			dataplanedefs.IPIPIfaceName,
			4,
			1400,
			dpConfig,
			opRecorder,
			&mockIPIPDataplane{
				links:          []netlink.Link{&mockLink{attrs: la}},
				tunnelLinkName: dataplanedefs.IPIPIfaceName,
				//ipVersion:      4,
			},
		)
		ipipMgr = newIPIPManager(
			ipSets, routeMgr, dataplanedefs.IPIPIfaceName,
			4,
			1400,
			dpConfig,
			opRecorder,
		)
		//ipipMgr.updateRouteManager(routeMgr)

		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host1",
			Ipv4Addr: "10.0.0.1",
		})
		routeMgr.OnDataDeviceUpdate("eth0")
	})

	It("should not create the IP set until first call to CompleteDeferredWork()", func() {
		Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		err := ipipMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
	})

	allHostsSet := func() set.Set[string] {
		log.Info(ipSets.Members)
		Expect(ipSets.Members).To(HaveLen(1))
		return ipSets.Members["all-hosts-net"]
	}

	Describe("after adding an IP for host1", func() {
		BeforeEach(func() {
			ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
				Hostname: "host1",
				Ipv4Addr: "10.0.0.1",
			})
			err := ipipMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should add host1's IP to the IP set", func() {
			Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))
		})

		Describe("after adding an IP for host2", func() {
			BeforeEach(func() {
				ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
					Hostname: "host2",
					Ipv4Addr: "10.0.0.2",
				})
				err := ipipMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})
			It("should add the IP to the IP set", func() {
				Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", "10.0.0.2", externalCIDR)))
			})
		})

		Describe("after adding a duplicate IP", func() {
			BeforeEach(func() {
				ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
					Hostname: "host2",
					Ipv4Addr: "10.0.0.1",
				})
				err := ipipMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})
			It("should tolerate the duplicate", func() {
				Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))
			})

			Describe("after removing a duplicate IP", func() {
				BeforeEach(func() {
					ipipMgr.OnUpdate(&proto.HostMetadataRemove{
						Hostname: "host2",
					})
					err := ipipMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})
				It("should keep the IP in the IP set", func() {
					Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))
				})

				Describe("after removing initial copy of IP", func() {
					BeforeEach(func() {
						ipipMgr.OnUpdate(&proto.HostMetadataRemove{
							Hostname: "host1",
						})
						err := ipipMgr.CompleteDeferredWork()
						Expect(err).ToNot(HaveOccurred())
					})
					It("should remove the IP", func() {
						Expect(allHostsSet().Len()).To(Equal(1))
					})
				})
			})
		})

		Describe("after adding/removing a duplicate IP in one batch", func() {
			BeforeEach(func() {
				ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
					Hostname: "host2",
					Ipv4Addr: "10.0.0.1",
				})
				ipipMgr.OnUpdate(&proto.HostMetadataRemove{
					Hostname: "host2",
				})
				err := ipipMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})
			It("should keep the IP in the IP set", func() {
				Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))
			})
		})

		Describe("after changing IP for host1", func() {
			BeforeEach(func() {
				ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
					Hostname: "host1",
					Ipv4Addr: "10.0.0.2",
				})
				err := ipipMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})
			It("should update the IP set", func() {
				Expect(allHostsSet()).To(Equal(set.From("10.0.0.2", externalCIDR)))
			})
		})

		Describe("after a no-op batch", func() {
			BeforeEach(func() {
				ipSets.AddOrReplaceCalled = false
				err := ipipMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})
			It("shouldn't rewrite the IP set", func() {
				Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
			})
		})
	})
})
