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
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/vishvananda/netlink"
)

var _ = Describe("RouteManager", func() {
	var manager *routeManager
	var rt *mockRouteTable
	var ipSets *dpsets.MockIPSets

	BeforeEach(func() {
		ipSets = dpsets.NewMockIPSets()
		rt = &mockRouteTable{
			currentRoutes: map[string][]routetable.Target{},
		}

		la := netlink.NewLinkAttrs()
		la.Name = "eth0"
		opRecorder := logutils.NewSummarizer("test")
		manager = newRouteManagerWithShim(
			ipSets, rt, dataplanedefs.IPIPIfaceName,
			Config{
				MaxIPSetSize:       1024,
				Hostname:           "host1",
				ExternalNodesCidrs: []string{"10.10.10.0/24"},
				RulesConfig: rules.Config{
					IPIPTunnelAddress: net.ParseIP("192.168.0.1"),
				},
				ProgramRoutes: true,
				IPIPMTU:       1400,
			},
			opRecorder,
			&mockIPIPDataplane{
				links:          []netlink.Link{&mockLink{attrs: la}},
				tunnelLinkName: dataplanedefs.IPIPIfaceName,
			},
			4,
		)
	})

	It("successfully adds a route to the parent interface", func() {
		manager.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host1",
			Ipv4Addr: "10.0.0.1",
		})
		manager.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host2",
			Ipv4Addr: "10.0.1.1",
		})

		err := manager.configureIPIPDevice(50, manager.dpConfig.RulesConfig.IPIPTunnelAddress, false)
		Expect(err).NotTo(HaveOccurred())
		manager.OnParentNameUpdate("eth0")

		Expect(manager.hostAddr).NotTo(BeZero())
		Expect(manager.noEncapDevice).NotTo(BeEmpty())
		parent, err := manager.getParentInterface()

		Expect(parent).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		manager.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.3/26",
			DstNodeName: "host2",
			DstNodeIp:   "10.0.1.1",
			SameSubnet:  true,
		})

		manager.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.2/26",
			DstNodeName: "host2",
			DstNodeIp:   "10.0.1.1",
		})

		manager.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.100/26",
			DstNodeName: "host1",
			DstNodeIp:   "10.0.0.1",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		manager.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.10/32",
			DstNodeName: "host1",
			DstNodeIp:   "10.0.0.7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = manager.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(1))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(rt.currentRoutes["eth0"]).NotTo(BeNil())
	})

	It("adds the route to the default table on next try when the parent route table is not immediately found", func() {
		parentNameC := make(chan string)
		go manager.KeepIPIPDeviceInSync(false, 1*time.Second, parentNameC)

		manager.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host2",
			Ipv4Addr: "10.0.1.1/32",
		})

		manager.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "172.0.0.1/26",
			DstNodeName: "host2",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		err := manager.CompleteDeferredWork()
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(Equal("no encap route table not set, will defer adding routes"))
		Expect(manager.routesDirty).To(BeTrue())

		manager.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host1",
			Ipv4Addr: "10.0.0.1",
		})

		Expect(manager.hostAddr).NotTo(BeZero())

		// Note: parent name is sent after configuration so this receive
		// ensures we don't race.
		Eventually(parentNameC, "2s").Should(Receive(Equal("eth0")))
		manager.OnParentNameUpdate("eth0")

		err = manager.configureIPIPDevice(50, manager.dpConfig.RulesConfig.IPIPTunnelAddress, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		err = manager.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(manager.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
	})
})
