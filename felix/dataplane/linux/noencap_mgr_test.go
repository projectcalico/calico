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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("NoEncap Manager", func() {
	var (
		noencapMgr *noEncapManager
		rt         *mockRouteTable
		ipSets     *dpsets.MockIPSets
		dataplane  *mockIPIPDataplane
	)

	const (
		externalCIDR = "10.10.10.0/24"
	)

	BeforeEach(func() {
		ipSets = dpsets.NewMockIPSets()
		rt = &mockRouteTable{
			currentRoutes: map[string][]routetable.Target{},
		}

		la := netlink.NewLinkAttrs()
		la.Name = "eth0"
		opRecorder := logutils.NewSummarizer("test")

		dataplane = &mockIPIPDataplane{
			links:          []netlink.Link{&mockLink{attrs: la}},
			tunnelLinkName: dataplanedefs.IPIPIfaceName,
		}
		noencapMgr = newNoEncapManagerWithSims(
			ipSets, rt,
			4,
			Config{
				MaxIPSetSize:       1024,
				Hostname:           "node1",
				ExternalNodesCidrs: []string{"10.10.10.0/24"},
				RulesConfig: rules.Config{
					IPIPTunnelAddress: net.ParseIP("192.168.0.1"),
				},
				ProgramRoutes:       true,
				DeviceRouteProtocol: dataplanedefs.DefaultRouteProto,
			},
			opRecorder,
			dataplane,
		)
	})

	allHostsSet := func() set.Set[string] {
		logrus.Info(ipSets.Members)
		Expect(ipSets.Members).To(HaveLen(1))
		return ipSets.Members["all-hosts-net"]
	}

	It("should handle IPSet updates correctly", func() {
		By("checking the the IP set is not created until first call to CompleteDeferredWork()")
		Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		err := noencapMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(ipSets.AddOrReplaceCalled).To(BeTrue())

		By("adding host1")
		noencapMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host1",
			Ipv4Addr: "10.0.0.1",
		})
		err = noencapMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))

		By("adding host2")
		noencapMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host2",
			Ipv4Addr: "10.0.0.2",
		})
		err = noencapMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", "10.0.0.2", externalCIDR)))

		By("testing tolerance for duplicate ip")
		noencapMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host3",
			Ipv4Addr: "10.0.0.2",
		})
		err = noencapMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", "10.0.0.2", externalCIDR)))

		By("removing the duplicate ip should keep the ip")
		noencapMgr.OnUpdate(&proto.HostMetadataRemove{
			Hostname: "host3",
		})
		err = noencapMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", "10.0.0.2", externalCIDR)))

		By("removing the initial copy of ip")
		noencapMgr.OnUpdate(&proto.HostMetadataRemove{
			Hostname: "host2",
		})
		err = noencapMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))

		By("adding/removing a duplicate IP in one batch")
		noencapMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host2",
			Ipv4Addr: "10.0.0.1",
		})
		noencapMgr.OnUpdate(&proto.HostMetadataRemove{
			Hostname: "host2",
		})
		err = noencapMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))

		By("changing ip of host1")
		noencapMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host1",
			Ipv4Addr: "10.0.0.2",
		})
		err = noencapMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.2", externalCIDR)))

		By("sending a no-op batch")
		ipSets.AddOrReplaceCalled = false
		err = noencapMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.2", externalCIDR)))
	})

	It("successfully adds a route to the noEncap interface", func() {
		noencapMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "10.0.0.1",
		})
		noencapMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "10.0.1.1",
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
			DstNodeIp:   "10.0.1.1",
			SameSubnet:  true,
		})

		noencapMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_NO_ENCAP,
			Dst:         "192.168.0.2/26",
			DstNodeName: "node2",
			DstNodeIp:   "10.0.1.1",
		})

		noencapMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_NO_ENCAP,
			Dst:         "192.168.0.100/26",
			DstNodeName: "node1",
			DstNodeIp:   "10.0.0.1",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		noencapMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_NO_ENCAP,
			Dst:         "192.168.0.10/32",
			DstNodeName: "node1",
			DstNodeIp:   "10.0.0.7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = noencapMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(rt.currentRoutes["eth0"]).NotTo(BeNil())
	})
})
