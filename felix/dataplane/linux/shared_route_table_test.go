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
	"github.com/projectcalico/calico/felix/dataplane/linux/dpconfig"
	"github.com/projectcalico/calico/felix/dataplane/linux/dptest"
	"github.com/projectcalico/calico/felix/dataplane/linux/ipip"
	"github.com/projectcalico/calico/felix/dataplane/linux/ipip/ipipdefs"
	"github.com/projectcalico/calico/felix/dataplane/linux/noencap"
	"github.com/projectcalico/calico/felix/dataplane/linux/vxlan"
	"github.com/projectcalico/calico/felix/dataplane/linux/vxlan/vxlandefs"
	"github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/lib/logrusr"
)

// The tunnel managers all program the main route table and all see every route
// update, as wired up by the dataplane.
var _ = Describe("VXLAN, IPIP and no-encap managers sharing one route table", func() {
	var (
		rt        *dptest.MockRouteTable
		dataplane *mocknetlink.MockNetlinkDataplane
		dpConfig  dpconfig.Config
	)

	BeforeEach(func() {
		rt = dptest.NewMockRouteTable()

		dataplane = mocknetlink.New()
		_, err := dataplane.NewMockNetlink()
		Expect(err).NotTo(HaveOccurred())
		eth0 := dataplane.AddIface(2, "eth0", true, true)
		Expect(dataplane.AddrAdd(eth0, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(172, 0, 0, 2)}})).To(Succeed())
		dataplane.ResetDeltas()

		dpConfig = dpconfig.Config{
			Hostname:     "node1",
			MaxIPSetSize: 5,
			// The IPIP and no-encap managers only program routes when Felix, rather than
			// confd and BIRD, owns the cluster routes for that encapsulation.
			ProgramIPIPClusterRoutes:    true,
			ProgramNoEncapClusterRoutes: true,
		}
	})

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
		vxlanMgr := vxlan.NewManagerWithShims(
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
		ipipMgr := ipip.NewManagerWithShims(
			rt,
			ipipdefs.IPIPIfaceName,
			4,
			1400,
			dpConfig,
			logrusr.NewSummarizer("test"),
			dataplane,
		)
		noEncapMgr := noencap.NewManagerWithShims(
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
