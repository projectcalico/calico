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
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
)

// classAwareMockRouteTable models the part of RouteTable's contract that matters
// here: the desired state is keyed on (route class, interface name) and SetRoutes
// _replaces_ the whole set of targets for that key.  (mockRouteTable, used by the
// other manager tests, is keyed on interface name alone so it can't distinguish
// between managers that write to the same pseudo-interface.)
type classAwareMockRouteTable struct {
	routes map[routetable.RouteClass]map[string][]routetable.Target
}

func newClassAwareMockRouteTable() *classAwareMockRouteTable {
	return &classAwareMockRouteTable{
		routes: map[routetable.RouteClass]map[string][]routetable.Target{},
	}
}

func (t *classAwareMockRouteTable) SetRoutes(class routetable.RouteClass, ifaceName string, targets []routetable.Target) {
	if t.routes[class] == nil {
		t.routes[class] = map[string][]routetable.Target{}
	}
	t.routes[class][ifaceName] = targets
}

func (t *classAwareMockRouteTable) cidrsForClass(class routetable.RouteClass, ifaceName string) []string {
	var cidrs []string
	for _, target := range t.routes[class][ifaceName] {
		cidrs = append(cidrs, target.CIDR.String())
	}
	return cidrs
}

func (t *classAwareMockRouteTable) RouteRemove(routetable.RouteClass, string, routetable.RouteKey) {}
func (t *classAwareMockRouteTable) RouteUpdate(routetable.RouteClass, string, routetable.Target)   {}
func (t *classAwareMockRouteTable) OnIfaceStateChanged(string, int, ifacemonitor.State)            {}
func (t *classAwareMockRouteTable) QueueResync()                                                   {}
func (t *classAwareMockRouteTable) QueueResyncIface(string)                                        {}
func (t *classAwareMockRouteTable) Index() int                                                     { return 0 }
func (t *classAwareMockRouteTable) Apply() error                                                   { return nil }

func (t *classAwareMockRouteTable) ReadRoutesFromKernel(string) ([]routetable.Target, error) {
	return nil, nil
}

var _ routetable.Interface = (*classAwareMockRouteTable)(nil)

var _ = Describe("Route manager", func() {
	var (
		rt        *classAwareMockRouteTable
		dataplane *mocknetlink.MockNetlinkDataplane
		dpConfig  Config
	)

	BeforeEach(func() {
		rt = newClassAwareMockRouteTable()

		dataplane = mocknetlink.New()
		_, err := dataplane.NewMockNetlink()
		Expect(err).NotTo(HaveOccurred())
		eth0 := dataplane.AddIface(2, "eth0", true, true)
		Expect(dataplane.AddrAdd(eth0, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(172, 0, 0, 2)}})).To(Succeed())
		dataplane.ResetDeltas()

		dpConfig = Config{
			Hostname:             "node1",
			MaxIPSetSize:         5,
			ProgramClusterRoutes: true,
		}
	})

	Describe("with VXLAN, IPIP and no-encap managers sharing one route table", func() {
		// This mirrors the way int_dataplane wires the managers up: they all
		// program the same main route table, and they all see every route update.
		var managers []Manager

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
				&mockVXLANFDB{},
				dataplanedefs.VXLANIfaceNameV4,
				4,
				1400,
				dpConfig,
				logutils.NewSummarizer("test"),
				dataplane,
			)
			ipipMgr := newIPIPManagerWithShims(
				rt,
				dataplanedefs.IPIPIfaceName,
				4,
				1400,
				dpConfig,
				logutils.NewSummarizer("test"),
				dataplane,
			)
			noEncapMgr := newNoEncapManagerWithSims(
				rt,
				4,
				dpConfig,
				logutils.NewSummarizer("test"),
				dataplane,
			)
			managers = []Manager{vxlanMgr, ipipMgr, noEncapMgr}

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
			Expect(rt.cidrsForClass(routetable.RouteClassIPAMBlockDropVXLAN, routetable.InterfaceNone)).To(
				ConsistOf("10.0.1.0/26"))
			Expect(rt.cidrsForClass(routetable.RouteClassIPAMBlockDropIPIP, routetable.InterfaceNone)).To(
				ConsistOf("10.0.2.0/26"))
			Expect(rt.cidrsForClass(routetable.RouteClassIPAMBlockDropNoEncap, routetable.InterfaceNone)).To(
				ConsistOf("10.0.3.0/26"))
		})

		It("should remove only its own blackhole routes when a block goes away", func() {
			for _, m := range managers {
				m.OnUpdate(&proto.RouteRemove{Dst: "10.0.2.0/26"})
			}
			for _, m := range managers {
				Expect(m.CompleteDeferredWork()).To(Succeed())
			}

			Expect(rt.cidrsForClass(routetable.RouteClassIPAMBlockDropIPIP, routetable.InterfaceNone)).To(BeEmpty())
			Expect(rt.cidrsForClass(routetable.RouteClassIPAMBlockDropVXLAN, routetable.InterfaceNone)).To(
				ConsistOf("10.0.1.0/26"))
			Expect(rt.cidrsForClass(routetable.RouteClassIPAMBlockDropNoEncap, routetable.InterfaceNone)).To(
				ConsistOf("10.0.3.0/26"))
		})
	})

	Describe("parent interface address updates", func() {
		var routeMgr *routeManager

		BeforeEach(func() {
			routeMgr = newRouteManager(
				rt,
				routetable.RouteClassVXLANTunnel,
				routetable.RouteClassVXLANSameSubnet,
				proto.IPPoolType_VXLAN,
				dataplanedefs.VXLANIfaceNameV4,
				4,
				1400,
				dpConfig,
				logutils.NewSummarizer("test"),
				dataplane,
			)
		})

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
})
