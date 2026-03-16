// Copyright (c) 2017-2024 Tigera, Inc. All rights reserved.
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

package routetable_test

import (
	"fmt"
	"net"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	mocknetlink "github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	. "github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/routetable/ownershippol"
	"github.com/projectcalico/calico/felix/testutils"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
)

const routePriorityForTest int = 48931

// routeKeyStr builds a mock dataplane route key string that includes table, CIDR, and priority.
func routeKeyStr(table int, cidr string, priority int) string {
	return fmt.Sprintf("%d-%s-%d", table, cidr, priority)
}

// mainRouteKey builds a route key string for the main routing table with the standard test priority.
func mainRouteKey(cidr string) string {
	return routeKeyStr(254, cidr, routePriorityForTest)
}

var (
	FelixRouteProtocol = netlink.RouteProtocol(syscall.RTPROT_BOOT)

	mac1 = testutils.MustParseMAC("00:11:22:33:44:51")
	mac2 = testutils.MustParseMAC("00:11:22:33:44:52")

	ip1  = ip.MustParseCIDROrIP("10.0.0.1/32").ToIPNet()
	ip2  = ip.MustParseCIDROrIP("10.0.0.2/32").ToIPNet()
	ip13 = ip.MustParseCIDROrIP("10.0.1.3/32").ToIPNet()

	defaultOwnershipPolicy = ownershippol.MainTableOwnershipPolicy{
		WorkloadInterfacePrefixes:     []string{"cali"},
		RemoveNonCalicoWorkloadRoutes: true,
		CalicoSpecialInterfaces:       nil,
		AllRouteProtocols:             []netlink.RouteProtocol{FelixRouteProtocol, 80},
		ExclusiveRouteProtocols:       []netlink.RouteProtocol{80},
	}
)

var _ = Describe("RouteTable v6", func() {
	var dataplane *mocknetlink.MockNetlinkDataplane
	var t *mocktime.MockTime
	var rt *RouteTable

	BeforeEach(func() {
		dataplane = mocknetlink.New()
		t = mocktime.New()
		// No grace period set, so invalid routes should be deleted immediately on apply.
		rt = New(
			&defaultOwnershipPolicy,
			6,
			10*time.Second,
			nil,
			FelixRouteProtocol,
			true,
			0,
			logutils.NewSummarizer("test"),
			dataplane,
			WithTimeShim(t),
			WithConntrackShim(dataplane),
			WithNetlinkHandleShim(dataplane.NewMockNetlink),
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	It("should use interface index 1 for no-iface routes", func() {
		rt.RouteUpdate(RouteClassWireguard, InterfaceNone, Target{
			RouteKey: RouteKey{
				CIDR: ip.MustParseCIDROrIP("f00f::/128"),
			},
			Type: TargetTypeThrow,
		})
		err := rt.Apply()
		Expect(err).ToNot(HaveOccurred())
		Expect(dataplane.RouteKeyToRoute[routeKeyStr(254, "f00f::/128", 1024)]).To(Equal(
			netlink.Route{
				Family:    netlink.FAMILY_V6,
				LinkIndex: 1,
				Dst:       mustParseCIDR("f00f::/128"),
				Type:      syscall.RTN_THROW,
				Protocol:  syscall.RTPROT_BOOT,
				Scope:     netlink.SCOPE_UNIVERSE,
				Table:     unix.RT_TABLE_MAIN,
				Priority:  1024,
			},
		))
	})

	It("should not remove the IPv6 link local route", func() {
		// Route that should be left alone
		noopLink := dataplane.AddIface(4, "cali4", true, true)
		noopRoute := netlink.Route{
			Family:    netlink.FAMILY_V6,
			LinkIndex: noopLink.LinkAttrs.Index,
			Dst:       mustParseCIDR("fe80::/64"),
			Type:      syscall.RTN_UNICAST,
			Protocol:  syscall.RTPROT_KERNEL,
			Scope:     netlink.SCOPE_LINK,
			Table:     unix.RT_TABLE_MAIN,
		}
		rt.SetRoutes(RouteClassLocalWorkload, noopLink.LinkAttrs.Name, []Target{{
			RouteKey: RouteKey{
				CIDR:     ip.MustParseCIDROrIP("10.0.0.4/32"),
				Priority: routePriorityForTest,
			},
			DestMAC: mac1,
		}})
		dataplane.AddMockRoute(&noopRoute)

		// Routes that should be deleted.
		deleteLink := dataplane.AddIface(5, "cali5", true, true)
		deleteRoute := netlink.Route{
			LinkIndex: deleteLink.LinkAttrs.Index,
			Dst:       mustParseCIDR("10.0.0.1/32"),
			Type:      syscall.RTN_UNICAST,
			Protocol:  FelixRouteProtocol,
			Scope:     netlink.SCOPE_LINK,
			Table:     unix.RT_TABLE_MAIN,
		}
		dataplane.AddMockRoute(&deleteRoute)
		deleteRoute2 := netlink.Route{
			LinkIndex: deleteLink.LinkAttrs.Index,
			Dst:       mustParseCIDR("10.0.0.2/32"),
			Type:      syscall.RTN_UNICAST,
			Protocol:  FelixRouteProtocol,
			Scope:     netlink.SCOPE_LINK,
			Table:     unix.RT_TABLE_MAIN,
			Priority:  routePriorityForTest,
		}
		dataplane.AddMockRoute(&deleteRoute2)

		err := rt.Apply()
		Expect(err).ToNot(HaveOccurred())
		Expect(dataplane.DeletedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
		Expect(dataplane.UpdatedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
		Expect(dataplane.DeletedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&deleteRoute)))
		Expect(dataplane.DeletedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&deleteRoute2)))
	})

	It("should normalize IPv6 Priority 0 to 1024 in RouteRemove", func() {
		// Add a route with Priority 0 — internally, routeKeyForTarget normalizes this to 1024 for IPv6.
		link := dataplane.AddIface(10, "cali10", true, true)
		rt.OnIfaceStateChanged(link.LinkAttrs.Name, link.LinkAttrs.Index, ifacemonitor.StateUp)

		rt.RouteUpdate(RouteClassLocalWorkload, link.LinkAttrs.Name, Target{
			RouteKey: RouteKey{
				CIDR: ip.MustParseCIDROrIP("fd00::1/128"),
				// Priority 0 — will be normalized to 1024.
			},
			Type: TargetTypeVXLAN,
		})
		err := rt.Apply()
		Expect(err).ToNot(HaveOccurred())
		Expect(dataplane.RouteKeyToRoute).To(HaveKey(routeKeyStr(254, "fd00::1/128", 1024)))

		// Now remove using Priority 0 again — RouteRemove should normalize it to 1024.
		rt.RouteRemove(RouteClassLocalWorkload, link.LinkAttrs.Name, RouteKey{
			CIDR: ip.MustParseCIDROrIP("fd00::1/128"),
			// Priority 0 — should be normalized to 1024 to match the stored route.
		})
		err = rt.Apply()
		Expect(err).ToNot(HaveOccurred())
		Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(routeKeyStr(254, "fd00::1/128", 1024)))
	})
})

var _ = Describe("RouteTable", func() {
	var dataplane *mocknetlink.MockNetlinkDataplane
	var t *mocktime.MockTime
	var rt *RouteTable

	BeforeEach(func() {
		dataplane = mocknetlink.New()
		t = mocktime.New()
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.SetAutoIncrement(11 * time.Second)
		rt = New(
			&defaultOwnershipPolicy,
			4,
			10*time.Second,
			nil,
			FelixRouteProtocol,
			true,
			0,
			logutils.NewSummarizer("test"),
			dataplane,
			WithRouteCleanupGracePeriod(10*time.Second),
			WithStaticARPEntries(true),
			WithTimeShim(t),
			WithConntrackShim(dataplane),
			WithNetlinkHandleShim(dataplane.NewMockNetlink),
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	It("should handle unexpected non-calico interface updates", func() {
		t.SetAutoIncrement(0 * time.Second)
		rt.OnIfaceStateChanged("calx", 11, ifacemonitor.StateUp)
		err := rt.Apply()
		Expect(err).ToNot(HaveOccurred())
	})

	It("should handle unexpected calico interface updates", func() {
		t.SetAutoIncrement(0 * time.Second)
		rt.OnIfaceStateChanged("cali1", 12, ifacemonitor.StateUp)
		rt.QueueResync()
		err := rt.Apply()
		Expect(err).ToNot(HaveOccurred())
		t.IncrementTime(11 * time.Second)
		rt.QueueResync()
		err = rt.Apply()
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("with some interfaces", func() {
		var cali1, cali2, cali3, eth0 *mocknetlink.MockLink
		var gatewayRoute, cali1Route, cali1Route2, cali3Route netlink.Route
		BeforeEach(func() {
			eth0 = dataplane.AddIface(2, "eth0", true, true)
			cali1 = dataplane.AddIface(3, "cali1", true, true)
			cali2 = dataplane.AddIface(4, "cali2", true, true)
			cali3 = dataplane.AddIface(5, "cali3", true, true)
			cali1Route = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     unix.RT_TABLE_MAIN,
				Priority:  routePriorityForTest,
			}
			dataplane.AddMockRoute(&cali1Route)
			cali3Route = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali3.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.3/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     unix.RT_TABLE_MAIN,
				Priority:  routePriorityForTest,
			}
			dataplane.AddMockRoute(&cali3Route)
			gatewayRoute = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: eth0.LinkAttrs.Index,
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Gw:        net.ParseIP("12.0.0.1"),
				Table:     unix.RT_TABLE_MAIN,
			}
			dataplane.AddMockRoute(&gatewayRoute)
		})
		It("should wait for the route cleanup delay", func() {
			t.SetAutoIncrement(0 * time.Second)
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(cali1Route, cali3Route, gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
			t.IncrementTime(11 * time.Second)
			err = rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
		})
		It("should wait for the route cleanup delay when resyncing", func() {
			t.SetAutoIncrement(0 * time.Second)
			rt.QueueResync()
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(cali1Route, cali3Route, gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
			t.IncrementTime(11 * time.Second)
			rt.QueueResync()
			err = rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
		})
		It("should clean up only our routes", func() {
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
		})
		It("should delete only our conntrack entries", func() {
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Eventually(dataplane.GetDeletedConntrackEntries).Should(ConsistOf(
				net.ParseIP("10.0.0.1").To4(),
				net.ParseIP("10.0.0.3").To4(),
			))
		})
		It("Should clear out a source address when source address is not set", func() {
			updateLink := dataplane.AddIface(6, "cali5", true, true)
			updateRoute := netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: updateLink.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.5/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Src:       net.ParseIP("192.168.0.1"),
				Table:     unix.RT_TABLE_MAIN,
				Priority:  routePriorityForTest,
			}
			dataplane.AddMockRoute(&updateRoute)
			rt.SetRoutes(RouteClassLocalWorkload, updateLink.LinkAttrs.Name, []Target{{
				RouteKey: RouteKey{
					CIDR:     ip.MustParseCIDROrIP("10.0.0.5"),
					Priority: routePriorityForTest,
				},
				DestMAC: mac1,
			}})

			fixedRoute := updateRoute
			fixedRoute.Src = nil

			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.UpdatedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&updateRoute)))
			Expect(dataplane.RouteKeyToRoute[mocknetlink.KeyForRoute(&updateRoute)]).To(Equal(fixedRoute))
		})
		Describe("With a device route source address set", func() {
			deviceRouteSource := "192.168.0.1"
			deviceRouteSourceAddress := net.ParseIP(deviceRouteSource).To4()
			// Modify the route table to have the device route source address set
			BeforeEach(func() {
				rt = New(
					&defaultOwnershipPolicy,
					4,
					10*time.Second,
					deviceRouteSourceAddress,
					FelixRouteProtocol,
					true,
					0,
					logutils.NewSummarizer("test"),
					dataplane,
					WithTimeShim(t),
					WithStaticARPEntries(true),
					WithConntrackShim(dataplane),
					WithNetlinkHandleShim(dataplane.NewMockNetlink),
				)
			})
			It("Should delete routes without a source address", func() {
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&cali3Route)))
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&cali1Route)))
			})
			It("Should enable strict mode", func() {
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.StrictEnabled).To(BeTrue())
			})
			It("Should add routes with a source address", func() {
				// Route that needs to be added
				addLink := dataplane.AddIface(6, "cali6", true, true)
				rt.SetRoutes(RouteClassLocalWorkload, addLink.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.6"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				cidr := mustParseCIDR("10.0.0.6/32")
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.6/32")]).To(Equal(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: addLink.LinkAttrs.Index,
					Dst:       cidr,
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Src:       deviceRouteSourceAddress,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
				dataplane.ExpectNeighs(unix.AF_INET, netlink.Neigh{
					Family:       unix.AF_INET,
					LinkIndex:    addLink.LinkAttrs.Index,
					State:        netlink.NUD_PERMANENT,
					Type:         unix.RTN_UNICAST,
					IP:           cidr.IP,
					HardwareAddr: mac1,
				})
			})
			Context("after initial route programming", func() {
				var cidr *net.IPNet
				var linkIndex int
				BeforeEach(func() {
					// Initial route programming...
					addLink := dataplane.AddIface(6, "cali6", true, true)
					linkIndex = addLink.LinkAttrs.Index
					rt.SetRoutes(RouteClassLocalWorkload, addLink.LinkAttrs.Name, []Target{{
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.0.0.6"),
							Priority: routePriorityForTest,
						},
						DestMAC: mac1,
					}})
					err := rt.Apply()
					Expect(err).ToNot(HaveOccurred())
					cidr = mustParseCIDR("10.0.0.6/32")
				})
				It("ARP entry should exist", func() {
					dataplane.ExpectNeighs(unix.AF_INET, netlink.Neigh{
						Family:       unix.AF_INET,
						LinkIndex:    linkIndex,
						State:        netlink.NUD_PERMANENT,
						Type:         unix.RTN_UNICAST,
						IP:           cidr.IP,
						HardwareAddr: mac1,
					})
				})
				It("ARP entry should be reestablished by a resync", func() {
					dataplane.RemoveNeighs(unix.AF_INET, netlink.Neigh{
						Family:       unix.AF_INET,
						LinkIndex:    linkIndex,
						State:        netlink.NUD_PERMANENT,
						Type:         unix.RTN_UNICAST,
						IP:           cidr.IP,
						HardwareAddr: mac1,
					})
					rt.QueueResync()
					err := rt.Apply()
					Expect(err).NotTo(HaveOccurred())
					dataplane.ExpectNeighs(unix.AF_INET, netlink.Neigh{
						Family:       unix.AF_INET,
						LinkIndex:    linkIndex,
						State:        netlink.NUD_PERMANENT,
						Type:         unix.RTN_UNICAST,
						IP:           cidr.IP,
						HardwareAddr: mac1,
					})
				})
			})
			It("Should skip adding an ARP entry if route is deleted via SetRoutes before sync", func() {
				// Route that needs to be added
				link := dataplane.AddIface(6, "cali6", true, true)
				rt.SetRoutes(RouteClassLocalWorkload, link.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.6"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				rt.SetRoutes(RouteClassLocalWorkload, link.LinkAttrs.Name, nil)
				err := rt.Apply()

				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(mainRouteKey("10.0.0.6/32")))
				dataplane.ExpectNeighs(unix.AF_INET)
			})
			It("Should skip adding an ARP entry if route is deleted via RouteRemove before sync", func() {
				// Route that needs to be added
				link := dataplane.AddIface(6, "cali6", true, true)
				cidr := ip.MustParseCIDROrIP("10.0.0.6")
				rt.SetRoutes(RouteClassLocalWorkload, link.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     cidr,
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				rt.RouteRemove(RouteClassLocalWorkload, link.LinkAttrs.Name, RouteKey{CIDR: cidr, Priority: routePriorityForTest})
				err := rt.Apply()

				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(mainRouteKey("10.0.0.6/32")))
				dataplane.ExpectNeighs(unix.AF_INET)
			})
			It("should clean up ifacesToARP when all ARP entries removed via RouteRemove", func() {
				// Set up a workload with an ARP entry and sync it.
				link := dataplane.AddIface(6, "cali6", true, true)
				cidr := ip.MustParseCIDROrIP("10.0.0.6")
				rt.SetRoutes(RouteClassLocalWorkload, link.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     cidr,
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				// Remove the route (and its ARP entry).
				rt.RouteRemove(RouteClassLocalWorkload, link.LinkAttrs.Name, RouteKey{CIDR: cidr, Priority: routePriorityForTest})

				// ifacesToARP should not retain the removed interface.
				Expect(rt.IfacesToARPLen()).To(Equal(0))
			})
			It("should clean up ifacesToARP when routes removed via SetRoutes(nil)", func() {
				// Set up a workload with an ARP entry and sync it.
				link := dataplane.AddIface(6, "cali6", true, true)
				rt.SetRoutes(RouteClassLocalWorkload, link.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.6"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				// Remove all routes for the interface.
				rt.SetRoutes(RouteClassLocalWorkload, link.LinkAttrs.Name, nil)

				// ifacesToARP should not retain the removed interface.
				Expect(rt.IfacesToARPLen()).To(Equal(0))
			})
			It("should not leak ifacesToARP entries after interface churn and resync", func() {
				// Simulate interface churn: add many workloads.
				for i := 0; i < 10; i++ {
					ifName := fmt.Sprintf("cali%d", 10+i)
					dataplane.AddIface(10+i, ifName, true, true)
					rt.SetRoutes(RouteClassLocalWorkload, ifName, []Target{{
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP(fmt.Sprintf("10.0.%d.1", i)),
							Priority: routePriorityForTest,
						},
						DestMAC: mac1,
					}})
				}
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				// Remove all churned workloads.
				for i := 0; i < 10; i++ {
					ifName := fmt.Sprintf("cali%d", 10+i)
					rt.SetRoutes(RouteClassLocalWorkload, ifName, nil)
				}

				// Full resync should rebuild ifacesToARP from permanentARPs
				// without retaining stale entries.
				rt.QueueResync()
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(rt.IfacesToARPLen()).To(Equal(0))
			})
			It("should not accumulate stale ifacesToARP entries across resyncs", func() {
				// Add a workload and sync.
				link := dataplane.AddIface(6, "cali6", true, true)
				_ = link
				rt.SetRoutes(RouteClassLocalWorkload, "cali6", []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.6"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				// Remove the workload and sync.
				rt.SetRoutes(RouteClassLocalWorkload, "cali6", nil)
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				// Full resync should not re-add "cali6" to ifacesToARP.
				rt.QueueResync()
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(rt.IfacesToARPLen()).To(Equal(0))
			})
			It("Should not remove routes with a source address", func() {
				// Route that should be left alone
				noopLink := dataplane.AddIface(6, "cali4", true, true)
				cidr := mustParseCIDR("10.0.0.4/32")
				noopRoute := netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: noopLink.LinkAttrs.Index,
					Dst:       cidr,
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Src:       deviceRouteSourceAddress,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}
				rt.SetRoutes(RouteClassLocalWorkload, noopLink.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.4/32"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				dataplane.AddMockRoute(&noopRoute)

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.DeletedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
				Expect(dataplane.UpdatedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
				dataplane.ExpectNeighs(unix.AF_INET, netlink.Neigh{
					Family:       unix.AF_INET,
					LinkIndex:    noopLink.LinkAttrs.Index,
					State:        netlink.NUD_PERMANENT,
					Type:         unix.RTN_UNICAST,
					IP:           cidr.IP,
					HardwareAddr: mac1,
				})
			})
			It("Should update source addresses from nil to a given source", func() {
				// Route that needs to be updated
				updateLink := dataplane.AddIface(6, "cali5", true, true)
				cidr := mustParseCIDR("10.0.0.5/32")
				updateRoute := netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: updateLink.LinkAttrs.Index,
					Dst:       cidr,
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}
				rt.SetRoutes(RouteClassLocalWorkload, updateLink.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.5"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				dataplane.AddMockRoute(&updateRoute)

				fixedRoute := updateRoute
				fixedRoute.Src = deviceRouteSourceAddress

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.UpdatedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&updateRoute)))
				Expect(dataplane.RouteKeyToRoute[mocknetlink.KeyForRoute(&updateRoute)]).To(Equal(fixedRoute))

				dataplane.ExpectNeighs(unix.AF_INET, netlink.Neigh{
					Family:       unix.AF_INET,
					LinkIndex:    updateLink.LinkAttrs.Index,
					State:        netlink.NUD_PERMANENT,
					Type:         unix.RTN_UNICAST,
					IP:           cidr.IP,
					HardwareAddr: mac1,
				})
			})

			It("Should update source addresses from an old source to a new one", func() {
				// Route that needs to be updated
				updateLink := dataplane.AddIface(6, "cali5", true, true)
				cidr := mustParseCIDR("10.0.0.5/32")
				updateRoute := netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: updateLink.LinkAttrs.Index,
					Dst:       cidr,
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Src:       net.ParseIP("192.168.0.2"),
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}
				rt.SetRoutes(RouteClassLocalWorkload, updateLink.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.5"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				dataplane.AddMockRoute(&updateRoute)

				fixedRoute := updateRoute
				fixedRoute.Src = deviceRouteSourceAddress

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.UpdatedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&updateRoute)))
				Expect(dataplane.RouteKeyToRoute[mocknetlink.KeyForRoute(&updateRoute)]).To(Equal(fixedRoute))

				dataplane.ExpectNeighs(unix.AF_INET, netlink.Neigh{
					Family:       unix.AF_INET,
					LinkIndex:    updateLink.LinkAttrs.Index,
					State:        netlink.NUD_PERMANENT,
					Type:         unix.RTN_UNICAST,
					IP:           cidr.IP,
					HardwareAddr: mac1,
				})
			})

			It("should not delete route with source address if target has the same source", func() {
				noopLink := dataplane.AddIface(7, "cali7", true, true)
				noopRoute := netlink.Route{
					LinkIndex: noopLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.5/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Src:       net.ParseIP("192.168.0.2"),
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}
				rt.SetRoutes(RouteClassLocalWorkload, noopLink.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.5"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
					Src:     ip.FromString("192.168.0.2"),
				}})
				dataplane.AddMockRoute(&noopRoute)
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.DeletedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
				Expect(dataplane.UpdatedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
			})

			It("should delete route with different source address", func() {
				noopLink := dataplane.AddIface(8, "cali8", true, true)
				noopRoute := netlink.Route{
					LinkIndex: noopLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.5/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Src:       net.ParseIP("192.168.0.2"),
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}
				rt.SetRoutes(RouteClassLocalWorkload, noopLink.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.5"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
					Src:     ip.FromString("192.168.0.3"),
				}})
				dataplane.AddMockRoute(&noopRoute)
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				routeKey := mocknetlink.KeyForRoute(&noopRoute)
				Expect(dataplane.UpdatedRouteKeys).To(HaveKey(routeKey))
				Expect(dataplane.RouteKeyToRoute[routeKey].Src).To(Equal(net.ParseIP("192.168.0.3").To4()))
			})

		})

		Describe("With a device route protocol set", func() {
			deviceRouteProtocol := netlink.RouteProtocol(10)
			ownershipPol := defaultOwnershipPolicy
			ownershipPol.AllRouteProtocols = []netlink.RouteProtocol{deviceRouteProtocol}
			ownershipPol.ExclusiveRouteProtocols = []netlink.RouteProtocol{deviceRouteProtocol}
			// Modify the route table to have the device route source address set
			BeforeEach(func() {
				rt = New(
					&ownershipPol,
					4,
					10*time.Second,
					nil,
					deviceRouteProtocol,
					true,
					0,
					logutils.NewSummarizer("test"),
					dataplane,
					WithTimeShim(t),
					WithConntrackShim(dataplane),
					WithNetlinkHandleShim(dataplane.NewMockNetlink),
				)
			})
			It("Should delete routes without a protocol", func() {
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&cali3Route)))
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&cali1Route)))
			})
			It("Should add routes with a protocol", func() {
				// Route that needs to be added
				addLink := dataplane.AddIface(6, "cali6", true, true)
				rt.SetRoutes(RouteClassLocalWorkload, addLink.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.6"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.6/32")]).To(Equal(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: addLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.6/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))

				By("Reading back the route")
				Expect(rt.ReadRoutesFromKernel(addLink.LinkAttrs.Name)).To(ConsistOf(
					Target{
						Type: TargetTypeLinkLocalUnicast,
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.0.0.6"),
							Priority: routePriorityForTest,
						},
						Protocol: deviceRouteProtocol,
					}),
				)
			})
			It("Should add multi-path routes with interface already up", func() {
				// Route that needs to be added
				addLink := dataplane.AddIface(6, "cali6", true, true)
				addLink2 := dataplane.AddIface(7, "cali7", true, true)
				rt.SetRoutes(RouteClassLocalWorkload, InterfaceNone, []Target{{
					Type: TargetTypeVXLAN,
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.0/24"),
						Priority: routePriorityForTest,
					},
					MultiPath: []NextHop{
						{
							IfaceName: addLink.LinkAttrs.Name,
							Gw:        ip.FromString("10.0.0.6"),
						},
						{
							IfaceName: addLink2.LinkAttrs.Name,
							Gw:        ip.FromString("10.0.0.7"),
						},
					},
				}})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.0/24")]).To(Equal(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: 0,
					Dst:       mustParseCIDR("10.0.0.0/24"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_UNIVERSE,
					Table:     unix.RT_TABLE_MAIN,
					Flags:     syscall.RTNH_F_ONLINK,
					MultiPath: []*netlink.NexthopInfo{
						{
							LinkIndex: addLink.LinkAttrs.Index,
							Gw:        net.ParseIP("10.0.0.6").To4(),
							Flags:     syscall.RTNH_F_ONLINK,
						},
						{
							LinkIndex: addLink2.LinkAttrs.Index,
							Gw:        net.ParseIP("10.0.0.7").To4(),
							Flags:     syscall.RTNH_F_ONLINK,
						},
					},
					Priority: routePriorityForTest,
				}))

				By("Reading back the route")
				Expect(rt.ReadRoutesFromKernel(InterfaceNone)).To(ConsistOf(
					Target{
						Type: TargetTypeVXLAN,
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.0.0.0/24"),
							Priority: routePriorityForTest,
						},
						Protocol: deviceRouteProtocol,
						MultiPath: []NextHop{
							{
								IfaceName: addLink.LinkAttrs.Name,
								Gw:        ip.FromString("10.0.0.6"),
							},
							{
								IfaceName: addLink2.LinkAttrs.Name,
								Gw:        ip.FromString("10.0.0.7"),
							},
						},
					}))
			})
			It("Should add/remove multi-path routes when interface goes up/down", func() {
				// Route that needs to be added
				By("Creating interfaces")
				addLink := dataplane.AddIface(6, "cali6", false, false)
				addLink2 := dataplane.AddIface(7, "cali7", false, false)

				By("Setting routes")
				rt.SetRoutes(RouteClassLocalWorkload, InterfaceNone, []Target{{
					Type: TargetTypeVXLAN,
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.0/24"),
						Priority: routePriorityForTest,
					},
					MultiPath: []NextHop{
						{
							IfaceName: addLink.LinkAttrs.Name,
							Gw:        ip.FromString("10.0.0.6"),
						},
						{
							IfaceName: addLink2.LinkAttrs.Name,
							Gw:        ip.FromString("10.0.0.7"),
						},
					},
				}})

				By("Apply")
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.0/24")]).To(BeZero())

				By("Bringing interfaces up")
				dataplane.SetIface("cali6", true, true)
				dataplane.SetIface("cali7", true, true)
				rt.OnIfaceStateChanged("cali6", addLink.LinkAttrs.Index, ifacemonitor.StateUp)
				rt.OnIfaceStateChanged("cali7", addLink2.LinkAttrs.Index, ifacemonitor.StateUp)

				By("Apply")
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				expectedRoute := netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: 0,
					Dst:       mustParseCIDR("10.0.0.0/24"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_UNIVERSE,
					Table:     unix.RT_TABLE_MAIN,
					Flags:     syscall.RTNH_F_ONLINK,
					MultiPath: []*netlink.NexthopInfo{
						{
							LinkIndex: addLink.LinkAttrs.Index,
							Gw:        net.ParseIP("10.0.0.6").To4(),
							Flags:     syscall.RTNH_F_ONLINK,
						},
						{
							LinkIndex: addLink2.LinkAttrs.Index,
							Gw:        net.ParseIP("10.0.0.7").To4(),
							Flags:     syscall.RTNH_F_ONLINK,
						},
					},
					Priority: routePriorityForTest,
				}
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.0/24")]).To(Equal(expectedRoute))

				By("Bringing one interface down")
				dataplane.SetIface("cali6", false, false)
				rt.OnIfaceStateChanged("cali6", addLink.LinkAttrs.Index, ifacemonitor.StateDown)

				By("Apply")
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				// It's ok to have one interface down on a multi-path route.
				// Kernel keeps the route in place.
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.0/24")]).To(Equal(expectedRoute),
					"Route should not be removed when only one interface is down")

				By("Bringing other interface down")
				dataplane.SetIface("cali7", false, false)
				rt.OnIfaceStateChanged("cali7", addLink2.LinkAttrs.Index, ifacemonitor.StateDown)

				By("Apply")
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				// The kernel will remove the route once all interfaces go down
				// so we do the same to stay in sync.
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.0/24")]).To(BeZero(),
					"Route should be removed when all interfaces are down")
			})
			It("Should add/remove multi-path routes when interface creted/deleted", func() {
				By("Setting routes")
				rt.SetRoutes(RouteClassLocalWorkload, InterfaceNone, []Target{{
					Type: TargetTypeVXLAN,
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.0/24"),
						Priority: routePriorityForTest,
					},
					MultiPath: []NextHop{
						{
							IfaceName: "cali6",
							Gw:        ip.FromString("10.0.0.6"),
						},
						{
							IfaceName: "cali7",
							Gw:        ip.FromString("10.0.0.7"),
						},
					},
				}})

				By("Apply")
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.0/24")]).To(BeZero())

				By("Creating one interface")
				addLink := dataplane.AddIface(6, "cali6", false, false)
				dataplane.SetIface("cali6", true, true)
				rt.OnIfaceStateChanged("cali6", addLink.LinkAttrs.Index, ifacemonitor.StateUp)

				By("Apply")
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.0/24")]).To(BeZero())

				By("Creating other interface")
				addLink2 := dataplane.AddIface(7, "cali7", false, false)
				dataplane.SetIface("cali7", true, true)
				rt.OnIfaceStateChanged("cali7", addLink2.LinkAttrs.Index, ifacemonitor.StateUp)

				By("Apply")
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				expectedRoute := netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: 0,
					Dst:       mustParseCIDR("10.0.0.0/24"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_UNIVERSE,
					Table:     unix.RT_TABLE_MAIN,
					Flags:     syscall.RTNH_F_ONLINK,
					MultiPath: []*netlink.NexthopInfo{
						{
							LinkIndex: addLink.LinkAttrs.Index,
							Gw:        net.ParseIP("10.0.0.6").To4(),
							Flags:     syscall.RTNH_F_ONLINK,
						},
						{
							LinkIndex: addLink2.LinkAttrs.Index,
							Gw:        net.ParseIP("10.0.0.7").To4(),
							Flags:     syscall.RTNH_F_ONLINK,
						},
					},
					Priority: routePriorityForTest,
				}
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.0/24")]).To(Equal(expectedRoute))

				By("Deleting one interface")
				dataplane.DelIface("cali6")
				rt.OnIfaceStateChanged("cali6", addLink.LinkAttrs.Index, ifacemonitor.StateNotPresent)

				By("Apply")
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				// Can't have a route with a deleted interface.  The ifindex becomes
				// invalid.
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.0/24")]).To(BeZero(),
					"Route should be removed when one interface deleted")
			})
			It("Should add multiple routes with a protocol", func() {
				// Route that needs to be added
				addLink := dataplane.AddIface(6, "cali6", true, true)
				rt.SetRoutes(RouteClassLocalWorkload, addLink.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.6"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}, {
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.7"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.6/32")]).To(Equal(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: addLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.6/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.7/32")]).To(Equal(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: addLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.7/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
			})
			It("Should add multiple routes with a protocol after persistent failures", func() {
				// Route that needs to be added
				addLink := dataplane.AddIface(6, "cali6", true, true)
				rt.SetRoutes(RouteClassLocalWorkload, addLink.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.6"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}, {
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.7"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				// Persist failures, this will apply the deltas to the cache but will be out of sync with the dataplane.
				dataplane.FailuresToSimulate = mocknetlink.FailNextRouteAdd | mocknetlink.FailNextRouteReplace
				dataplane.PersistFailures = true
				err := rt.Apply()
				Expect(err).To(HaveOccurred())

				// Retry - this will now succeed and fix everything.
				dataplane.FailuresToSimulate = mocknetlink.FailNone
				dataplane.PersistFailures = false
				err = rt.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.6/32")]).To(Equal(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: addLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.6/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
				Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.7/32")]).To(Equal(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: addLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.7/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
			})
			It("Should not remove routes with a protocol", func() {
				// Route that should be left alone
				noopLink := dataplane.AddIface(6, "cali4", true, true)
				noopRoute := netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: noopLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.4/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}
				rt.SetRoutes(RouteClassLocalWorkload, noopLink.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.4/32"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				dataplane.AddMockRoute(&noopRoute)

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.DeletedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
				Expect(dataplane.UpdatedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
			})
			It("Should update protocol from nil to a given protocol", func() {
				// Route that needs to be updated
				updateLink := dataplane.AddIface(6, "cali5", true, true)
				updateRoute := netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: updateLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.5/32"),
					Type:      syscall.RTN_UNICAST,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}
				rt.SetRoutes(RouteClassLocalWorkload, updateLink.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.5"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				dataplane.AddMockRoute(&updateRoute)

				fixedRoute := updateRoute
				fixedRoute.Protocol = deviceRouteProtocol

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.UpdatedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&updateRoute)))
				Expect(dataplane.RouteKeyToRoute[mocknetlink.KeyForRoute(&updateRoute)]).To(Equal(fixedRoute))
			})

			It("Should update protocol from an old protocol to a new one", func() {
				// Route that needs to be updated
				updateLink := dataplane.AddIface(6, "cali5", true, true)
				updateRoute := netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: updateLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.5/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  64,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}
				rt.SetRoutes(RouteClassLocalWorkload, updateLink.LinkAttrs.Name, []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.5"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				dataplane.AddMockRoute(&updateRoute)

				fixedRoute := updateRoute
				fixedRoute.Protocol = deviceRouteProtocol

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.UpdatedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&updateRoute)))
				Expect(dataplane.RouteKeyToRoute[mocknetlink.KeyForRoute(&updateRoute)]).To(Equal(fixedRoute))
			})
		})

		Describe("with a slow conntrack deletion", func() {
			const delay = 300 * time.Millisecond
			BeforeEach(func() {
				dataplane.ConntrackSleep = delay
			})
			It("should block a route add until conntrack finished", func() {
				// Initial apply starts a background thread to delete
				// 10.0.0.1 and 10.0.0.3.
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				// We try to add 10.0.0.1 back in.
				rt.SetRoutes(RouteClassLocalWorkload, "cali1", []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				start := time.Now()
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(time.Since(start)).To(BeNumerically(">=", delay*9/10))
			})
			It("should not block an unrelated route add ", func() {
				// Initial apply starts a background thread to delete
				// 10.0.0.1 and 10.0.0.3.
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				// We try to add 10.0.0.10, which hasn't been seen before.
				rt.SetRoutes(RouteClassLocalWorkload, "cali1", []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.10/32"),
						Priority: routePriorityForTest,
					},
					DestMAC: mac1,
				}})
				start := time.Now()
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(time.Since(start)).To(BeNumerically("<", delay/2))
			})
		})

		Describe("with a persistent failure to connect", func() {
			BeforeEach(func() {
				dataplane.PersistentlyFailToConnect = true
			})

			It("should panic after all its retries are exhausted", func() {
				Expect(rt.Apply()).To(Equal(ErrConnectFailed))
				Expect(func() { _ = rt.Apply() }).To(Panic())
			})
		})

		Describe("after syncing, after adding a route and failing the update twice", func() {
			JustBeforeEach(func() {
				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())

				dataplane.FailuresToSimulate = mocknetlink.FailNextRouteAdd | mocknetlink.FailNextRouteReplace
				dataplane.PersistFailures = true
				rt.RouteUpdate(RouteClassLocalWorkload, "cali3", Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.20.30.40"),
						Priority: routePriorityForTest,
					},
				})
				err = rt.Apply()
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(ErrUpdateFailed))

				dataplane.FailuresToSimulate = 0
				dataplane.PersistFailures = false
			})

			It("has not programmed the route", func() {
				Expect(dataplane.RouteKeyToRoute).NotTo(ContainElement(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
			})

			It("resolves on the next apply", func() {
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
			})
		})

		Describe("after adding two routes to cali3", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(RouteClassLocalWorkload, "cali3", Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.20.30.40"),
						Priority: routePriorityForTest,
					},
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				rt.RouteUpdate(RouteClassLocalWorkload, "cali3", Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.20.0/24"),
						Priority: routePriorityForTest,
					},
				})
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should have two routes for cali3", func() {
				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.20.0/24"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
			})

			It("should make no dataplane updates when deleting, creating and updating back to the same target before the next apply", func() {
				rt.RouteRemove(RouteClassLocalWorkload, "cali3", RouteKey{
					CIDR:     ip.MustParseCIDROrIP("10.0.20.0/24"),
					Priority: routePriorityForTest,
				})
				rt.RouteUpdate(RouteClassLocalWorkload, "cali3", Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.20.0/24"),
						Priority: routePriorityForTest,
					},
					GW: ip.FromString("1.2.3.4"),
				})
				rt.RouteUpdate(RouteClassLocalWorkload, "cali3", Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.20.0/24"),
						Priority: routePriorityForTest,
					},
				})
				dataplane.ResetDeltas()

				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(dataplane.AddedRouteKeys).To(BeEmpty())
				Expect(dataplane.DeletedRouteKeys).To(BeEmpty())
				Expect(dataplane.UpdatedRouteKeys).To(BeEmpty())

				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.20.0/24"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
			})

			It("should make no dataplane updates when deleting and then setting back to the same target before the next apply", func() {
				rt.RouteRemove(RouteClassLocalWorkload, "cali3", RouteKey{
					CIDR:     ip.MustParseCIDROrIP("10.0.20.0/24"),
					Priority: routePriorityForTest,
				})
				rt.SetRoutes(RouteClassLocalWorkload, "cali3", []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.20.0/24"),
						Priority: routePriorityForTest,
					},
				}, {
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.20.30.40"),
						Priority: routePriorityForTest,
					},
				}})

				dataplane.ResetDeltas()

				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(dataplane.AddedRouteKeys).To(BeEmpty())
				Expect(dataplane.DeletedRouteKeys).To(BeEmpty())
				Expect(dataplane.UpdatedRouteKeys).To(BeEmpty())

				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.20.0/24"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  routePriorityForTest,
				}))
			})
		})

		Describe("delete interface", func() {
			BeforeEach(func() {
				rt.SetRoutes(RouteClassLocalWorkload, "cali1", []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
						Priority: routePriorityForTest,
					},
				}})
				rt.SetRoutes(RouteClassLocalWorkload, "cali3", []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.3/32"),
						Priority: routePriorityForTest,
					},
				}})
				// Apply the changes.
				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())

				// Modify route and delete interface
				rt.SetRoutes(RouteClassLocalWorkload, "cali3", nil)
				delete(dataplane.NameToLink, "cali3")
			})
			It("should still get conntrack deletion invocation during resync", func() {
				rt.QueueResync()
				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())
				Eventually(dataplane.GetDeletedConntrackEntries).Should(Equal([]net.IP{net.ParseIP("10.0.0.3").To4()}))
			})
			It("should still get conntrack deletion invocation during apply", func() {
				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())
				Eventually(dataplane.GetDeletedConntrackEntries).Should(Equal([]net.IP{net.ParseIP("10.0.0.3").To4()}))
			})
		})

		// We do the following tests in different failure (and non-failure) scenarios.  In
		// each case, we make the failure transient so that only the first Apply() should
		// fail.  Then, at most, the second call to Apply() should succeed.
		for _, testFailFlags := range mocknetlink.RoutetableFailureScenarios {
			desc := fmt.Sprintf("with some routes added and failures: %v", testFailFlags)
			Describe(desc, func() {
				BeforeEach(func() {
					rt.SetRoutes(RouteClassLocalWorkload, "cali1", []Target{{
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
							Priority: routePriorityForTest,
						},
						DestMAC: mac1,
					}})
					rt.SetRoutes(RouteClassLocalWorkload, "cali2", []Target{{
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.0.0.2/32"),
							Priority: routePriorityForTest,
						},
						DestMAC: mac2,
					}})
					rt.SetRoutes(RouteClassLocalWorkload, "cali3", []Target{{
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.0.1.3/32"),
							Priority: routePriorityForTest,
						},
					}})
					dataplane.FailuresToSimulate = testFailFlags
				})
				JustBeforeEach(func() {
					maxTries := 1
					if testFailFlags != mocknetlink.FailNone {
						maxTries = 3
					}
					for try := 0; try < maxTries; try++ {
						By("Apply")
						rt.OnIfaceStateChanged("cali1", cali1.LinkAttrs.Index, ifacemonitor.StateUp)
						err := rt.Apply()
						if err != nil {
							continue
						}
						if testFailFlags == mocknetlink.FailNextLinkByName ||
							testFailFlags == mocknetlink.FailNextLinkByNameNotFound {
							// Need >1 loop to hit these cases because, on the first try,
							// we go through the full resync, which doesn't use LinkByName.
							continue
						}
						break
					}
				})
				if testFailFlags == mocknetlink.FailNextRouteAdd {
					// RouteAdd is no longer used...
					It("should not consume the error", func() {
						// Check that all the failures we simulated were hit.
						Expect(dataplane.FailuresToSimulate).To(Equal(testFailFlags),
							"Error was consumed, does test need updating?")
					})
					return
				}
				It("should have consumed all failures", func() {
					// Check that all the failures we simulated were hit.
					Expect(dataplane.FailuresToSimulate).To(Equal(mocknetlink.FailNone))
				})
				// If we return "not found" then the route gets cleaned up, because conflict
				// resolution determines that no routes are eligible for programming.
				if testFailFlags != mocknetlink.FailNextLinkByNameNotFound {
					It("should keep correct route", func() {
						Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.1/32")]).To(Equal(netlink.Route{
							Family:    unix.AF_INET,
							LinkIndex: cali1.LinkAttrs.Index,
							Dst:       &ip1,
							Type:      syscall.RTN_UNICAST,
							Protocol:  FelixRouteProtocol,
							Scope:     netlink.SCOPE_LINK,
							Table:     unix.RT_TABLE_MAIN,
							Priority:  routePriorityForTest,
						}))
						Expect(dataplane.AddedRouteKeys.Contains(mainRouteKey("10.0.0.1/32"))).To(BeFalse())
					})
				}
				It("should add new route", func() {
					Expect(dataplane.RouteKeyToRoute).To(HaveKey(mainRouteKey("10.0.0.2/32")))
					Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.0.2/32")]).To(Equal(netlink.Route{
						Family:    unix.AF_INET,
						LinkIndex: cali2.LinkAttrs.Index,
						Dst:       &ip2,
						Type:      syscall.RTN_UNICAST,
						Protocol:  FelixRouteProtocol,
						Scope:     netlink.SCOPE_LINK,
						Table:     unix.RT_TABLE_MAIN,
						Priority:  routePriorityForTest,
					}))
				})
				It("should update changed route", func() {
					Expect(dataplane.RouteKeyToRoute).To(HaveKey(mainRouteKey("10.0.1.3/32")))
					Expect(dataplane.RouteKeyToRoute[mainRouteKey("10.0.1.3/32")]).To(Equal(netlink.Route{
						Family:    unix.AF_INET,
						LinkIndex: cali3.LinkAttrs.Index,
						Dst:       &ip13,
						Type:      syscall.RTN_UNICAST,
						Protocol:  FelixRouteProtocol,
						Scope:     netlink.SCOPE_LINK,
						Table:     unix.RT_TABLE_MAIN,
						Priority:  routePriorityForTest,
					}))
					Expect(dataplane.DeletedRouteKeys.Contains(mainRouteKey("10.0.0.3/32"))).To(BeTrue())
					Eventually(dataplane.GetDeletedConntrackEntries).Should(ContainElement(net.ParseIP("10.0.0.3").To4()))
				})
				It("should have expected number of routes at the end", func() {
					Expect(len(dataplane.RouteKeyToRoute)).To(Equal(4),
						fmt.Sprintf("Wrong number of routes %v: %v",
							len(dataplane.RouteKeyToRoute),
							dataplane.RouteKeyToRoute))
				})
				if testFailFlags&(mocknetlink.FailNextSetSocketTimeout|
					mocknetlink.FailNextSetStrict|
					mocknetlink.FailNextNewNetlink|
					mocknetlink.FailNextLinkByName|
					mocknetlink.FailNextLinkList|
					mocknetlink.FailNextLinkListWrappedEINTR| // Normally would be retried by the RealNetlink shim.
					mocknetlink.FailNextRouteReplace|
					mocknetlink.FailNextRouteDel|
					mocknetlink.FailNextNeighSet|
					mocknetlink.FailNextRouteList) != 0 {
					It("should reconnect to netlink", func() {
						Expect(dataplane.NumNewNetlinkCalls).To(Equal(2))
					})
				} else {
					It("should not reconnect to netlink", func() {
						Expect(dataplane.NumNewNetlinkCalls).To(Equal(1))
					})
				}

				Describe("after an external route addition with route removal enabled", func() {
					JustBeforeEach(func() {
						cali1Route2 = netlink.Route{
							Family:    unix.AF_INET,
							LinkIndex: cali1.LinkAttrs.Index,
							Dst:       mustParseCIDR("10.0.0.22/32"),
							Type:      syscall.RTN_UNICAST,
							Scope:     netlink.SCOPE_LINK,
							Table:     unix.RT_TABLE_MAIN,
						}
						dataplane.AddMockRoute(&cali1Route2)
						err := rt.Apply()
						Expect(err).ToNot(HaveOccurred())
					})

					It("shouldn't spot the externally added route until a full resync", func() {
						Expect(dataplane.RouteKeyToRoute).To(HaveLen(5))
						Expect(dataplane.RouteKeyToRoute).To(ContainElement(cali1Route2))
					})
					It("after a QueueResync() should remove the route", func() {
						rt.QueueResync()
						err := rt.Apply()
						Expect(err).ToNot(HaveOccurred())
						Expect(dataplane.RouteKeyToRoute).To(HaveLen(4))
						Expect(dataplane.RouteKeyToRoute).NotTo(ContainElement(cali1Route2))
					})
				})

				Describe("after an external route remove with route removal disabled", func() {
					JustBeforeEach(func() {
						dataplane.RemoveMockRoute(&cali1Route)
						err := rt.Apply()
						Expect(err).ToNot(HaveOccurred())
					})

					It("shouldn't spot the externally deleted route until a full resync", func() {
						Expect(dataplane.RouteKeyToRoute).To(HaveLen(3))
						Expect(dataplane.RouteKeyToRoute).NotTo(ContainElement(cali1Route))
					})
					It("after a QueueResync() should add the route", func() {
						rt.QueueResync()
						err := rt.Apply()
						Expect(err).ToNot(HaveOccurred())
						Expect(dataplane.RouteKeyToRoute).To(HaveLen(4))
						Expect(dataplane.RouteKeyToRoute).To(ContainElement(cali1Route))
					})
				})
			})
		}
	})

	Describe("with a down interface", func() {
		var cali1 *mocknetlink.MockLink
		var cali1Route netlink.Route
		BeforeEach(func() {
			cali1 = dataplane.AddIface(2, "cali1", false, false)
			cali1Route = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     unix.RT_TABLE_MAIN,
			}
			dataplane.AddMockRoute(&cali1Route)
		})
		It("with no failures, it should still try to clean up the route", func() {
			err := rt.Apply()
			Expect(err).To(BeNil())
			Expect(dataplane.RouteKeyToRoute).To(BeEmpty())
		})
		for _, failure := range []mocknetlink.FailFlags{
			mocknetlink.FailNextLinkByName,
			mocknetlink.FailNextRouteDel,
			mocknetlink.FailNextRouteList,
			mocknetlink.FailNextRouteListEINTR,
			mocknetlink.FailNextRouteListWrappedEINTR,
		} {
			It(fmt.Sprintf("with a %v failure it should ignore Down updates", failure), func() {
				// First Apply() with a failure.
				dataplane.FailuresToSimulate = failure
				_ = rt.Apply()

				// Fire in the update.
				rt.OnIfaceStateChanged("cali1", 11, ifacemonitor.StateDown)
				// Try another Apply(), the interface shouldn't be marked dirty
				// so nothing should happen.
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute).To(BeEmpty())
			})
			It(fmt.Sprintf("with a %v failure, then an interface kick, it should sync", failure), func() {
				dataplane.FailuresToSimulate = failure
				_ = rt.Apply()

				// Set interface up
				rt.OnIfaceStateChanged("cali1", cali1.LinkAttrs.Index, ifacemonitor.StateUp)
				dataplane.SetIface("cali1", true, true)

				// Now, the apply should work.
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute).To(BeEmpty())
			})
		}
	})

	Describe("with an interface that disappears", func() {
		BeforeEach(func() {
			// Do initial apply so that we can trigger a per-interface sync below.
			err := rt.Apply()
			Expect(err).NotTo(HaveOccurred())
			// Add an interface so that the route table tries to list the routes associated with it.
			dataplane.AddIface(2, "cali1", true, true)
			// But trigger the interface to disappear just before the list call.  This will trigger
			// a list operation with no interface, resulting in an ENODEV.
			dataplane.DeleteInterfaceAfterLinkByName = true
		})
		It("it should suppress the ENODEV error", func() {
			// Trigger a per-interface sync.
			rt.OnIfaceStateChanged("cali1", 2, ifacemonitor.StateUp)
			rt.RouteUpdate(RouteClassLocalWorkload, "cali1", Target{
				RouteKey: RouteKey{
					CIDR:     ip.MustParseCIDROrIP("10.0.20.0/24"),
					Priority: routePriorityForTest,
				},
			})
			err := rt.Apply()
			Expect(err).NotTo(HaveOccurred())
			// Check that we really hit the case we intended to hit.
			Expect(dataplane.HitRouteListFilteredNoDev).To(BeTrue(),
				"RouteListFiltered wasn't called with missing device?  Perhaps test needs updating.")
		})
	})
})

var _ = Describe("RouteTable with multiple priorities", func() {
	var dataplane *mocknetlink.MockNetlinkDataplane
	var t *mocktime.MockTime
	var rt *RouteTable

	const (
		lowPriority  = 100
		highPriority = 200
	)

	BeforeEach(func() {
		dataplane = mocknetlink.New()
		t = mocktime.New()
		t.SetAutoIncrement(11 * time.Second)
		rt = New(
			&defaultOwnershipPolicy,
			4,
			10*time.Second,
			nil,
			FelixRouteProtocol,
			true,
			0,
			logutils.NewSummarizer("test"),
			dataplane,
			WithRouteCleanupGracePeriod(10*time.Second),
			WithTimeShim(t),
			WithConntrackShim(dataplane),
			WithNetlinkHandleShim(dataplane.NewMockNetlink),
		)
	})

	Describe("with an interface", func() {
		var cali1 *mocknetlink.MockLink
		BeforeEach(func() {
			cali1 = dataplane.AddIface(3, "cali1", true, true)
		})

		It("should program two routes with the same CIDR but different priorities", func() {
			rt.SetRoutes(RouteClassLocalWorkload, "cali1", []Target{
				{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
						Priority: lowPriority,
					},
				},
				{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
						Priority: highPriority,
					},
				},
			})
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())

			lowKey := routeKeyStr(254, "10.0.0.1/32", lowPriority)
			highKey := routeKeyStr(254, "10.0.0.1/32", highPriority)

			Expect(dataplane.RouteKeyToRoute).To(HaveKey(lowKey))
			Expect(dataplane.RouteKeyToRoute).To(HaveKey(highKey))
			Expect(dataplane.RouteKeyToRoute[lowKey]).To(Equal(netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     unix.RT_TABLE_MAIN,
				Priority:  lowPriority,
			}))
			Expect(dataplane.RouteKeyToRoute[highKey]).To(Equal(netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     unix.RT_TABLE_MAIN,
				Priority:  highPriority,
			}))
		})

		It("should add two routes with different priorities via RouteUpdate", func() {
			rt.RouteUpdate(RouteClassLocalWorkload, "cali1", Target{
				RouteKey: RouteKey{
					CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
					Priority: lowPriority,
				},
			})
			rt.RouteUpdate(RouteClassLocalWorkload, "cali1", Target{
				RouteKey: RouteKey{
					CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
					Priority: highPriority,
				},
			})
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())

			Expect(dataplane.RouteKeyToRoute).To(HaveKey(routeKeyStr(254, "10.0.0.1/32", lowPriority)))
			Expect(dataplane.RouteKeyToRoute).To(HaveKey(routeKeyStr(254, "10.0.0.1/32", highPriority)))
		})

		Context("after programming two routes with different priorities", func() {
			BeforeEach(func() {
				rt.SetRoutes(RouteClassLocalWorkload, "cali1", []Target{
					{
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
							Priority: lowPriority,
						},
					},
					{
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
							Priority: highPriority,
						},
					},
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should remove only the low-priority route when it is removed", func() {
				rt.RouteRemove(RouteClassLocalWorkload, "cali1", RouteKey{
					CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
					Priority: lowPriority,
				})
				dataplane.ResetDeltas()
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				lowKey := routeKeyStr(254, "10.0.0.1/32", lowPriority)
				highKey := routeKeyStr(254, "10.0.0.1/32", highPriority)

				Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(lowKey))
				Expect(dataplane.RouteKeyToRoute).To(HaveKey(highKey))
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(lowKey))
			})

			It("should remove only the high-priority route when it is removed", func() {
				rt.RouteRemove(RouteClassLocalWorkload, "cali1", RouteKey{
					CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
					Priority: highPriority,
				})
				dataplane.ResetDeltas()
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				lowKey := routeKeyStr(254, "10.0.0.1/32", lowPriority)
				highKey := routeKeyStr(254, "10.0.0.1/32", highPriority)

				Expect(dataplane.RouteKeyToRoute).To(HaveKey(lowKey))
				Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(highKey))
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(highKey))
			})

			It("should remove both routes when SetRoutes is called with nil", func() {
				rt.SetRoutes(RouteClassLocalWorkload, "cali1", nil)
				dataplane.ResetDeltas()
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				lowKey := routeKeyStr(254, "10.0.0.1/32", lowPriority)
				highKey := routeKeyStr(254, "10.0.0.1/32", highPriority)

				Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(lowKey))
				Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(highKey))
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(lowKey))
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(highKey))
			})

			It("should replace both routes when SetRoutes is called with new targets at same priorities", func() {
				rt.SetRoutes(RouteClassLocalWorkload, "cali1", []Target{
					{
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
							Priority: lowPriority,
						},
						GW: ip.FromString("10.0.0.254"),
					},
					{
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
							Priority: highPriority,
						},
						GW: ip.FromString("10.0.0.253"),
					},
				})
				dataplane.ResetDeltas()
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				lowKey := routeKeyStr(254, "10.0.0.1/32", lowPriority)
				highKey := routeKeyStr(254, "10.0.0.1/32", highPriority)

				Expect(dataplane.RouteKeyToRoute[lowKey].Gw).To(Equal(net.ParseIP("10.0.0.254").To4()))
				Expect(dataplane.RouteKeyToRoute[highKey].Gw).To(Equal(net.ParseIP("10.0.0.253").To4()))
			})

			It("should handle removing one priority and keeping the other via SetRoutes", func() {
				rt.SetRoutes(RouteClassLocalWorkload, "cali1", []Target{
					{
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
							Priority: highPriority,
						},
					},
				})
				dataplane.ResetDeltas()
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				lowKey := routeKeyStr(254, "10.0.0.1/32", lowPriority)
				highKey := routeKeyStr(254, "10.0.0.1/32", highPriority)

				Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(lowKey))
				Expect(dataplane.RouteKeyToRoute).To(HaveKey(highKey))
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(lowKey))
			})

			It("should survive a resync and keep both routes", func() {
				rt.QueueResync()
				dataplane.ResetDeltas()
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				lowKey := routeKeyStr(254, "10.0.0.1/32", lowPriority)
				highKey := routeKeyStr(254, "10.0.0.1/32", highPriority)

				Expect(dataplane.RouteKeyToRoute).To(HaveKey(lowKey))
				Expect(dataplane.RouteKeyToRoute).To(HaveKey(highKey))
				// No changes should be needed.
				Expect(dataplane.AddedRouteKeys).To(BeEmpty())
				Expect(dataplane.DeletedRouteKeys).To(BeEmpty())
			})

			It("should add a third priority for the same CIDR", func() {
				const thirdPriority = 300
				rt.RouteUpdate(RouteClassLocalWorkload, "cali1", Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
						Priority: thirdPriority,
					},
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(dataplane.RouteKeyToRoute).To(HaveKey(routeKeyStr(254, "10.0.0.1/32", lowPriority)))
				Expect(dataplane.RouteKeyToRoute).To(HaveKey(routeKeyStr(254, "10.0.0.1/32", highPriority)))
				Expect(dataplane.RouteKeyToRoute).To(HaveKey(routeKeyStr(254, "10.0.0.1/32", thirdPriority)))
			})
		})

		It("should clean up stale kernel routes at different priorities during resync", func() {
			// Pre-populate the kernel with two routes at different priorities
			// that we don't know about.
			staleRouteLow := netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     unix.RT_TABLE_MAIN,
				Priority:  lowPriority,
			}
			staleRouteHigh := netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     unix.RT_TABLE_MAIN,
				Priority:  highPriority,
			}
			dataplane.AddMockRoute(&staleRouteLow)
			dataplane.AddMockRoute(&staleRouteHigh)

			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())

			// Both stale routes should be deleted.
			lowKey := routeKeyStr(254, "10.0.0.1/32", lowPriority)
			highKey := routeKeyStr(254, "10.0.0.1/32", highPriority)
			Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(lowKey))
			Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(highKey))
		})

		It("should clean up stale priority and keep desired priority during resync", func() {
			// Pre-populate the kernel with a stale route at one priority.
			staleRoute := netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     unix.RT_TABLE_MAIN,
				Priority:  lowPriority,
			}
			dataplane.AddMockRoute(&staleRoute)

			// Tell the routetable we want a route at a different priority.
			rt.SetRoutes(RouteClassLocalWorkload, "cali1", []Target{{
				RouteKey: RouteKey{
					CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
					Priority: highPriority,
				},
			}})

			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())

			lowKey := routeKeyStr(254, "10.0.0.1/32", lowPriority)
			highKey := routeKeyStr(254, "10.0.0.1/32", highPriority)

			// Stale route should be cleaned up, desired route should be programmed.
			Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(lowKey))
			Expect(dataplane.RouteKeyToRoute).To(HaveKey(highKey))
		})

		Describe("live migration: source host", func() {
			// Simulates the sequence of events when a VM is live-migrated
			// AWAY from this host. Felix manages the local workload route
			// on cali1; BIRD programs a remote route on eth0 that Felix
			// should not touch.

			const (
				normalPriority   = 200 // Normal routing priority.
				elevatedPriority = 100 // Lower number = higher kernel preference.
				birdProto        = 12  // RTPROT_BIRD
				vmCIDR           = "10.0.0.42/32"
			)

			var eth0 *mocknetlink.MockLink

			BeforeEach(func() {
				eth0 = dataplane.AddIface(10, "eth0", true, true)
			})

			It("should handle the full migration sequence", func() {
				// Step 1: Felix programs a local route for the VM at normal priority.
				rt.SetRoutes(RouteClassLocalWorkload, "cali1", []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP(vmCIDR),
						Priority: normalPriority,
					},
				}})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				felixKey := routeKeyStr(254, vmCIDR, normalPriority)
				Expect(dataplane.RouteKeyToRoute).To(HaveKey(felixKey))

				// Step 2: BIRD programs a remote route at elevated priority via eth0.
				birdRoute := netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: eth0.LinkAttrs.Index,
					Dst:       mustParseCIDR(vmCIDR),
					Type:      syscall.RTN_UNICAST,
					Protocol:  birdProto,
					Scope:     netlink.SCOPE_UNIVERSE,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  elevatedPriority,
				}
				dataplane.AddMockRoute(&birdRoute)
				birdKey := routeKeyStr(254, vmCIDR, elevatedPriority)

				// Resync: Felix should see the BIRD route but leave it alone.
				rt.QueueResync()
				dataplane.ResetDeltas()
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(dataplane.RouteKeyToRoute).To(HaveKey(felixKey))
				Expect(dataplane.RouteKeyToRoute).To(HaveKey(birdKey))
				Expect(dataplane.DeletedRouteKeys).NotTo(HaveKey(birdKey))

				// Step 3: Source cleanup — Felix removes the local route.
				rt.RouteRemove(RouteClassLocalWorkload, "cali1", RouteKey{
					CIDR:     ip.MustParseCIDROrIP(vmCIDR),
					Priority: normalPriority,
				})
				dataplane.ResetDeltas()
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(felixKey))
				Expect(dataplane.RouteKeyToRoute).To(HaveKey(birdKey))
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(felixKey))
				Expect(dataplane.DeletedRouteKeys).NotTo(HaveKey(birdKey))

				// Step 4: BIRD updates its route to normal priority.
				dataplane.RemoveMockRoute(&birdRoute)
				birdRouteNormal := netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: eth0.LinkAttrs.Index,
					Dst:       mustParseCIDR(vmCIDR),
					Type:      syscall.RTN_UNICAST,
					Protocol:  birdProto,
					Scope:     netlink.SCOPE_UNIVERSE,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  normalPriority,
				}
				dataplane.AddMockRoute(&birdRouteNormal)
				birdNormalKey := routeKeyStr(254, vmCIDR, normalPriority)

				// Resync: Felix should leave BIRD's route at the new priority alone.
				rt.QueueResync()
				dataplane.ResetDeltas()
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(dataplane.RouteKeyToRoute).To(HaveKey(birdNormalKey))
				Expect(dataplane.DeletedRouteKeys).NotTo(HaveKey(birdNormalKey))
			})
		})

		Describe("live migration: destination host", func() {
			// Simulates the sequence of events when a VM is live-migrated
			// TO this host. BIRD has a remote route for the VM on eth0;
			// Felix then programs a local workload route on cali1 with
			// elevated priority.

			const (
				normalPriority   = 200 // Normal routing priority.
				elevatedPriority = 100 // Lower number = higher kernel preference.
				birdProto        = 12  // RTPROT_BIRD
				vmCIDR           = "10.0.0.42/32"
			)

			var eth0 *mocknetlink.MockLink

			BeforeEach(func() {
				eth0 = dataplane.AddIface(10, "eth0", true, true)
			})

			It("should handle the full migration sequence", func() {
				// Step 1: BIRD remote route exists at normal priority.
				birdRoute := netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: eth0.LinkAttrs.Index,
					Dst:       mustParseCIDR(vmCIDR),
					Type:      syscall.RTN_UNICAST,
					Protocol:  birdProto,
					Scope:     netlink.SCOPE_UNIVERSE,
					Table:     unix.RT_TABLE_MAIN,
					Priority:  normalPriority,
				}
				dataplane.AddMockRoute(&birdRoute)
				birdKey := routeKeyStr(254, vmCIDR, normalPriority)

				// Initial resync: BIRD route should be left alone.
				rt.QueueResync()
				dataplane.ResetDeltas()
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(dataplane.RouteKeyToRoute).To(HaveKey(birdKey))
				Expect(dataplane.DeletedRouteKeys).NotTo(HaveKey(birdKey))

				// Step 2: VM is now live on this host — Felix programs a
				// local route with elevated priority.
				rt.SetRoutes(RouteClassLocalWorkload, "cali1", []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP(vmCIDR),
						Priority: elevatedPriority,
					},
				}})
				dataplane.ResetDeltas()
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				felixKey := routeKeyStr(254, vmCIDR, elevatedPriority)
				Expect(dataplane.RouteKeyToRoute).To(HaveKey(felixKey))
				Expect(dataplane.RouteKeyToRoute).To(HaveKey(birdKey))

				// Step 3: Source cleanup — BIRD removes the remote route.
				dataplane.RemoveMockRoute(&birdRoute)

				// Resync: Felix route should survive, BIRD route gone.
				rt.QueueResync()
				dataplane.ResetDeltas()
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(dataplane.RouteKeyToRoute).To(HaveKey(felixKey))
				Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(birdKey))

				// Step 4: Reversion to normal — Felix updates its route
				// to normal priority.
				rt.SetRoutes(RouteClassLocalWorkload, "cali1", []Target{{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP(vmCIDR),
						Priority: normalPriority,
					},
				}})
				dataplane.ResetDeltas()
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				normalKey := routeKeyStr(254, vmCIDR, normalPriority)
				Expect(dataplane.RouteKeyToRoute).To(HaveKey(normalKey))
				Expect(dataplane.RouteKeyToRoute).NotTo(HaveKey(felixKey))
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(felixKey))
			})
		})
	})
})

var _ = Describe("RouteTable (main table)", func() {
	var dataplane *mocknetlink.MockNetlinkDataplane
	var t *mocktime.MockTime
	var rt *RouteTable

	BeforeEach(func() {
		dataplane = mocknetlink.New()
		t = mocktime.New()
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.SetAutoIncrement(11 * time.Second)
		rt = New(
			&defaultOwnershipPolicy,
			4,
			10*time.Second,
			nil,
			FelixRouteProtocol,
			true,
			0,
			logutils.NewSummarizer("test"),
			dataplane,
			WithRouteCleanupGracePeriod(10*time.Second),
			WithTimeShim(t),
			WithConntrackShim(dataplane),
			WithNetlinkHandleShim(dataplane.NewMockNetlink),
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	Describe("with some interfaces", func() {
		var cali1, eth0 *mocknetlink.MockLink
		var gatewayRoute, cali1Route, cali1RouteTable100 netlink.Route
		BeforeEach(func() {
			eth0 = dataplane.AddIface(2, "eth0", true, true)
			cali1 = dataplane.AddIface(3, "cali1", true, true)
			cali1Route = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     unix.RT_TABLE_MAIN,
			}
			dataplane.AddMockRoute(&cali1Route)
			cali1RouteTable100 = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.3/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     100,
			}
			dataplane.AddMockRoute(&cali1RouteTable100)
			gatewayRoute = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: eth0.LinkAttrs.Index,
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Gw:        net.ParseIP("12.0.0.1"),
				Table:     unix.RT_TABLE_MAIN,
			}
			dataplane.AddMockRoute(&gatewayRoute)
		})
		It("should wait for the route cleanup delay", func() {
			t.SetAutoIncrement(0 * time.Second)
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(cali1Route, cali1RouteTable100, gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
			t.IncrementTime(11 * time.Second)
			err = rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(cali1RouteTable100, gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
		})
		It("should wait for the route cleanup delay when resyncing", func() {
			t.SetAutoIncrement(0 * time.Second)
			rt.QueueResync()
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(cali1Route, cali1RouteTable100, gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
			t.IncrementTime(11 * time.Second)
			rt.QueueResync()
			err = rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(cali1RouteTable100, gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
		})
		It("should clean up only routes from the required table", func() {
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(cali1RouteTable100, gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
		})
	})
})

var _ = Describe("RouteTable (table 100)", func() {
	var dataplane *mocknetlink.MockNetlinkDataplane
	var t *mocktime.MockTime
	var rt *RouteTable

	BeforeEach(func() {
		dataplane = mocknetlink.New()
		t = mocktime.New()
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.SetAutoIncrement(11 * time.Second)
		rt = New(
			&ownershippol.ExclusiveOwnershipPolicy{},
			4,
			10*time.Second,
			nil,
			FelixRouteProtocol,
			true,
			100,
			logutils.NewSummarizer("test"),
			dataplane,
			WithRouteCleanupGracePeriod(10*time.Second),
			WithTimeShim(t),
			WithConntrackShim(dataplane),
			WithNetlinkHandleShim(dataplane.NewMockNetlink),
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	Describe("with some interfaces and routes", func() {
		var cali, eth0 *mocknetlink.MockLink
		var gatewayRoute, caliRoute, caliRouteTable100, throwRoute, caliRouteTable100SameAsThrow netlink.Route
		BeforeEach(func() {
			eth0 = dataplane.AddIface(2, "eth0", true, true)
			cali = dataplane.AddIface(3, "cali", true, true)
			caliRoute = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     unix.RT_TABLE_MAIN,
			}
			dataplane.AddMockRoute(&caliRoute)
			caliRouteTable100 = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.3/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     100,
			}
			dataplane.AddMockRoute(&caliRouteTable100)
			gatewayRoute = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: eth0.LinkAttrs.Index,
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Gw:        net.ParseIP("12.0.0.1"),
				Table:     unix.RT_TABLE_MAIN,
			}
			dataplane.AddMockRoute(&gatewayRoute)
			throwRoute = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: 0,
				Dst:       mustParseCIDR("10.10.10.10/32"),
				Type:      syscall.RTN_THROW,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_UNIVERSE,
				Table:     100,
				Priority:  routePriorityForTest,
			}
			dataplane.AddMockRoute(&throwRoute)

			// Used in tests but not added to the dataplane at the start.
			caliRouteTable100SameAsThrow = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.10.10.10/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     100,
				Priority:  routePriorityForTest,
			}
		})
		It("should tidy up non-link routes immediately and wait for the route cleanup delay for interface routes", func() {
			t.SetAutoIncrement(0 * time.Second)
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, caliRouteTable100, gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
			t.IncrementTime(11 * time.Second)
			err = rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
		})
		It("should wait for the route cleanup delay when resyncing", func() {
			t.SetAutoIncrement(0 * time.Second)
			rt.QueueResync()
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, caliRouteTable100, gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
			t.IncrementTime(11 * time.Second)
			rt.QueueResync()
			err = rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
		})
		It("should clean up only routes from the required table", func() {
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute))
			Expect(dataplane.AddedRouteKeys).To(BeEmpty())
		})

		Describe("after configuring a throw route", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(RouteClassWireguard, InterfaceNone, Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
						Priority: routePriorityForTest,
					},
					Type: TargetTypeThrow,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("the throw route should remain and the cali route in table 100 should be removed", func() {
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, throwRoute))
				Expect(dataplane.AddedRouteKeys).To(BeEmpty())
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&caliRouteTable100)))
			})
		})

		Describe("after configuring a throw route", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(RouteClassWireguard, InterfaceNone, Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
						Priority: routePriorityForTest,
					},
					Type: TargetTypeThrow,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should be able to toggle between throw and local iface routes", func() {
				// Modify the action associated with a particular destination.
				for range 3 {
					rt.RouteRemove(RouteClassWireguard, InterfaceNone, RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
						Priority: routePriorityForTest,
					})
					rt.RouteUpdate(RouteClassLocalWorkload, "cali", Target{
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
							Priority: routePriorityForTest,
						},
					})
					err := rt.Apply()
					Expect(err).ToNot(HaveOccurred())
					Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, caliRouteTable100SameAsThrow))

					rt.RouteRemove(RouteClassLocalWorkload, "cali", RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
						Priority: routePriorityForTest,
					})
					rt.RouteUpdate(RouteClassWireguard, InterfaceNone, Target{
						RouteKey: RouteKey{
							CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
							Priority: routePriorityForTest,
						},
						Type: TargetTypeThrow,
					})
					err = rt.Apply()
					Expect(err).ToNot(HaveOccurred())
					Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, throwRoute))
				}
			})

			It("should prioritise a workload route over the throw route", func() {
				rt.RouteUpdate(RouteClassLocalWorkload, "cali", Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
						Priority: routePriorityForTest,
					},
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, caliRouteTable100SameAsThrow))

				rt.RouteRemove(RouteClassLocalWorkload, "cali", RouteKey{
					CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
					Priority: routePriorityForTest,
				})
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, throwRoute))
			})
		})

		Describe("throw route configured in dataplane, actual route is via cali", func() {
			It("the throw route should be removed and the interface route added", func() {
				rt.RouteUpdate(RouteClassLocalWorkload, "cali", Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
						Priority: routePriorityForTest,
					},
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, caliRouteTable100SameAsThrow))
			})
		})

		Describe("after configuring an existing throw route and then deleting it", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(RouteClassWireguard, InterfaceNone, Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
						Priority: routePriorityForTest,
					},
					Type: TargetTypeThrow,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				rt.RouteRemove(RouteClassWireguard, InterfaceNone, RouteKey{
					CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
					Priority: routePriorityForTest,
				})
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("the route should be removed", func() {
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute))
				Expect(dataplane.AddedRouteKeys).To(BeEmpty())
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&throwRoute)))
			})
		})

		Describe("after configuring a throw route and then replacing it with a blackhole route", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(RouteClassIPAMBlockDrop, InterfaceNone, Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
						Priority: routePriorityForTest,
					},
					Type: TargetTypeThrow,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				rt.RouteUpdate(RouteClassIPAMBlockDrop, InterfaceNone, Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
						Priority: routePriorityForTest,
					},
					Type: TargetTypeBlackhole,
				})
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("the blackhole route should remain", func() {
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: 0,
					Dst:       mustParseCIDR("10.10.10.10/32"),
					Type:      syscall.RTN_BLACKHOLE,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_UNIVERSE,
					Table:     100,
					Priority:  routePriorityForTest,
				}))
				Expect(dataplane.UpdatedRouteKeys.Contains(routeKeyStr(100, "10.10.10.10/32", routePriorityForTest))).To(BeTrue())
			})
		})

		Describe("after configuring a blackhole route and then replacing it with a prohibit route", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(RouteClassIPAMBlockDrop, InterfaceNone, Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
						Priority: routePriorityForTest,
					},
					Type: TargetTypeBlackhole,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				rt.RouteUpdate(RouteClassIPAMBlockDrop, InterfaceNone, Target{
					RouteKey: RouteKey{
						CIDR:     ip.MustParseCIDROrIP("10.10.10.10/32"),
						Priority: routePriorityForTest,
					},
					Type: TargetTypeProhibit,
				})
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("the prohibit route should remain", func() {
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, netlink.Route{
					Family:    unix.AF_INET,
					LinkIndex: 0,
					Dst:       mustParseCIDR("10.10.10.10/32"),
					Type:      syscall.RTN_PROHIBIT,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_UNIVERSE,
					Table:     100,
					Priority:  routePriorityForTest,
				}))
				Expect(dataplane.UpdatedRouteKeys.Contains(routeKeyStr(100, "10.10.10.10/32", routePriorityForTest))).To(BeTrue())
			})
		})
	})

	Describe("with an interface but no routes", func() {
		var cali *mocknetlink.MockLink
		var caliRoute netlink.Route
		BeforeEach(func() {
			cali = dataplane.AddIface(2, "cali", true, true)
			caliRoute = netlink.Route{
				Family:    unix.AF_INET,
				LinkIndex: cali.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     100,
				Priority:  routePriorityForTest,
			}
		})
		It("should create the table as needed", func() {
			// In "strict" mode, RouteListFiltered returns an error if the routing table doesn't exist.
			// Check that is handled and that we proceed to create the route (and thus create the routing table).
			rt.RouteUpdate(RouteClassLocalWorkload, "cali", Target{
				RouteKey: RouteKey{
					CIDR:     ip.MustParseCIDROrIP("10.0.0.1/32"),
					Priority: routePriorityForTest,
				},
			})
			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute))
			Expect(dataplane.HitRouteListFilteredNoTable).To(BeTrue(),
				"Expected first call to RouteListFiltered to be before routing table created.")
		})
	})
})

var _ = Describe("Tests to verify netlink interface", func() {
	It("Should give expected error for missing interface", func() {
		_, err := netlink.LinkByName("dsfhjakdhfjk")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not found"))
	})
})

var _ = Describe("Tests to verify ip version is policed", func() {
	It("Should panic with an invalid IP version", func() {
		Expect(func() {
			dataplane := mocknetlink.New()
			t := mocktime.New()
			_ = New(
				&defaultOwnershipPolicy,
				5, // invalid IP version
				10*time.Second,
				nil,
				FelixRouteProtocol,
				true,
				100,
				logutils.NewSummarizer("test"),
				dataplane,
				WithTimeShim(t),
				WithConntrackShim(dataplane),
				WithNetlinkHandleShim(dataplane.NewMockNetlink),
			)
		}).To(Panic())
	})
})

func mustParseCIDR(cidr string) *net.IPNet {
	_, c, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())
	return c
}
