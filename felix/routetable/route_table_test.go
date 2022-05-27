// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/calico/felix/logutils"
	. "github.com/projectcalico/calico/felix/routetable"

	"fmt"
	"net"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	mocknetlink "github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/testutils"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
)

var (
	FelixRouteProtocol = netlink.RouteProtocol(syscall.RTPROT_BOOT)

	mac1 = testutils.MustParseMAC("00:11:22:33:44:51")
	mac2 = testutils.MustParseMAC("00:11:22:33:44:52")

	ip1  = ip.MustParseCIDROrIP("10.0.0.1/32").ToIPNet()
	ip2  = ip.MustParseCIDROrIP("10.0.0.2/32").ToIPNet()
	ip13 = ip.MustParseCIDROrIP("10.0.1.3/32").ToIPNet()
)

var _ = Describe("RouteTable v6", func() {
	var dataplane *mocknetlink.MockNetlinkDataplane
	var t *mocktime.MockTime
	var rt *RouteTable

	BeforeEach(func() {
		dataplane = mocknetlink.New()
		t = mocktime.New()
		// No grace period set, so invalid routes should be deleted immediately on apply.
		rt = NewWithShims(
			[]string{"^cali.*"},
			6,
			dataplane.NewMockNetlink,
			false,
			10*time.Second,
			dataplane.AddStaticArpEntry,
			dataplane,
			t,
			nil,
			FelixRouteProtocol,
			true,
			0,
			logutils.NewSummarizer("test"),
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	It("should not remove the IPv6 link local route", func() {
		// Route that should be left alone
		noopLink := dataplane.AddIface(4, "cali4", true, true)
		noopRoute := netlink.Route{
			LinkIndex: noopLink.LinkAttrs.Index,
			Dst:       mustParseCIDR("fe80::/64"),
			Type:      syscall.RTN_UNICAST,
			Protocol:  syscall.RTPROT_KERNEL,
			Scope:     netlink.SCOPE_LINK,
		}
		rt.SetRoutes(noopLink.LinkAttrs.Name, []Target{
			{CIDR: ip.MustParseCIDROrIP("10.0.0.4/32"), DestMAC: mac1},
		})
		dataplane.AddMockRoute(&noopRoute)

		// Route that should be deleted.
		deleteLink := dataplane.AddIface(5, "cali5", true, true)
		deleteRoute := netlink.Route{
			LinkIndex: deleteLink.LinkAttrs.Index,
			Dst:       mustParseCIDR("10.0.0.1/32"),
			Type:      syscall.RTN_UNICAST,
			Protocol:  FelixRouteProtocol,
			Scope:     netlink.SCOPE_LINK,
		}
		dataplane.AddMockRoute(&deleteRoute)

		err := rt.Apply()
		Expect(err).ToNot(HaveOccurred())
		Expect(dataplane.DeletedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
		Expect(dataplane.UpdatedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
		Expect(dataplane.DeletedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&deleteRoute)))
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
		rt = NewWithShims(
			[]string{"^cali.*"},
			4,
			dataplane.NewMockNetlink,
			false,
			10*time.Second,
			dataplane.AddStaticArpEntry,
			dataplane,
			t,
			nil,
			FelixRouteProtocol,
			true,
			0,
			logutils.NewSummarizer("test"),
			WithRouteCleanupGracePeriod(10*time.Second),
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	It("should handle unexpected non-calico interface updates", func() {
		t.SetAutoIncrement(0 * time.Second)
		rt.OnIfaceStateChanged("calx", ifacemonitor.StateUp)
		err := rt.Apply()
		Expect(err).ToNot(HaveOccurred())
	})

	It("should handle unexpected calico interface updates", func() {
		t.SetAutoIncrement(0 * time.Second)
		rt.OnIfaceStateChanged("cali1", ifacemonitor.StateUp)
		rt.QueueResync()
		err := rt.Apply()
		Expect(err).ToNot(HaveOccurred())
		t.IncrementTime(11 * time.Second)
		rt.QueueResync()
		err = rt.Apply()
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("with some interfaces", func() {
		var cali1, cali3, eth0 *mocknetlink.MockLink
		var gatewayRoute, cali1Route, cali1Route2, cali3Route netlink.Route
		BeforeEach(func() {
			eth0 = dataplane.AddIface(0, "eth0", true, true)
			cali1 = dataplane.AddIface(1, "cali1", true, true)
			dataplane.AddIface(2, "cali2", true, true)
			cali3 = dataplane.AddIface(3, "cali3", true, true)
			cali1Route = netlink.Route{
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.AddMockRoute(&cali1Route)
			cali3Route = netlink.Route{
				LinkIndex: cali3.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.3/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.AddMockRoute(&cali3Route)
			gatewayRoute = netlink.Route{
				LinkIndex: eth0.LinkAttrs.Index,
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Gw:        net.ParseIP("12.0.0.1"),
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
			updateLink := dataplane.AddIface(5, "cali5", true, true)
			updateRoute := netlink.Route{
				LinkIndex: updateLink.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.5/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Src:       net.ParseIP("192.168.0.1"),
			}
			dataplane.AddMockRoute(&updateRoute)
			rt.SetRoutes(updateLink.LinkAttrs.Name, []Target{
				{CIDR: ip.MustParseCIDROrIP("10.0.0.5"), DestMAC: mac1},
			})

			fixedRoute := updateRoute
			fixedRoute.Src = nil

			err := rt.Apply()
			Expect(err).ToNot(HaveOccurred())
			Expect(dataplane.UpdatedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&updateRoute)))
			Expect(dataplane.RouteKeyToRoute[mocknetlink.KeyForRoute(&updateRoute)]).To(Equal(fixedRoute))

		})
		Describe("With a device route source address set", func() {
			deviceRouteSource := "192.168.0.1"
			deviceRouteSourceAddress := net.ParseIP(deviceRouteSource)
			// Modify the route table to have the device route source address set
			BeforeEach(func() {
				rt = NewWithShims(
					[]string{"^cali.*"},
					4,
					dataplane.NewMockNetlink,
					false,
					10*time.Second,
					dataplane.AddStaticArpEntry,
					dataplane,
					t,
					deviceRouteSourceAddress,
					FelixRouteProtocol,
					true,
					0,
					logutils.NewSummarizer("test"),
				)
			})
			It("Should delete routes without a source address", func() {
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&cali3Route)))
				Expect(dataplane.DeletedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&cali1Route)))
			})
			It("Should add routes with a source address", func() {
				// Route that needs to be added
				addLink := dataplane.AddIface(6, "cali6", true, true)
				rt.SetRoutes(addLink.LinkAttrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.6"), DestMAC: mac1},
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute["254-10.0.0.6/32"]).To(Equal(netlink.Route{
					LinkIndex: addLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.6/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Src:       deviceRouteSourceAddress,
				}))
				Expect(dataplane.HasStaticArpEntry(ip.MustParseCIDROrIP("10.0.0.6/32"), mac1, "cali6")).To(BeTrue())
			})
			It("Should not remove routes with a source address", func() {
				// Route that should be left alone
				noopLink := dataplane.AddIface(4, "cali4", true, true)
				noopRoute := netlink.Route{
					LinkIndex: noopLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.4/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Src:       deviceRouteSourceAddress,
				}
				rt.SetRoutes(noopLink.LinkAttrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.4/32"), DestMAC: mac1},
				})
				dataplane.AddMockRoute(&noopRoute)

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.DeletedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
				Expect(dataplane.UpdatedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
				Expect(dataplane.HasStaticArpEntry(ip.CIDRFromIPNet(noopRoute.Dst), mac1, noopLink.Attrs().Name)).To(BeTrue())
			})
			It("Should update source addresses from nil to a given source", func() {
				// Route that needs to be updated
				updateLink := dataplane.AddIface(5, "cali5", true, true)
				updateRoute := netlink.Route{
					LinkIndex: updateLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.5/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}
				rt.SetRoutes(updateLink.LinkAttrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.5"), DestMAC: mac1},
				})
				dataplane.AddMockRoute(&updateRoute)

				fixedRoute := updateRoute
				fixedRoute.Src = deviceRouteSourceAddress

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.UpdatedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&updateRoute)))
				Expect(dataplane.RouteKeyToRoute[mocknetlink.KeyForRoute(&updateRoute)]).To(Equal(fixedRoute))
				Expect(dataplane.HasStaticArpEntry(ip.MustParseCIDROrIP("10.0.0.5/32"), mac1, "cali5")).To(BeTrue())
			})

			It("Should update source addresses from an old source to a new one", func() {
				// Route that needs to be updated
				updateLink := dataplane.AddIface(5, "cali5", true, true)
				updateRoute := netlink.Route{
					LinkIndex: updateLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.5/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
					Src:       net.ParseIP("192.168.0.2"),
				}
				rt.SetRoutes(updateLink.LinkAttrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.5"), DestMAC: mac1},
				})
				dataplane.AddMockRoute(&updateRoute)

				fixedRoute := updateRoute
				fixedRoute.Src = deviceRouteSourceAddress

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.UpdatedRouteKeys).To(HaveKey(mocknetlink.KeyForRoute(&updateRoute)))
				Expect(dataplane.RouteKeyToRoute[mocknetlink.KeyForRoute(&updateRoute)]).To(Equal(fixedRoute))
				Expect(dataplane.HasStaticArpEntry(ip.MustParseCIDROrIP("10.0.0.5/32"), mac1, "cali5")).To(BeTrue())
			})
		})

		Describe("With a device route protocol set", func() {
			deviceRouteProtocol := netlink.RouteProtocol(10)
			// Modify the route table to have the device route source address set
			BeforeEach(func() {
				rt = NewWithShims(
					[]string{"^cali.*"},
					4,
					dataplane.NewMockNetlink,
					false,
					10*time.Second,
					dataplane.AddStaticArpEntry,
					dataplane,
					t,
					nil,
					deviceRouteProtocol,
					true,
					0,
					logutils.NewSummarizer("test"),
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
				rt.SetRoutes(addLink.LinkAttrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.6"), DestMAC: mac1},
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute["254-10.0.0.6/32"]).To(Equal(netlink.Route{
					LinkIndex: addLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.6/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})
			It("Should add multiple routes with a protocol", func() {
				// Route that needs to be added
				addLink := dataplane.AddIface(6, "cali6", true, true)
				rt.SetRoutes(addLink.LinkAttrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.6"), DestMAC: mac1},
					{CIDR: ip.MustParseCIDROrIP("10.0.0.7"), DestMAC: mac1},
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute["254-10.0.0.6/32"]).To(Equal(netlink.Route{
					LinkIndex: addLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.6/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
				Expect(dataplane.RouteKeyToRoute["254-10.0.0.7/32"]).To(Equal(netlink.Route{
					LinkIndex: addLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.7/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})
			It("Should add multiple routes with a protocol after persistent failures", func() {
				// Route that needs to be added
				addLink := dataplane.AddIface(6, "cali6", true, true)
				rt.SetRoutes(addLink.LinkAttrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.6"), DestMAC: mac1},
					{CIDR: ip.MustParseCIDROrIP("10.0.0.7"), DestMAC: mac1},
				})
				// Persist failures, this will apply the deltas to the cache but will be out of sync with the dataplane.
				dataplane.FailuresToSimulate = mocknetlink.FailNextRouteAdd
				dataplane.PersistFailures = true
				err := rt.Apply()
				Expect(err).To(HaveOccurred())

				// Retry - this will now succeed and fix everything.
				dataplane.FailuresToSimulate = mocknetlink.FailNone
				dataplane.PersistFailures = false
				err = rt.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute["254-10.0.0.6/32"]).To(Equal(netlink.Route{
					LinkIndex: addLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.6/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
				Expect(dataplane.RouteKeyToRoute["254-10.0.0.7/32"]).To(Equal(netlink.Route{
					LinkIndex: addLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.7/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})
			It("Should not remove routes with a protocol", func() {
				// Route that should be left alone
				noopLink := dataplane.AddIface(4, "cali4", true, true)
				noopRoute := netlink.Route{
					LinkIndex: noopLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.4/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  deviceRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}
				rt.SetRoutes(noopLink.LinkAttrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.4/32"), DestMAC: mac1},
				})
				dataplane.AddMockRoute(&noopRoute)

				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.DeletedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
				Expect(dataplane.UpdatedRouteKeys).ToNot(HaveKey(mocknetlink.KeyForRoute(&noopRoute)))
			})
			It("Should update protocol from nil to a given protocol", func() {
				// Route that needs to be updated
				updateLink := dataplane.AddIface(5, "cali5", true, true)
				updateRoute := netlink.Route{
					LinkIndex: updateLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.5/32"),
					Type:      syscall.RTN_UNICAST,
					Scope:     netlink.SCOPE_LINK,
				}
				rt.SetRoutes(updateLink.LinkAttrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.5"), DestMAC: mac1},
				})
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
				updateLink := dataplane.AddIface(5, "cali5", true, true)
				updateRoute := netlink.Route{
					LinkIndex: updateLink.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.0.5/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  64,
					Scope:     netlink.SCOPE_LINK,
				}
				rt.SetRoutes(updateLink.LinkAttrs.Name, []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.5"), DestMAC: mac1},
				})
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
				rt.SetRoutes("cali1", []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.1/32"), DestMAC: mac1},
				})
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
				rt.SetRoutes("cali1", []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.10/32"), DestMAC: mac1},
				})
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
				for i := 0; i < 3; i++ {
					Expect(rt.Apply()).To(Equal(ConnectFailed))
				}
				Expect(func() { _ = rt.Apply() }).To(Panic())
			})
		})

		Describe("after syncing, after adding a route and failing the update twice", func() {
			JustBeforeEach(func() {
				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())

				dataplane.FailuresToSimulate = mocknetlink.FailNextRouteAdd
				dataplane.PersistFailures = true
				rt.RouteUpdate("cali3", Target{
					CIDR: ip.MustParseCIDROrIP("10.20.30.40"),
				})
				err = rt.Apply()
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(UpdateFailed))

				dataplane.FailuresToSimulate = 0
				dataplane.PersistFailures = false
			})

			It("has not programmed the route", func() {
				Expect(dataplane.RouteKeyToRoute).NotTo(ContainElement(netlink.Route{
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})

			It("resolves on the next apply", func() {
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})
		})

		Describe("after adding two routes to cali3", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate("cali3", Target{
					CIDR: ip.MustParseCIDROrIP("10.20.30.40"),
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				rt.RouteUpdate("cali3", Target{
					CIDR: ip.MustParseCIDROrIP("10.0.20.0/24"),
				})
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should have two routes for cali3", func() {
				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.20.0/24"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})

			It("should make no dataplane updates when deleting, creating and updating back to the same target before the next apply", func() {
				rt.RouteRemove("cali3", ip.MustParseCIDROrIP("10.0.20.0/24"))
				rt.RouteUpdate("cali3", Target{
					CIDR: ip.MustParseCIDROrIP("10.0.20.0/24"),
					GW:   ip.FromString("1.2.3.4"),
				})
				rt.RouteUpdate("cali3", Target{
					CIDR: ip.MustParseCIDROrIP("10.0.20.0/24"),
				})
				dataplane.ResetDeltas()

				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(dataplane.AddedRouteKeys).To(BeEmpty())
				Expect(dataplane.DeletedRouteKeys).To(BeEmpty())
				Expect(dataplane.UpdatedRouteKeys).To(BeEmpty())

				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.20.0/24"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})

			It("should make no dataplane updates when deleting and then setting back to the same target before the next apply", func() {
				rt.RouteRemove("cali3", ip.MustParseCIDROrIP("10.0.20.0/24"))
				rt.SetRoutes("cali3", []Target{{
					CIDR: ip.MustParseCIDROrIP("10.0.20.0/24"),
				}, {
					CIDR: ip.MustParseCIDROrIP("10.20.30.40"),
				}})

				dataplane.ResetDeltas()

				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(dataplane.AddedRouteKeys).To(BeEmpty())
				Expect(dataplane.DeletedRouteKeys).To(BeEmpty())
				Expect(dataplane.UpdatedRouteKeys).To(BeEmpty())

				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.20.30.40/32"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
				Expect(dataplane.RouteKeyToRoute).To(ContainElement(netlink.Route{
					LinkIndex: cali3.LinkAttrs.Index,
					Dst:       mustParseCIDR("10.0.20.0/24"),
					Type:      syscall.RTN_UNICAST,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_LINK,
				}))
			})
		})

		Describe("delete interface", func() {
			BeforeEach(func() {
				rt.SetRoutes("cali1", []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.1/32")},
				})
				rt.SetRoutes("cali3", []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.3/32")},
				})
				// Apply the changes.
				err := rt.Apply()
				Expect(err).NotTo(HaveOccurred())

				// Modify route and delete interface
				rt.SetRoutes("cali3", nil)
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
			failFlags := testFailFlags
			desc := fmt.Sprintf("with some routes added and failures: %v", failFlags)
			Describe(desc, func() {
				BeforeEach(func() {
					rt.SetRoutes("cali1", []Target{
						{CIDR: ip.MustParseCIDROrIP("10.0.0.1/32"), DestMAC: mac1},
					})
					rt.SetRoutes("cali2", []Target{
						{CIDR: ip.MustParseCIDROrIP("10.0.0.2/32"), DestMAC: mac2},
					})
					rt.SetRoutes("cali3", []Target{
						{CIDR: ip.MustParseCIDROrIP("10.0.1.3/32")},
					})
					dataplane.FailuresToSimulate = failFlags
				})
				JustBeforeEach(func() {
					maxTries := 1
					if failFlags != mocknetlink.FailNone {
						maxTries = 2
					}
					for try := 0; try < maxTries; try++ {
						err := rt.Apply()
						if err == nil {
							// We should only need to retry if Apply returns an error.
							log.Info("Apply returned no error, breaking out of loop")
							break
						}
					}
					if failFlags == mocknetlink.FailNextLinkByNameNotFound {
						// Special case: a "not found" error doesn't get
						// rechecked straight away because it's expected
						// so we have to give the RouteTable a nudge.
						rt.QueueResync()
						err := rt.Apply()
						Expect(err).ToNot(HaveOccurred())
					}
				})
				It("should have consumed all failures", func() {
					// Check that all the failures we simulated were hit.
					Expect(dataplane.FailuresToSimulate).To(Equal(mocknetlink.FailNone))
				})
				It("should keep correct route", func() {
					Expect(dataplane.RouteKeyToRoute["254-10.0.0.1/32"]).To(Equal(netlink.Route{
						LinkIndex: 1,
						Dst:       &ip1,
						Type:      syscall.RTN_UNICAST,
						Protocol:  FelixRouteProtocol,
						Scope:     netlink.SCOPE_LINK,
					}))
					Expect(dataplane.AddedRouteKeys.Contains("254-10.0.0.1/32")).To(BeFalse())
				})
				It("should add new route", func() {
					Expect(dataplane.RouteKeyToRoute).To(HaveKey("254-10.0.0.2/32"))
					Expect(dataplane.RouteKeyToRoute["254-10.0.0.2/32"]).To(Equal(netlink.Route{
						LinkIndex: 2,
						Dst:       &ip2,
						Type:      syscall.RTN_UNICAST,
						Protocol:  FelixRouteProtocol,
						Scope:     netlink.SCOPE_LINK,
					}))
				})
				It("should update changed route", func() {
					Expect(dataplane.RouteKeyToRoute).To(HaveKey("254-10.0.1.3/32"))
					Expect(dataplane.RouteKeyToRoute["254-10.0.1.3/32"]).To(Equal(netlink.Route{
						LinkIndex: 3,
						Dst:       &ip13,
						Type:      syscall.RTN_UNICAST,
						Protocol:  FelixRouteProtocol,
						Scope:     netlink.SCOPE_LINK,
					}))
					Expect(dataplane.DeletedRouteKeys.Contains("254-10.0.0.3/32")).To(BeTrue())
					Eventually(dataplane.GetDeletedConntrackEntries).Should(Equal([]net.IP{net.ParseIP("10.0.0.3").To4()}))
				})
				It("should have expected number of routes at the end", func() {
					Expect(len(dataplane.RouteKeyToRoute)).To(Equal(4),
						fmt.Sprintf("Wrong number of routes %v: %v",
							len(dataplane.RouteKeyToRoute),
							dataplane.RouteKeyToRoute))
				})
				if failFlags&(mocknetlink.FailNextSetSocketTimeout|
					mocknetlink.FailNextNewNetlink|
					mocknetlink.FailNextLinkByName|
					mocknetlink.FailNextLinkList|
					mocknetlink.FailNextRouteAdd|
					mocknetlink.FailNextRouteDel|
					mocknetlink.FailNextAddARP|
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
							LinkIndex: cali1.LinkAttrs.Index,
							Dst:       mustParseCIDR("10.0.0.22/32"),
							Type:      syscall.RTN_UNICAST,
							Scope:     netlink.SCOPE_LINK,
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
			cali1 = dataplane.AddIface(1, "cali1", false, false)
			cali1Route = netlink.Route{
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
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
		} {
			failure := failure
			It(fmt.Sprintf("with a %v failure, it should give up", failure), func() {
				dataplane.FailuresToSimulate = failure
				err := rt.Apply()
				Expect(err).To(BeNil())
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(cali1Route))
			})
			It(fmt.Sprintf("with a %v failure, it shouldn't leave the interface dirty", failure), func() {
				// First Apply() with a failure.
				dataplane.FailuresToSimulate = failure
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				// All failures should have been hit.
				Expect(dataplane.FailuresToSimulate).To(BeZero())
				// Try another Apply(), the interface shouldn't be marked dirty
				// so nothing should happen.
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(cali1Route))
			})
			It(fmt.Sprintf("with a %v failure it should ignore Down updates", failure), func() {
				// First Apply() with a failure.
				dataplane.FailuresToSimulate = failure
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				// Fire in the update.
				rt.OnIfaceStateChanged("cali1", ifacemonitor.StateDown)
				// Try another Apply(), the interface shouldn't be marked dirty
				// so nothing should happen.
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(cali1Route))
			})
			It(fmt.Sprintf("with a %v failure, then an interface kick, it should sync", failure), func() {
				dataplane.FailuresToSimulate = failure
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())

				// Set interface up
				rt.OnIfaceStateChanged("cali1", ifacemonitor.StateUp)
				cali1 = dataplane.AddIface(1, "cali1", true, true)

				// Now, the apply should work.
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute).To(BeEmpty())
			})
		}
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
		rt = NewWithShims(
			[]string{"^cali.*"},
			4,
			dataplane.NewMockNetlink,
			false,
			10*time.Second,
			dataplane.AddStaticArpEntry,
			dataplane,
			t,
			nil,
			FelixRouteProtocol,
			true,
			0,
			logutils.NewSummarizer("test"),
			WithRouteCleanupGracePeriod(10*time.Second),
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	Describe("with some interfaces", func() {
		var cali1, eth0 *mocknetlink.MockLink
		var gatewayRoute, cali1Route, cali1RouteTable100 netlink.Route
		BeforeEach(func() {
			eth0 = dataplane.AddIface(0, "eth0", true, true)
			cali1 = dataplane.AddIface(1, "cali1", true, true)
			cali1Route = netlink.Route{
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.AddMockRoute(&cali1Route)
			cali1RouteTable100 = netlink.Route{
				LinkIndex: cali1.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.3/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     100,
			}
			dataplane.AddMockRoute(&cali1RouteTable100)
			gatewayRoute = netlink.Route{
				LinkIndex: eth0.LinkAttrs.Index,
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Gw:        net.ParseIP("12.0.0.1"),
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
		rt = NewWithShims(
			[]string{"^cali$", InterfaceNone}, // exact interface match
			4,
			dataplane.NewMockNetlink,
			false,
			10*time.Second,
			dataplane.AddStaticArpEntry,
			dataplane,
			t,
			nil,
			FelixRouteProtocol,
			true,
			100,
			logutils.NewSummarizer("test"),
			WithRouteCleanupGracePeriod(10*time.Second),
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	Describe("with some interfaces", func() {
		var cali, eth0 *mocknetlink.MockLink
		var gatewayRoute, caliRoute, caliRouteTable100, throwRoute, caliRouteTable100SameAsThrow netlink.Route
		BeforeEach(func() {
			eth0 = dataplane.AddIface(0, "eth0", true, true)
			cali = dataplane.AddIface(1, "cali", true, true)
			caliRoute = netlink.Route{
				LinkIndex: cali.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.AddMockRoute(&caliRoute)
			caliRouteTable100 = netlink.Route{
				LinkIndex: cali.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.0.0.3/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     100,
			}
			dataplane.AddMockRoute(&caliRouteTable100)
			gatewayRoute = netlink.Route{
				LinkIndex: eth0.LinkAttrs.Index,
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Gw:        net.ParseIP("12.0.0.1"),
			}
			dataplane.AddMockRoute(&gatewayRoute)
			throwRoute = netlink.Route{
				LinkIndex: 0,
				Dst:       mustParseCIDR("10.10.10.10/32"),
				Type:      syscall.RTN_THROW,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_UNIVERSE,
				Table:     100,
			}
			dataplane.AddMockRoute(&throwRoute)

			// Used in tests but not added to the dataplane at the start.
			caliRouteTable100SameAsThrow = netlink.Route{
				LinkIndex: cali.LinkAttrs.Index,
				Dst:       mustParseCIDR("10.10.10.10/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  FelixRouteProtocol,
				Scope:     netlink.SCOPE_LINK,
				Table:     100,
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
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
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

		Describe("after configuring a throw route and then deleting and recreating the route via cali", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					Type: TargetTypeThrow,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("the throw route should be removed and the interface route added", func() {
				// Modify the action associated with a particular destination.
				for ii := 0; ii < 100; ii ++ {
					rt.RouteRemove(InterfaceNone, ip.MustParseCIDROrIP("10.10.10.10/32"))
					rt.RouteUpdate("cali", Target{
						CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					})
					err := rt.Apply()
					Expect(err).ToNot(HaveOccurred())
					Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, caliRouteTable100SameAsThrow))

					rt.RouteRemove("cali", ip.MustParseCIDROrIP("10.10.10.10/32"))
					rt.RouteUpdate(InterfaceNone, Target{
						CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
						Type: TargetTypeThrow,
					})
					err = rt.Apply()
					Expect(err).ToNot(HaveOccurred())
					Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, throwRoute))
				}
			})
		})

		Describe("throw route configured in dataplane, actual route is via cali", func() {
			It("the throw route should be removed and the interface route added", func() {
				rt.RouteUpdate("cali", Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, caliRouteTable100SameAsThrow))
			})
		})

		Describe("after configuring an existing throw route and then deleting it", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					Type: TargetTypeThrow,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				rt.RouteRemove(InterfaceNone, ip.MustParseCIDROrIP("10.10.10.10/32"))
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
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					Type: TargetTypeThrow,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					Type: TargetTypeBlackhole,
				})
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})

			It("the blackhole route should remain", func() {
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, netlink.Route{
					LinkIndex: 0,
					Dst:       mustParseCIDR("10.10.10.10/32"),
					Type:      syscall.RTN_BLACKHOLE,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_UNIVERSE,
					Table:     100,
				}))
				Expect(dataplane.AddedRouteKeys.Contains("100-10.10.10.10/32")).To(BeTrue())
				Expect(dataplane.DeletedRouteKeys.Contains("100-10.10.10.10/32")).To(BeTrue())
			})
		})

		Describe("after configuring a blackhole route and then replacing it with a prohibit route", func() {
			JustBeforeEach(func() {
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					Type: TargetTypeBlackhole,
				})
				err := rt.Apply()
				Expect(err).ToNot(HaveOccurred())
				rt.RouteUpdate(InterfaceNone, Target{
					CIDR: ip.MustParseCIDROrIP("10.10.10.10/32"),
					Type: TargetTypeProhibit,
				})
				err = rt.Apply()
				Expect(err).ToNot(HaveOccurred())
			})


			It("the prohibit route should remain", func() {
				Expect(dataplane.RouteKeyToRoute).To(ConsistOf(caliRoute, gatewayRoute, netlink.Route{
					LinkIndex: 0,
					Dst:       mustParseCIDR("10.10.10.10/32"),
					Type:      syscall.RTN_PROHIBIT,
					Protocol:  FelixRouteProtocol,
					Scope:     netlink.SCOPE_UNIVERSE,
					Table:     100,
				}))
				Expect(dataplane.AddedRouteKeys.Contains("100-10.10.10.10/32")).To(BeTrue())
				Expect(dataplane.DeletedRouteKeys.Contains("100-10.10.10.10/32")).To(BeTrue())
			})
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
			_ = NewWithShims(
				[]string{"^cali$", InterfaceNone},
				5, // invalid IP version
				dataplane.NewMockNetlink,
				false,
				10*time.Second,
				dataplane.AddStaticArpEntry,
				dataplane,
				t,
				nil,
				FelixRouteProtocol,
				true,
				100,
				logutils.NewSummarizer("test"),
			)
		}).To(Panic())
	})
})

func mustParseCIDR(cidr string) *net.IPNet {
	_, c, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())
	return c
}
