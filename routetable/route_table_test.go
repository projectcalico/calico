// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	. "github.com/projectcalico/felix/routetable"

	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/testutils"
	"github.com/projectcalico/libcalico-go/lib/set"
)

var (
	simulatedError = errors.New("dummy error")
	notFound       = errors.New("not found")
	alreadyExists  = errors.New("already exists")

	mac1 = testutils.MustParseMAC("00:11:22:33:44:51")
	mac2 = testutils.MustParseMAC("00:11:22:33:44:52")
	mac3 = testutils.MustParseMAC("00:11:22:33:44:53")

	ip1  = ip.MustParseCIDROrIP("10.0.0.1/32").ToIPNet()
	ip2  = ip.MustParseCIDROrIP("10.0.0.2/32").ToIPNet()
	ip3  = ip.MustParseCIDROrIP("10.0.0.3/32").ToIPNet()
	ip13 = ip.MustParseCIDROrIP("10.0.1.3/32").ToIPNet()
)

var _ = Describe("RouteTable", func() {
	var dataplane *mockDataplane
	var t *mockTime
	var rt *RouteTable

	BeforeEach(func() {
		dataplane = &mockDataplane{
			nameToLink:       map[string]netlink.Link{},
			routeKeyToRoute:  map[string]netlink.Route{},
			addedRouteKeys:   set.New(),
			deletedRouteKeys: set.New(),
		}
		startTime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
		Expect(err).NotTo(HaveOccurred())
		t = &mockTime{
			currentTime: startTime,
		}
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.setAutoIncrement(11 * time.Second)
		rt = NewWithShims(
			[]string{"cali"},
			4,
			dataplane.NewNetlinkHandle,
			10*time.Second,
			dataplane.AddStaticArpEntry,
			dataplane,
			t,
		)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	Describe("with some interfaces", func() {
		var cali1, cali3, eth0 *mockLink
		var gatewayRoute, cali1Route, cali1Route2, cali3Route netlink.Route
		BeforeEach(func() {
			eth0 = dataplane.addIface(0, "eth0", true, true)
			cali1 = dataplane.addIface(1, "cali1", true, true)
			dataplane.addIface(2, "cali2", true, true)
			cali3 = dataplane.addIface(3, "cali3", true, true)
			cali1Route = netlink.Route{
				LinkIndex: cali1.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  syscall.RTPROT_BOOT,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.addMockRoute(&cali1Route)
			cali3Route = netlink.Route{
				LinkIndex: cali3.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.3/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  syscall.RTPROT_BOOT,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.addMockRoute(&cali3Route)
			gatewayRoute = netlink.Route{
				LinkIndex: eth0.attrs.Index,
				Type:      syscall.RTN_UNICAST,
				Protocol:  syscall.RTPROT_BOOT,
				Scope:     netlink.SCOPE_LINK,
				Gw:        net.ParseIP("12.0.0.1"),
			}
			dataplane.addMockRoute(&gatewayRoute)
		})
		It("should wait for the route cleanup delay", func() {
			t.setAutoIncrement(0 * time.Second)
			rt.Apply()
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1Route, cali3Route, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
			t.incrementTime(11 * time.Second)
			rt.Apply()
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})
		It("should wait for the route cleanup delay when resyncing", func() {
			t.setAutoIncrement(0 * time.Second)
			rt.QueueResync()
			rt.Apply()
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1Route, cali3Route, gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
			t.incrementTime(11 * time.Second)
			rt.QueueResync()
			rt.Apply()
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})
		It("should clean up only our routes", func() {
			rt.Apply()
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})
		It("should delete only our conntrack entries", func() {
			rt.Apply()
			Eventually(dataplane.GetDeletedConntrackEntries).Should(ConsistOf(
				net.ParseIP("10.0.0.1").To4(),
				net.ParseIP("10.0.0.3").To4(),
			))
		})

		Describe("with a slow conntrack deletion", func() {
			const delay = 300 * time.Millisecond
			BeforeEach(func() {
				dataplane.ConntrackSleep = delay
			})
			It("should block a route add until conntrack finished", func() {
				// Initial apply starts a background thread to delete
				// 10.0.0.1 and 10.0.0.3.
				rt.Apply()
				// We try to add 10.0.0.1 back in.
				rt.SetRoutes("cali1", []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.1/32"), DestMAC: mac1},
				})
				start := time.Now()
				rt.Apply()
				Expect(time.Since(start)).To(BeNumerically(">=", delay*9/10))
			})
			It("should not block an unrelated route add ", func() {
				// Initial apply starts a background thread to delete
				// 10.0.0.1 and 10.0.0.3.
				rt.Apply()
				// We try to add 10.0.0.10, which hasn't been seen before.
				rt.SetRoutes("cali1", []Target{
					{CIDR: ip.MustParseCIDROrIP("10.0.0.10/32"), DestMAC: mac1},
				})
				start := time.Now()
				rt.Apply()
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
				Expect(func() { rt.Apply() }).To(Panic())
			})
		})

		// We do the following tests in different failure (and non-failure) scenarios.  In
		// each case, we make the failure transient so that only the first Apply() should
		// fail.  Then, at most, the second call to Apply() should succeed.
		for _, failFlags := range failureScenarios {
			failFlags := failFlags
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
					dataplane.failuresToSimulate = failFlags
				})
				JustBeforeEach(func() {
					maxTries := 1
					if failFlags != 0 {
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
					if failFlags == failNextLinkByNameNotFound {
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
					Expect(dataplane.failuresToSimulate).To(Equal(failNone))
				})
				It("should keep correct route", func() {
					Expect(dataplane.routeKeyToRoute["1-10.0.0.1/32"]).To(Equal(netlink.Route{
						LinkIndex: 1,
						Dst:       &ip1,
						Type:      syscall.RTN_UNICAST,
						Protocol:  syscall.RTPROT_BOOT,
						Scope:     netlink.SCOPE_LINK,
					}))
					Expect(dataplane.addedRouteKeys.Contains("1-10.0.0.1/32")).To(BeFalse())
				})
				It("should add new route", func() {
					Expect(dataplane.routeKeyToRoute["2-10.0.0.2/32"]).To(Equal(netlink.Route{
						LinkIndex: 2,
						Dst:       &ip2,
						Type:      syscall.RTN_UNICAST,
						Protocol:  syscall.RTPROT_BOOT,
						Scope:     netlink.SCOPE_LINK,
					}))
				})
				It("should update changed route", func() {
					Expect(dataplane.routeKeyToRoute["3-10.0.1.3/32"]).To(Equal(netlink.Route{
						LinkIndex: 3,
						Dst:       &ip13,
						Type:      syscall.RTN_UNICAST,
						Protocol:  syscall.RTPROT_BOOT,
						Scope:     netlink.SCOPE_LINK,
					}))
					Expect(dataplane.deletedRouteKeys.Contains("3-10.0.0.3/32")).To(BeTrue())
				})
				It("should have expected number of routes at the end", func() {
					Expect(len(dataplane.routeKeyToRoute)).To(Equal(4),
						fmt.Sprintf("Wrong number of routes %v: %v",
							len(dataplane.routeKeyToRoute),
							dataplane.routeKeyToRoute))
				})
				if failFlags&(failNextSetSocketTimeout|
					failNextNewNetlinkHandle|
					failNextLinkByName|
					failNextLinkList|
					failNextRouteAdd|
					failNextRouteDel|
					failNextAddARP|
					failNextRouteList) != 0 {
					It("should reconnect to netlink", func() {
						Expect(dataplane.NumNewNetlinkCalls).To(Equal(2))
					})
				} else {
					It("should not reconnect to netlink", func() {
						Expect(dataplane.NumNewNetlinkCalls).To(Equal(1))
					})
				}

				Describe("after an external route addition", func() {
					JustBeforeEach(func() {
						cali1Route2 = netlink.Route{
							LinkIndex: cali1.attrs.Index,
							Dst:       mustParseCIDR("10.0.0.22/32"),
							Type:      syscall.RTN_UNICAST,
							Protocol:  syscall.RTPROT_BOOT,
							Scope:     netlink.SCOPE_LINK,
						}
						dataplane.addMockRoute(&cali1Route2)
						rt.Apply()
					})

					It("shouldn't spot the update", func() {
						Expect(dataplane.routeKeyToRoute).To(HaveLen(5))
						Expect(dataplane.routeKeyToRoute).To(ContainElement(cali1Route2))
					})
					It("after a QueueResync() should remove the route", func() {
						rt.QueueResync()
						rt.Apply()
						Expect(dataplane.routeKeyToRoute).To(HaveLen(4))
						Expect(dataplane.routeKeyToRoute).NotTo(ContainElement(cali1Route2))
					})
				})

				Describe("after an external route remove", func() {
					JustBeforeEach(func() {
						dataplane.removeMockRoute(&cali1Route)
						rt.Apply()
					})

					It("shouldn't spot the update", func() {
						Expect(dataplane.routeKeyToRoute).To(HaveLen(3))
						Expect(dataplane.routeKeyToRoute).NotTo(ContainElement(cali1Route))
					})
					It("after a QueueResync() should remove the route", func() {
						rt.QueueResync()
						rt.Apply()
						Expect(dataplane.routeKeyToRoute).To(HaveLen(4))
						Expect(dataplane.routeKeyToRoute).To(ContainElement(cali1Route))
					})
				})
			})
		}
	})

	Describe("with a down interface", func() {
		var cali1 *mockLink
		var cali1Route netlink.Route
		BeforeEach(func() {
			cali1 = dataplane.addIface(1, "cali1", false, false)
			cali1Route = netlink.Route{
				LinkIndex: cali1.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  syscall.RTPROT_BOOT,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.addMockRoute(&cali1Route)
		})
		It("with no failures, it should still try to clean up the route", func() {
			err := rt.Apply()
			Expect(err).To(BeNil())
			Expect(dataplane.routeKeyToRoute).To(BeEmpty())
		})
		for _, failure := range []failFlags{
			failNextLinkByName,
			failNextRouteDel,
			failNextRouteList,
		} {
			failure := failure
			It(fmt.Sprintf("with a %v failure, it should give up", failure), func() {
				dataplane.failuresToSimulate = failure
				err := rt.Apply()
				Expect(err).To(BeNil())
				Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1Route))
			})
			It(fmt.Sprintf("with a %v failure, it shouldn't leave the interface dirty", failure), func() {
				// First Apply() with a failure.
				dataplane.failuresToSimulate = failure
				rt.Apply()
				// All failures should have been hit.
				Expect(dataplane.failuresToSimulate).To(BeZero())
				// Try another Apply(), the interface shouldn't be marked dirty
				// so nothing should happen.
				err := rt.Apply()
				Expect(err).To(BeNil())
				Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1Route))
			})
			It(fmt.Sprintf("with a %v failure it should ignore Down updates", failure), func() {
				// First Apply() with a failure.
				dataplane.failuresToSimulate = failure
				rt.Apply()
				// Fire in the update.
				rt.OnIfaceStateChanged("cali1", ifacemonitor.StateDown)
				// Try another Apply(), the interface shouldn't be marked dirty
				// so nothing should happen.
				err := rt.Apply()
				Expect(err).To(BeNil())
				Expect(dataplane.routeKeyToRoute).To(ConsistOf(cali1Route))
			})
			It(fmt.Sprintf("with a %v failure, then an interface kick, it should sync", failure), func() {
				dataplane.failuresToSimulate = failure
				rt.Apply()

				// Set interface up
				rt.OnIfaceStateChanged("cali1", ifacemonitor.StateUp)
				cali1 = dataplane.addIface(1, "cali1", true, true)

				// Now, the apply should work.
				rt.Apply()
				Expect(dataplane.routeKeyToRoute).To(BeEmpty())
			})
		}
	})
})

var _ = Describe("Tests to verify netlink interface", func() {
	It("Should give expected error for missing interface", func() {
		_, err := netlink.LinkByName("dsfhjakdhfjk")
		Expect(err.Error()).To(ContainSubstring("not found"))
	})
})

func mustParseCIDR(cidr string) *net.IPNet {
	_, c, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())
	return c
}

type failFlags uint32

const (
	failNextLinkList failFlags = 1 << iota
	failNextLinkByName
	failNextLinkByNameNotFound
	failNextRouteList
	failNextRouteAdd
	failNextRouteDel
	failNextAddARP
	failNextNewNetlinkHandle
	failNextSetSocketTimeout
	failNone failFlags = 0
)

var failureScenarios = []failFlags{
	failNone,
	failNextLinkList,
	failNextLinkByName,
	failNextLinkByNameNotFound,
	failNextRouteList,
	failNextRouteAdd,
	failNextRouteDel,
	failNextAddARP,
	failNextNewNetlinkHandle,
	failNextSetSocketTimeout,
}

func (f failFlags) String() string {
	parts := []string{}
	if f&failNextLinkList != 0 {
		parts = append(parts, "failNextLinkList")
	}
	if f&failNextLinkByName != 0 {
		parts = append(parts, "failNextLinkByName")
	}
	if f&failNextLinkByNameNotFound != 0 {
		parts = append(parts, "failNextLinkByNameNotFound")
	}
	if f&failNextRouteList != 0 {
		parts = append(parts, "failNextRouteList")
	}
	if f&failNextRouteAdd != 0 {
		parts = append(parts, "failNextRouteAdd")
	}
	if f&failNextRouteDel != 0 {
		parts = append(parts, "failNextRouteDel")
	}
	if f&failNextAddARP != 0 {
		parts = append(parts, "failNextAddARP")
	}
	if f&failNextNewNetlinkHandle != 0 {
		parts = append(parts, "failNextNewNetlinkHandle")
	}
	if f&failNextSetSocketTimeout != 0 {
		parts = append(parts, "failNextSetSocketTimeout")
	}
	if f == 0 {
		parts = append(parts, "failNone")
	}
	return strings.Join(parts, "|")
}

type mockDataplane struct {
	nameToLink       map[string]netlink.Link
	routeKeyToRoute  map[string]netlink.Route
	addedRouteKeys   set.Set
	deletedRouteKeys set.Set

	NumNewNetlinkCalls int
	NetlinkOpen        bool

	PersistentlyFailToConnect bool

	failuresToSimulate failFlags

	mutex                   sync.Mutex
	deletedConntrackEntries []net.IP
	ConntrackSleep          time.Duration
}

func (d *mockDataplane) addIface(idx int, name string, up bool, running bool) *mockLink {
	flags := net.Flags(0)
	var rawFlags uint32
	if up {
		flags |= net.FlagUp
		rawFlags |= syscall.IFF_UP
	}
	if running {
		rawFlags |= syscall.IFF_RUNNING
	}
	link := &mockLink{
		attrs: netlink.LinkAttrs{
			Name:     name,
			Flags:    flags,
			RawFlags: rawFlags,
			Index:    idx,
		},
	}
	d.nameToLink[name] = link
	return link
}

func (d *mockDataplane) shouldFail(flag failFlags) bool {
	flagPresent := d.failuresToSimulate&flag != 0
	d.failuresToSimulate &^= flag
	if flagPresent {
		log.WithField("flag", flag).Warn("Mock dataplane: triggering failure")
	}
	return flagPresent
}

func (d *mockDataplane) NewNetlinkHandle() (HandleIface, error) {
	d.NumNewNetlinkCalls++
	if d.PersistentlyFailToConnect || d.shouldFail(failNextNewNetlinkHandle) {
		return nil, simulatedError
	}
	Expect(d.NetlinkOpen).To(BeFalse())
	d.NetlinkOpen = true
	return d, nil
}

func (d *mockDataplane) Delete() {
	Expect(d.NetlinkOpen).To(BeTrue())
	d.NetlinkOpen = false
}

func (d *mockDataplane) SetSocketTimeout(to time.Duration) error {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(failNextSetSocketTimeout) {
		return simulatedError
	}
	return nil
}

func (d *mockDataplane) LinkList() ([]netlink.Link, error) {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(failNextLinkList) {
		return nil, simulatedError
	}
	var links []netlink.Link
	for _, link := range d.nameToLink {
		links = append(links, link)
	}
	return links, nil
}

func (d *mockDataplane) LinkByName(name string) (netlink.Link, error) {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(failNextLinkByNameNotFound) {
		return nil, notFound
	}
	if d.shouldFail(failNextLinkByName) {
		return nil, simulatedError
	}
	if link, ok := d.nameToLink[name]; ok {
		return link, nil
	} else {
		return nil, notFound
	}
}

func (d *mockDataplane) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(failNextRouteList) {
		return nil, simulatedError
	}
	var routes []netlink.Route
	for _, route := range d.routeKeyToRoute {
		if route.LinkIndex == link.Attrs().Index {
			routes = append(routes, route)
		}
	}
	return routes, nil
}

func (d *mockDataplane) addMockRoute(route *netlink.Route) {
	key := keyForRoute(route)
	d.routeKeyToRoute[key] = *route
}

func (d *mockDataplane) removeMockRoute(route *netlink.Route) {
	key := keyForRoute(route)
	delete(d.routeKeyToRoute, key)
}

func (d *mockDataplane) RouteAdd(route *netlink.Route) error {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(failNextRouteAdd) {
		return simulatedError
	}
	key := keyForRoute(route)
	log.WithField("routeKey", key).Info("Mock dataplane: RouteAdd called")
	d.addedRouteKeys.Add(key)
	if _, ok := d.routeKeyToRoute[key]; ok {
		return alreadyExists
	} else {
		d.routeKeyToRoute[key] = *route
		return nil
	}
}

func (d *mockDataplane) RouteDel(route *netlink.Route) error {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(failNextRouteDel) {
		return simulatedError
	}
	key := keyForRoute(route)
	log.WithField("routeKey", key).Info("Mock dataplane: RouteDel called")
	d.deletedRouteKeys.Add(key)
	if _, ok := d.routeKeyToRoute[key]; ok {
		delete(d.routeKeyToRoute, key)
		return nil
	} else {
		return nil
	}
}

func (d *mockDataplane) AddStaticArpEntry(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error {
	if d.shouldFail(failNextAddARP) {
		return simulatedError
	}
	log.WithFields(log.Fields{
		"cidr":      cidr,
		"destMac":   destMAC,
		"ifaceName": ifaceName,
	}).Info("Mock dataplane: adding ARP entry")
	return nil
}

func (d *mockDataplane) RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP) {
	log.WithFields(log.Fields{
		"ipVersion": ipVersion,
		"ipAddr":    ipAddr,
		"sleepTime": d.ConntrackSleep,
	}).Info("Mock dataplane: Removing conntrack flows")
	d.mutex.Lock()
	d.deletedConntrackEntries = append(d.deletedConntrackEntries, ipAddr)
	d.mutex.Unlock()
	time.Sleep(d.ConntrackSleep)
}

func (d *mockDataplane) GetDeletedConntrackEntries() []net.IP {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	cpy := make([]net.IP, len(d.deletedConntrackEntries))
	copy(cpy, d.deletedConntrackEntries)
	return cpy
}

func keyForRoute(route *netlink.Route) string {
	key := fmt.Sprintf("%v-%v", route.LinkIndex, route.Dst)
	log.WithField("routeKey", key).Debug("Calculated route key")
	return key
}

type mockLink struct {
	attrs netlink.LinkAttrs
}

func (l *mockLink) Attrs() *netlink.LinkAttrs {
	return &l.attrs
}

func (l *mockLink) Type() string {
	return "not-implemented"
}

type mockTime struct {
	currentTime   time.Time
	autoIncrement time.Duration
}

func (m *mockTime) Now() time.Time {
	t := m.currentTime
	m.incrementTime(m.autoIncrement)
	return t
}
func (m *mockTime) Since(t time.Time) time.Duration {
	return m.Now().Sub(t)
}

func (m *mockTime) setAutoIncrement(t time.Duration) {
	m.autoIncrement = t
}

func (m *mockTime) incrementTime(t time.Duration) {
	m.currentTime = m.currentTime.Add(t)
}
