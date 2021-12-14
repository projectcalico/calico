// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

package ifacemonitor_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
)

const (
	chanPollTime  = "10ms"
	chanPollIntvl = "100us"
)

func TestUpdateFilter_FilterUpdates_LinkCClosed(t *testing.T) {
	t.Log("Link channel closure should be propagated to output channel")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	close(harness.LinkIn)
	Eventually(harness.LinkOut, chanPollTime, chanPollIntvl).Should(BeClosed())
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(BeClosed())
}

func TestUpdateFilter_FilterUpdates_RouteCClosed(t *testing.T) {
	t.Log("Link channel closure should be propagated to output channel")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	close(harness.RouteIn)
	Eventually(harness.LinkOut, chanPollTime, chanPollIntvl).Should(BeClosed())
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(BeClosed())
}

func TestUpdateFilter_FilterUpdates_LinkUpdateDelay(t *testing.T) {
	t.Log("Link updates should be delayed")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	linkUpd := linkUpdateWithIndex(2)
	harness.LinkIn <- linkUpd
	Consistently(harness.LinkOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())
	harness.Time.IncrementTime(100 * time.Millisecond)

	Eventually(harness.LinkOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(linkUpd)))
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

func TestUpdateFilter_FilterUpdates_RouteUpdatePassThru(t *testing.T) {
	t.Log("Route ADD updates should be passed through if there's nothing in the queue")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	routeUpd := routeUpdate("10.0.0.1/16", true, 2)
	harness.RouteIn <- routeUpd
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(routeUpd)))
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

func TestUpdateFilter_FilterUpdates_RouteUpdateSquash(t *testing.T) {
	t.Log("After a DEL, an ADD and a link update should be delayed.")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	// This DEL will cause the iface 2 queue to block.
	routeDel := routeUpdate("10.0.0.1/16", false, 2)
	harness.RouteIn <- routeDel

	// This DEL will be squashed by the following ADD.
	routeDel2 := routeUpdate("10.0.0.2/16", false, 2)
	harness.RouteIn <- routeDel2
	routeAdd2 := routeUpdate("10.0.0.2/16", true, 2)
	harness.RouteIn <- routeAdd2

	// But this ADD on a different interface should go through without delay.
	// (Waiting for this makes sure that the filter has pulled the other items
	// off the channel, avoiding a race in the test.)
	routeAdd3 := routeUpdate("10.0.0.3/16", true, 3)
	harness.RouteIn <- routeAdd3

	t.Log("Should get the unblocked ADD first.")
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(routeAdd3)))

	// Now we know the other route updates have been processed, this link update should get queued.
	linkUpd := linkUpdateWithIndex(2)
	harness.LinkIn <- linkUpd
	// Need to let the filter receive the above update before we can advance time.
	Consistently(harness.LinkOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())

	t.Log("Shouldn't get any output after 99ms.")
	harness.Time.IncrementTime(99 * time.Millisecond)
	Consistently(harness.RouteOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())
	Consistently(harness.LinkOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())

	t.Log("DEL should be dropped, should get the ADD and the link update after 100ms.")
	harness.Time.IncrementTime(1 * time.Millisecond)
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(routeDel)))
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(routeAdd2)))
	Eventually(harness.LinkOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(linkUpd)))
	Consistently(harness.RouteOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())
	Consistently(harness.LinkOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

func TestUpdateFilter_FilterUpdates_MultipleIPs(t *testing.T) {
	t.Log("Multiple IP updates should get queued.")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	// This DEL will block the following messages from being delivered.
	routeDel := routeUpdate("10.0.0.1/16", false, 2)
	harness.RouteIn <- routeDel
	routeAdd := routeUpdate("10.0.0.2/16", true, 2)
	harness.RouteIn <- routeAdd

	// But this ADD on a different interface should go through without delay.
	// (Waiting for this makes sure that the filter has pulled the other items
	// off the channel, avoiding a race in the test.)
	routeAdd2 := routeUpdate("10.0.0.3/16", true, 3)
	harness.RouteIn <- routeAdd2

	t.Log("Should get the second ADD first.")
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(routeAdd2)))

	t.Log("Updates should come through after 100ms.")
	harness.Time.IncrementTime(100 * time.Millisecond)
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(routeDel)))
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(routeAdd)))
	Consistently(harness.RouteOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())
	Consistently(harness.LinkOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

func TestUpdateFilter_FilterUpdates_Broadcast(t *testing.T) {
	t.Log("Broadcast IPs should be ignored.")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	broadRouteUpd := routeUpdate("10.0.0.255/16", true, 2)
	harness.RouteIn <- broadRouteUpd
	harness.Time.IncrementTime(100 * time.Millisecond)
	Consistently(harness.RouteOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())

	routeUpd := routeUpdate("10.0.0.1/16", true, 2)
	harness.RouteIn <- routeUpd
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(routeUpd)))
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

func TestUpdateFilter_FilterUpdates_MultipleIPsWithSquash(t *testing.T) {
	t.Log("Multiple IP updates should get queued.")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	// This DEL will block the following messages from being delivered.
	addrDelTenOne := routeUpdate("10.0.0.1/16", false, 2)
	harness.RouteIn <- addrDelTenOne
	addrAddTenTwo := routeUpdate("10.0.0.2/16", true, 2)
	harness.RouteIn <- addrAddTenTwo
	// This ADD should squash the earlier DEL for this IP.
	addrAddTenOne := routeUpdate("10.0.0.1/16", true, 2)
	harness.RouteIn <- addrAddTenOne

	// But this ADD on a different interface should go through without delay.
	// (Waiting for this makes sure that the filter has pulled the other items
	// off the channel, avoiding a race in the test.)
	addrAddTenThree := routeUpdate("10.0.0.3/16", true, 3)
	harness.RouteIn <- addrAddTenThree

	t.Log("Should get the second ADD first.")
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(addrAddTenThree)))

	t.Log("Updates should come through after 100ms.")
	harness.Time.IncrementTime(100 * time.Millisecond)
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(addrAddTenTwo)))
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(addrAddTenOne)))
	Consistently(harness.RouteOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())
	Consistently(harness.LinkOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

func TestUpdateFilter_FilterUpdates_RouteUpdateDelOnly(t *testing.T) {
	t.Log("Route DEL followed by an ADD should be delayed and coalesced")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	routeDel := routeUpdate("10.0.0.1/16", false, 2)
	// This DEL will be queued.
	harness.RouteIn <- routeDel

	// But this ADD on a different interface should go through without delay.
	// (Waiting for this makes sure that the filter has pulled the other items
	// off the channel, avoiding a race in the test.)
	routeAdd2 := routeUpdate("10.0.0.2/16", true, 3)
	harness.RouteIn <- routeAdd2

	t.Log("Should get the second ADD first.")
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(routeAdd2)))

	t.Log("Shouldn't get any output after 99ms.")
	harness.Time.IncrementTime(99 * time.Millisecond)
	Consistently(harness.RouteOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())

	t.Log("Should get only the DEL after 100ms.")
	harness.Time.IncrementTime(1 * time.Millisecond)
	Eventually(harness.RouteOut, chanPollTime, chanPollIntvl).Should(Receive(Equal(routeDel)))
	Consistently(harness.RouteOut, chanPollTime, chanPollIntvl).ShouldNot(Receive())
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

type filterUpdatesHarness struct {
	Time *mocktime.MockTime

	Ctx    context.Context
	Cancel context.CancelFunc

	LinkIn   chan netlink.LinkUpdate
	LinkOut  chan netlink.LinkUpdate
	RouteIn  chan netlink.RouteUpdate
	RouteOut chan netlink.RouteUpdate
}

func setUpFilterTest(t *testing.T) (*filterUpdatesHarness, context.CancelFunc) {
	RegisterTestingT(t)
	mockTime := mocktime.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	linkIn := make(chan netlink.LinkUpdate, 10)
	routeIn := make(chan netlink.RouteUpdate, 10)
	linkOut := make(chan netlink.LinkUpdate, 10)
	routeOut := make(chan netlink.RouteUpdate, 10)

	go ifacemonitor.FilterUpdates(ctx, routeOut, routeIn, linkOut, linkIn, ifacemonitor.WithTimeShim(mockTime))
	return &filterUpdatesHarness{
		Ctx:    ctx,
		Cancel: cancel,
		Time:   mockTime,

		LinkIn:   linkIn,
		LinkOut:  linkOut,
		RouteIn:  routeIn,
		RouteOut: routeOut,
	}, cancel
}

func routeUpdate(cidrStr string, up bool, ifaceIdx int) netlink.RouteUpdate {
	ip, cidr, _ := net.ParseCIDR(cidrStr)
	cidr.IP = ip.To4()
	routeUpd := netlink.RouteUpdate{}
	routeUpd.Dst = cidr
	if strings.Contains(cidrStr, ".255") {
		routeUpd.Route.Type = unix.RTN_BROADCAST
	} else {
		routeUpd.Route.Type = unix.RTN_LOCAL
	}
	routeUpd.LinkIndex = ifaceIdx
	if up {
		routeUpd.Type = unix.RTM_NEWROUTE
	} else {
		routeUpd.Type = unix.RTM_DELROUTE
	}
	return routeUpd
}

func linkUpdateWithIndex(idx int) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		Link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{
			Index: idx,
		},
		},
		IfInfomsg: nl.IfInfomsg{
			IfInfomsg: unix.IfInfomsg{
				Index: int32(idx),
			},
		},
	}
}
