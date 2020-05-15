// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/time/mock"
)

func TestUpdateFilter_FilterUpdates_LinkUpdatePassThru(t *testing.T) {
	t.Log("Link updates should be passed through if there's nothing in the queue")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	linkUpd := linkUpdateWithIndex(2)
	harness.LinkIn <- linkUpd
	Eventually(harness.LinkOut).Should(Receive(Equal(linkUpd)))
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

func TestUpdateFilter_FilterUpdates_AddrUpdatePassThru(t *testing.T) {
	t.Log("Addr ADD updates should be passed through if there's nothing in the queue")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	addrUpd := addrUpdate("10.0.0.1/16", true, 2)
	harness.AddrIn <- addrUpd
	Eventually(harness.AddrOut, "50ms").Should(Receive(Equal(addrUpd)))
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

func TestUpdateFilter_FilterUpdates_AddrUpdateSquash(t *testing.T) {
	t.Log("After a DEL, an ADD and a link updateate should be delayed.")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	// This DEL will cause the iface 2 queue to block.
	addrDel := addrUpdate("10.0.0.1/16", false, 2)
	harness.AddrIn <- addrDel

	// This DEL will be squashed by the following ADD.
	addrDel2 := addrUpdate("10.0.0.2/16", false, 2)
	harness.AddrIn <- addrDel2
	addrAdd2 := addrUpdate("10.0.0.2/16", true, 2)
	harness.AddrIn <- addrAdd2

	// But this ADD on a different interface should go through without delay.
	// (Waiting for this makes sure that the filter has pulled the other items
	// off the channel, avoiding a race in the test.)
	addrAdd3 := addrUpdate("10.0.0.3/16", true, 3)
	harness.AddrIn <- addrAdd3

	t.Log("Should get the unblocked ADD first.")
	Eventually(harness.AddrOut, "10ms", "1us").Should(Receive(Equal(addrAdd3)))

	// Now we know the other addr updates have been processed, this link update should get queued.
	linkUpd := linkUpdateWithIndex(2)
	harness.LinkIn <- linkUpd
	// Need to let the filter receive the above update before we can advance time.
	Consistently(harness.LinkOut, "10ms", "1us").ShouldNot(Receive())

	t.Log("Shouldn't get any output after 99ms.")
	harness.Time.IncrementTime(99 * time.Millisecond)
	Consistently(harness.AddrOut, "10ms", "1us").ShouldNot(Receive())
	Consistently(harness.LinkOut, "10ms", "1us").ShouldNot(Receive())

	t.Log("DEL should be dropped, should get the ADD and the link update after 100ms.")
	harness.Time.IncrementTime(1 * time.Millisecond)
	Eventually(harness.AddrOut, "10ms", "1us").Should(Receive(Equal(addrDel)))
	Eventually(harness.AddrOut, "10ms", "1us").Should(Receive(Equal(addrAdd2)))
	Eventually(harness.LinkOut, "10ms", "1us").Should(Receive(Equal(linkUpd)))
	Consistently(harness.AddrOut, "10ms", "1us").ShouldNot(Receive())
	Consistently(harness.LinkOut, "10ms", "1us").ShouldNot(Receive())
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

func TestUpdateFilter_FilterUpdates_MultipleIPs(t *testing.T) {
	t.Log("Multiple IP updates should get queued.")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	// This DEL will block the following messages from being delivered.
	addrDel := addrUpdate("10.0.0.1/16", false, 2)
	harness.AddrIn <- addrDel
	addrAdd := addrUpdate("10.0.0.2/16", true, 2)
	harness.AddrIn <- addrAdd

	// But this ADD on a different interface should go through without delay.
	// (Waiting for this makes sure that the filter has pulled the other items
	// off the channel, avoiding a race in the test.)
	addrAdd2 := addrUpdate("10.0.0.3/16", true, 3)
	harness.AddrIn <- addrAdd2

	t.Log("Should get the second ADD first.")
	Eventually(harness.AddrOut, "10ms", "1us").Should(Receive(Equal(addrAdd2)))

	t.Log("Updates should come through after 100ms.")
	harness.Time.IncrementTime(100 * time.Millisecond)
	Eventually(harness.AddrOut, "10ms", "1us").Should(Receive(Equal(addrDel)))
	Eventually(harness.AddrOut, "10ms", "1us").Should(Receive(Equal(addrAdd)))
	Consistently(harness.AddrOut, "10ms", "1us").ShouldNot(Receive())
	Consistently(harness.LinkOut, "10ms", "1us").ShouldNot(Receive())
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

func TestUpdateFilter_FilterUpdates_MultipleIPsWithSquash(t *testing.T) {
	t.Log("Multiple IP updates should get queued.")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	// This DEL will block the following messages from being delivered.
	addrDelTenOne := addrUpdate("10.0.0.1/16", false, 2)
	harness.AddrIn <- addrDelTenOne
	addrAddTenTwo := addrUpdate("10.0.0.2/16", true, 2)
	harness.AddrIn <- addrAddTenTwo
	// This ADD should squash the earlier DEL for this IP.
	addrAddTenOne := addrUpdate("10.0.0.1/16", true, 2)
	harness.AddrIn <- addrAddTenOne

	// But this ADD on a different interface should go through without delay.
	// (Waiting for this makes sure that the filter has pulled the other items
	// off the channel, avoiding a race in the test.)
	addrAddTenThree := addrUpdate("10.0.0.3/16", true, 3)
	harness.AddrIn <- addrAddTenThree

	t.Log("Should get the second ADD first.")
	Eventually(harness.AddrOut, "10ms", "1us").Should(Receive(Equal(addrAddTenThree)))

	t.Log("Updates should come through after 100ms.")
	harness.Time.IncrementTime(100 * time.Millisecond)
	Eventually(harness.AddrOut, "10ms", "1us").Should(Receive(Equal(addrAddTenTwo)))
	Eventually(harness.AddrOut, "10ms", "1us").Should(Receive(Equal(addrAddTenOne)))
	Consistently(harness.AddrOut, "10ms", "1us").ShouldNot(Receive())
	Consistently(harness.LinkOut, "10ms", "1us").ShouldNot(Receive())
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

func TestUpdateFilter_FilterUpdates_AddrUpdateDelOnly(t *testing.T) {
	t.Log("Addr DEL followed by an ADD should be delayed and coalesced")
	harness, cancel := setUpFilterTest(t)
	defer cancel()

	addrDel := addrUpdate("10.0.0.1/16", false, 2)
	// This DEL will be queued.
	harness.AddrIn <- addrDel

	// But this ADD on a different interface should go through without delay.
	// (Waiting for this makes sure that the filter has pulled the other items
	// off the channel, avoiding a race in the test.)
	addrAdd2 := addrUpdate("10.0.0.2/16", true, 3)
	harness.AddrIn <- addrAdd2

	t.Log("Should get the second ADD first.")
	Eventually(harness.AddrOut, "10ms", "1us").Should(Receive(Equal(addrAdd2)))

	t.Log("Shouldn't get any output after 99ms.")
	harness.Time.IncrementTime(99 * time.Millisecond)
	Consistently(harness.AddrOut, "10ms", "1us").ShouldNot(Receive())

	t.Log("Should get only the DEL after 100ms.")
	harness.Time.IncrementTime(1 * time.Millisecond)
	Eventually(harness.AddrOut, "10ms", "1us").Should(Receive(Equal(addrDel)))
	Consistently(harness.AddrOut, "10ms", "1us").ShouldNot(Receive())
	Expect(harness.Time.HasTimers()).To(BeFalse(), "Should be no timers left at end of test")
}

type filterUpdatesHarness struct {
	Time *mock.MockTime

	Ctx    context.Context
	Cancel context.CancelFunc

	LinkIn  chan netlink.LinkUpdate
	LinkOut chan netlink.LinkUpdate
	AddrIn  chan netlink.AddrUpdate
	AddrOut chan netlink.AddrUpdate
}

func setUpFilterTest(t *testing.T) (*filterUpdatesHarness, context.CancelFunc) {
	RegisterTestingT(t)
	mockTime := mock.NewMockTime()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	linkIn := make(chan netlink.LinkUpdate, 10)
	addrIn := make(chan netlink.AddrUpdate, 10)
	linkOut := make(chan netlink.LinkUpdate, 10)
	addrOut := make(chan netlink.AddrUpdate, 10)

	go ifacemonitor.FilterUpdates(ctx, addrOut, addrIn, linkOut, linkIn, ifacemonitor.WithTimeShim(mockTime))
	return &filterUpdatesHarness{
		Ctx:    ctx,
		Cancel: cancel,
		Time:   mockTime,

		LinkIn:  linkIn,
		LinkOut: linkOut,
		AddrIn:  addrIn,
		AddrOut: addrOut,
	}, cancel
}

func addrUpdate(cidrStr string, up bool, ifaceIdx int) netlink.AddrUpdate {
	ip, cidr, _ := net.ParseCIDR(cidrStr)
	cidr.IP = ip.To4()
	addrUpd := netlink.AddrUpdate{
		LinkAddress: *cidr,
		LinkIndex:   ifaceIdx,
		NewAddr:     up,
	}
	return addrUpd
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
