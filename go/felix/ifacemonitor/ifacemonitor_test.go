// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
	"strings"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/ifacemonitor"
	"github.com/projectcalico/felix/go/felix/set"
	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type linkModel struct {
	index int
	state string
	addrs set.Set
}

type netlinkTest struct {
	linkUpdates chan netlink.LinkUpdate
	addrUpdates chan netlink.AddrUpdate

	nextIndex int
	links     map[string]linkModel
}

type mockDataplane struct {
	linkC chan string
	addrC chan string
}

func (nl *netlinkTest) addLink(name string) {
	if nl.links == nil {
		nl.links = map[string]linkModel{}
		nl.nextIndex = 10
	}
	nl.links[name] = linkModel{
		index: nl.nextIndex,
		state: "down",
		addrs: set.New(),
	}
	nl.nextIndex++
	nl.signalLink(name)
}

func (nl *netlinkTest) changeLinkState(name string, state string) {
	link := nl.links[name]
	link.state = state
	nl.links[name] = link
	nl.signalLink(name)
}

func (nl *netlinkTest) delLink(name string) {
	delete(nl.links, name)
	nl.signalLink(name)
}

func (nl *netlinkTest) signalLink(name string) {
	// Values for a link that does not exist...
	index := 0
	var rawFlags uint32 = 0
	var msgType uint16 = syscall.RTM_DELLINK

	// If the link does exist, overwrite appropriately.
	link, prs := nl.links[name]
	if prs {
		msgType = syscall.RTM_NEWLINK
		index = link.index
		if link.state == "up" {
			rawFlags = syscall.IFF_RUNNING
		}
	}

	// Build the update.
	update := netlink.LinkUpdate{
		Header: syscall.NlMsghdr{
			Type: msgType,
		},
		Link: &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name:     name,
				Index:    index,
				RawFlags: rawFlags,
			},
		},
	}

	// Send it.
	log.Info("Test code signaling a link update")
	nl.linkUpdates <- update
}

func (nl *netlinkTest) addAddr(name string, addr string) {
	link := nl.links[name]
	link.addrs.Add(addr)
	nl.links[name] = link
	nl.signalAddr(name, addr, true)
}

func (nl *netlinkTest) delAddr(name string, addr string) {
	link := nl.links[name]
	link.addrs.Discard(addr)
	nl.links[name] = link
	nl.signalAddr(name, addr, false)
}

func (nl *netlinkTest) signalAddr(name string, addr string, exists bool) {
	// Build the update.
	net, err := netlink.ParseIPNet(addr)
	if err != nil {
		panic("Address parsing failed")
	}
	update := netlink.AddrUpdate{
		LinkIndex:   nl.links[name].index,
		NewAddr:     exists,
		LinkAddress: *net,
	}

	// Send it.
	log.Info("Test code signaling an addr update")
	nl.addrUpdates <- update
}

func (nl *netlinkTest) Subscribe(
	linkUpdates chan netlink.LinkUpdate,
	addrUpdates chan netlink.AddrUpdate,
) error {
	nl.linkUpdates = linkUpdates
	nl.addrUpdates = addrUpdates
	return nil
}

func (nl *netlinkTest) LinkList() ([]netlink.Link, error) {
	links := []netlink.Link{}
	for name, link := range nl.links {
		var rawFlags uint32 = 0
		if link.state == "up" {
			rawFlags = syscall.IFF_RUNNING
		}
		links = append(links, &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name:     name,
				Index:    link.index,
				RawFlags: rawFlags,
			},
		})
	}
	return links, nil
}

func (nl *netlinkTest) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	name := link.Attrs().Name
	model, prs := nl.links[name]
	addrs := []netlink.Addr{}
	if prs {
		model.addrs.Iter(func(item interface{}) error {
			addr := item.(string)
			net, err := netlink.ParseIPNet(addr)
			if err != nil {
				panic("Address parsing failed")
			}
			if strings.ContainsRune(addr, ':') {
				if family == netlink.FAMILY_V6 {
					addrs = append(addrs, netlink.Addr{
						IPNet: net,
					})
				}
			} else {
				if family == netlink.FAMILY_V4 {
					addrs = append(addrs, netlink.Addr{
						IPNet: net,
					})
				}
			}
			return nil
		})
	}
	return addrs, nil
}

func (dp *mockDataplane) linkStateCallback(ifaceName string, ifaceState ifacemonitor.State) {
	log.Info("linkStateCallback: ifaceName=", ifaceName)
	log.Info("linkStateCallback: ifaceState=", ifaceState)
	dp.linkC <- ifaceName
}

func (dp *mockDataplane) expectLinkStateCb(ifaceName string) {
	cbIface := <-dp.linkC
	Expect(cbIface).To(Equal(ifaceName))
}

func (dp *mockDataplane) addrStateCallback(ifaceName string, addrs set.Set) {
	log.Info("addrStateCallback: ifaceName=", ifaceName)
	log.Info("addrStateCallback: addrs=", addrs)
	dp.addrC <- ifaceName
}

func (dp *mockDataplane) expectAddrStateCb(ifaceName string) {
	cbIface := <-dp.addrC
	Expect(cbIface).To(Equal(ifaceName))
}

var _ = Describe("ifacemonitor", func() {
	It("New", func() {

		// Make an Interface Monitor that uses a test netlink
		// stub implementation and resync trigger channel -
		// both controlled by this code.
		nl := &netlinkTest{}
		resyncC := make(chan time.Time)
		im := ifacemonitor.NewWithStubs(nl, resyncC)

		// Register this test code's callbacks, which (a) log;
		// and (b) send to a 1-buffered channel, so that the
		// test code _must_ explicitly indicate when it
		// expects those callbacks to have occurred.
		dp := &mockDataplane{
			linkC: make(chan string, 1),
			addrC: make(chan string, 1),
		}
		im.Callback = dp.linkStateCallback
		im.AddrCallback = dp.addrStateCallback

		// Start the monitor running, and give it time for its
		// initial resync (which will be a no-op) before we
		// start adding link state.
		go im.MonitorInterfaces()
		time.Sleep(10 * time.Millisecond)

		// Add a link and an address.  No link callback
		// expected because the link is not up yet.  But we do
		// get an address callback because those are
		// independent of link state.
		nl.addLink("eth0")
		nl.addAddr("eth0", "10.0.240.10/24")
		dp.expectAddrStateCb("eth0")

		// Set the link up, and expect a link callback.
		// Addresses are unchanged, so there is no address
		// callback.
		nl.changeLinkState("eth0", "up")
		dp.expectLinkStateCb("eth0")

		// Add an address.
		nl.addAddr("eth0", "172.19.34.1/27")
		dp.expectAddrStateCb("eth0")

		// Delete that address.
		nl.delAddr("eth0", "172.19.34.1/27")
		dp.expectAddrStateCb("eth0")

		// Add address again.
		nl.addAddr("eth0", "172.19.34.1/27")
		dp.expectAddrStateCb("eth0")

		// Delete an address that wasn't actually there - no callback.
		nl.delAddr("eth0", "8.8.8.8/32")

		// Set link down.
		nl.changeLinkState("eth0", "down")
		dp.expectLinkStateCb("eth0")

		// Set link up again.
		nl.changeLinkState("eth0", "up")
		dp.expectLinkStateCb("eth0")

		// Trigger a resync, then immediately delete the link.
		// What happens is that the test code deletes its
		// state for eth0 before the monitor's resync() calls
		// LinkList, and so the monitor reports "Spotted
		// interface removal on resync" and makes link and
		// address callbacks accordingly.
		resyncC <- time.Time{}
		nl.delLink("eth0")
		dp.expectLinkStateCb("eth0")
		dp.expectAddrStateCb("eth0")

		// Trigger another resync.  Nothing is expected.  We
		// ensure that the resync processing completes, before
		// exiting from this test, by sending a further resync
		// trigger.  (This would block if the interface
		// monitor's main loop was not yet ready to read it.)
		resyncC <- time.Time{}
		resyncC <- time.Time{}
	})
})
