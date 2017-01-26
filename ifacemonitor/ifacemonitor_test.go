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
	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/set"
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
	linkUpdates    chan netlink.LinkUpdate
	addrUpdates    chan netlink.AddrUpdate
	userSubscribed chan int

	nextIndex int
	links     map[string]linkModel
}

type addrState struct {
	ifaceName string
	addrs     set.Set
}

type mockDataplane struct {
	linkC chan string
	addrC chan addrState
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
	nl.signalLink(name, 0)
}

func (nl *netlinkTest) changeLinkState(name string, state string) {
	link := nl.links[name]
	link.state = state
	nl.links[name] = link
	nl.signalLink(name, 0)
}

func (nl *netlinkTest) delLink(name string) {
	var oldIndex int
	link, prs := nl.links[name]
	if prs {
		oldIndex = link.index
	} else {
		oldIndex = 0
	}
	delete(nl.links, name)
	nl.signalLink(name, oldIndex)
}

func (nl *netlinkTest) signalLink(name string, oldIndex int) {
	// Values for a link that does not exist...
	index := oldIndex
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
	log.WithField("channel", nl.linkUpdates).Info("Test code signaling a link update")
	nl.linkUpdates <- update
	log.Info("Test code signaled a link update")
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
	log.WithField("channel", nl.linkUpdates).Info("Test code signaling an addr update")
	nl.addrUpdates <- update
	log.Info("Test code signaled an addr update")
}

func (nl *netlinkTest) Subscribe(
	linkUpdates chan netlink.LinkUpdate,
	addrUpdates chan netlink.AddrUpdate,
) error {
	nl.linkUpdates = linkUpdates
	nl.addrUpdates = addrUpdates
	nl.userSubscribed <- 1
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
	log.Info("mock dataplane reported link callback")
}

func (dp *mockDataplane) expectLinkStateCb(ifaceName string) {
	cbIface := <-dp.linkC
	Expect(cbIface).To(Equal(ifaceName))
}

func (dp *mockDataplane) addrStateCallback(ifaceName string, addrs set.Set) {
	log.Info("addrStateCallback: ifaceName=", ifaceName)
	log.Info("addrStateCallback: addrs=", addrs)
	dp.addrC <- addrState{ifaceName: ifaceName, addrs: addrs}
	log.Info("mock dataplane reported address callback")
}

func (dp *mockDataplane) expectAddrStateCb(ifaceName string, addr string, present bool) {
	log.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"addr":      addr,
		"present":   present,
	}).Debug("expectAddrStateCb")
	for {
		cbIface := <-dp.addrC
		log.WithFields(log.Fields{
			"ifaceName": cbIface.ifaceName,
			"addrs":     cbIface.addrs,
		}).Debug("Mock dp got addr cb")
		if cbIface.ifaceName != ifaceName {
			log.Debug("Wrong interface")
			continue
		}
		if (addr == "") && (!present) && (cbIface.addrs != nil) {
			log.Debug("Expected nil addrs, didn't get it")
			continue
		}
		if (addr != "") && (!present) && cbIface.addrs.Contains(addr) {
			log.Debug("Expected addr to be missing, but it's there")
			continue
		}
		if (addr != "") && present && !cbIface.addrs.Contains(addr) {
			log.Debug("Expected addr to be present, but it's missing")
			continue
		}
		break
	}
}

var _ = Describe("ifacemonitor", func() {
	var nl *netlinkTest
	var resyncC chan time.Time
	var im *ifacemonitor.InterfaceMonitor
	var dp *mockDataplane

	BeforeEach(func() {
		// Make an Interface Monitor that uses a test netlink stub implementation and resync
		// trigger channel - both controlled by this code.
		nl = &netlinkTest{userSubscribed: make(chan int)}
		resyncC = make(chan time.Time)
		im = ifacemonitor.NewWithStubs(nl, resyncC)

		// Register this test code's callbacks, which (a) log; and (b) send to a 1- or
		// 2-buffered channel, so that the test code _must_ explicitly indicate when it
		// expects those callbacks to have occurred.  For the link channel a buffer of 1 is
		// enough, because link callbacks only result from link updates from the netlink
		// stub.  For the address channel we sometimes need a buffer of 2 because both link
		// and address updates from the stub can generate address callbacks.
		// expectAddrStateCb takes care to check that we eventually get the callback that we
		// expect.
		dp = &mockDataplane{
			linkC: make(chan string, 1),
			addrC: make(chan addrState, 2),
		}
		im.Callback = dp.linkStateCallback
		im.AddrCallback = dp.addrStateCallback

		// Start the monitor running, and wait until it has subscribed to our test netlink
		// stub.
		go im.MonitorInterfaces()
		<-nl.userSubscribed
	})

	It("should handle mainline netlink updates", func() {
		// Add a link and an address.  No link callback expected because the link is not up
		// yet.  But we do get an address callback because those are independent of link
		// state.  (Note that if the monitor's initial resync runs slowly enough, it might
		// see the new link and addr as part of that resync - whereas normally what happens
		// is that the resync completes as a no-op first, and the addLink causes a
		// notification afterwards.  But either way we expect to get the same callbacks to
		// the dataplane, so we don't need to distinguish between these two possibilities.
		nl.addLink("eth0")
		resyncC <- time.Time{}
		dp.expectAddrStateCb("eth0", "", true)
		nl.addAddr("eth0", "10.0.240.10/24")
		dp.expectAddrStateCb("eth0", "10.0.240.10", true)

		// Set the link up, and expect a link callback.  Addresses are unchanged, so there
		// is no address callback.
		nl.changeLinkState("eth0", "up")
		dp.expectLinkStateCb("eth0")

		// Add an address.
		nl.addAddr("eth0", "172.19.34.1/27")
		dp.expectAddrStateCb("eth0", "172.19.34.1", true)

		// Delete that address.
		nl.delAddr("eth0", "172.19.34.1/27")
		dp.expectAddrStateCb("eth0", "172.19.34.1", false)

		// Add address again.
		nl.addAddr("eth0", "172.19.34.1/27")
		dp.expectAddrStateCb("eth0", "172.19.34.1", true)

		// Delete an address that wasn't actually there - no callback.
		nl.delAddr("eth0", "8.8.8.8/32")

		// Set link down.
		nl.changeLinkState("eth0", "down")
		dp.expectLinkStateCb("eth0")

		// Set link up again.
		nl.changeLinkState("eth0", "up")
		dp.expectLinkStateCb("eth0")

		// Trigger a resync, then immediately delete the link.  What happens is that the
		// test code deletes its state for eth0 before the monitor's resync() calls
		// LinkList, and so the monitor reports "Spotted interface removal on resync" and
		// makes link and address callbacks accordingly.
		resyncC <- time.Time{}
		nl.delLink("eth0")
		dp.expectLinkStateCb("eth0")
		dp.expectAddrStateCb("eth0", "", false)

		// Trigger another resync.  Nothing is expected.  We ensure that the resync
		// processing completes, before exiting from this test, by sending a further resync
		// trigger.  (This would block if the interface monitor's main loop was not yet
		// ready to read it.)
		resyncC <- time.Time{}
		resyncC <- time.Time{}
	})
})
