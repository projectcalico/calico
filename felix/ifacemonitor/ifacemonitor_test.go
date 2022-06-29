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
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/ifacemonitor"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type linkModel struct {
	index int
	state string
	addrs set.Set[string]
}

type netlinkTest struct {
	linkUpdates    chan netlink.LinkUpdate
	routeUpdates   chan netlink.RouteUpdate
	userSubscribed chan int
	cancel         chan struct{}

	nextIndex int
	links     map[string]linkModel

	// Mutex protecting the two items above.  Note that in many cases we unlock as soon as
	// possible after we've read and/or written that data - instead of using defer - because we
	// don't want to hold the mutex when writing to a channel (which is often what happens next
	// in the same function).
	linksMutex  sync.Mutex
	LinkListErr error
}

type addrState struct {
	ifaceName string
	addrs     set.Set[string]
}

type linkUpdate struct {
	name  string
	state ifacemonitor.State
	index int
}

type mockDataplane struct {
	linkC chan linkUpdate
	addrC chan addrState
}

func (nl *netlinkTest) addLink(name string) {
	nl.addLinkNoSignal(name)
	nl.signalLink(name, 0)
}

func (nl *netlinkTest) addLinkNoSignal(name string) {
	log.WithFields(log.Fields{"name": name}).Info("ADDLINK")
	nl.linksMutex.Lock()
	if nl.links == nil {
		nl.links = map[string]linkModel{}
		nl.nextIndex = 10
	}
	nl.links[name] = linkModel{
		index: nl.nextIndex,
		state: "down",
		addrs: set.New[string](),
	}
	nl.nextIndex++
	nl.linksMutex.Unlock()
}

func (nl *netlinkTest) renameLink(oldName, newName string) {
	log.WithFields(log.Fields{"oldName": oldName, "newName": newName}).Info("RENAMELINK")
	nl.linksMutex.Lock()
	link := nl.links[oldName]
	delete(nl.links, oldName)
	nl.links[newName] = link
	nl.linksMutex.Unlock()
	nl.signalLink(newName, 0)
}

func (nl *netlinkTest) changeLinkState(name string, state string) {
	log.WithFields(log.Fields{"name": name, "state": state}).Info("CHANGELINKSTATE")
	nl.linksMutex.Lock()
	link := nl.links[name]
	link.state = state
	nl.links[name] = link
	nl.linksMutex.Unlock()
	nl.signalLink(name, 0)
}

func (nl *netlinkTest) delLink(name string) {
	oldIndex := nl.delLinkNoSignal(name)
	nl.signalLink(name, oldIndex)
}

func (nl *netlinkTest) delLinkNoSignal(name string) (oldIndex int) {
	log.WithFields(log.Fields{"name": name}).Info("DELLINK")
	nl.linksMutex.Lock()
	link, prs := nl.links[name]
	if prs {
		oldIndex = link.index
	} else {
		oldIndex = 0
	}
	delete(nl.links, name)
	nl.linksMutex.Unlock()
	return
}

func (nl *netlinkTest) signalLink(name string, oldIndex int) {
	// Values for a link that does not exist...
	index := oldIndex
	var rawFlags uint32 = 0
	var msgType uint16 = syscall.RTM_DELLINK

	// If the link does exist, overwrite appropriately.
	nl.linksMutex.Lock()
	link, prs := nl.links[name]
	if prs {
		msgType = syscall.RTM_NEWLINK
		index = link.index
		if link.state == "up" {
			rawFlags = syscall.IFF_RUNNING
		}
	}
	nl.linksMutex.Unlock()

	// Build the update.
	update := netlink.LinkUpdate{
		Header: unix.NlMsghdr{
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
	log.WithFields(log.Fields{"name": name, "addr": addr}).Info("ADDADDR")
	nl.linksMutex.Lock()
	link := nl.links[name]
	link.addrs.Add(addr)
	nl.links[name] = link
	nl.linksMutex.Unlock()
	nl.signalAddr(name, addr, true)
}

func (nl *netlinkTest) delAddr(name string, addr string) {
	log.WithFields(log.Fields{"name": name, "addr": addr}).Info("DELADDR")
	nl.linksMutex.Lock()
	link := nl.links[name]
	if link.addrs != nil {
		link.addrs.Discard(addr)
		nl.links[name] = link
	}
	nl.linksMutex.Unlock()
	nl.signalAddr(name, addr, false)
}

func (nl *netlinkTest) signalAddr(name string, addr string, exists bool) {
	// Build the update.
	net, err := netlink.ParseIPNet(addr)
	if err != nil {
		panic("Address parsing failed")
	}
	nl.linksMutex.Lock()

	routeUpd := netlink.RouteUpdate{}
	routeUpd.Dst = net
	routeUpd.Route.Type = unix.RTN_LOCAL
	routeUpd.Table = unix.RT_TABLE_LOCAL
	routeUpd.LinkIndex = nl.links[name].index
	if exists {
		routeUpd.Type = unix.RTM_NEWROUTE
	} else {
		routeUpd.Type = unix.RTM_DELROUTE
	}

	nl.linksMutex.Unlock()

	// Send it.
	log.WithField("channel", nl.linkUpdates).Info("Test code signaling an addr update")
	nl.routeUpdates <- routeUpd
	log.Info("Test code signaled an addr update")
}

func (nl *netlinkTest) Subscribe(
	linkUpdates chan netlink.LinkUpdate,
	routeUpdates chan netlink.RouteUpdate,
) (chan struct{}, error) {
	nl.linkUpdates = linkUpdates
	nl.routeUpdates = routeUpdates
	nl.cancel = make(chan struct{})
	nl.userSubscribed <- 1
	return nl.cancel, nil
}

func (nl *netlinkTest) LinkList() ([]netlink.Link, error) {
	if nl.LinkListErr != nil {
		return nil, nl.LinkListErr
	}

	links := []netlink.Link{}
	nl.linksMutex.Lock()
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
	nl.linksMutex.Unlock()
	return links, nil
}

func (nl *netlinkTest) ListLocalRoutes(link netlink.Link, family int) ([]netlink.Route, error) {
	name := link.Attrs().Name
	nl.linksMutex.Lock()
	defer nl.linksMutex.Unlock()
	model, prs := nl.links[name]
	var routes []netlink.Route
	if prs {
		model.addrs.Iter(func(addr string) error {
			net, err := netlink.ParseIPNet(addr)
			if err != nil {
				panic("Address parsing failed")
			}
			if strings.ContainsRune(addr, ':') {
				if family == netlink.FAMILY_V6 {
					routes = append(routes, netlink.Route{
						Type: unix.RTN_LOCAL,
						Dst:  net,
					})
				}
			} else {
				if family == netlink.FAMILY_V4 {
					routes = append(routes, netlink.Route{
						Type: unix.RTN_LOCAL,
						Dst:  net,
					})
				}
			}
			return nil
		})
	}
	return routes, nil
}

func (nl *netlinkTest) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	name := link.Attrs().Name
	nl.linksMutex.Lock()
	defer nl.linksMutex.Unlock()
	model, prs := nl.links[name]
	addrs := []netlink.Addr{}
	if prs {
		model.addrs.Iter(func(addr string) error {
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

func (dp *mockDataplane) linkStateCallback(ifaceName string, ifaceState ifacemonitor.State, idx int) {
	log.WithFields(log.Fields{"name": ifaceName, "state": ifaceState}).Info("CALLBACK LINK")
	dp.linkC <- linkUpdate{
		name:  ifaceName,
		state: ifaceState,
		index: idx,
	}
	log.Info("mock dataplane reported link callback")
}

func (dp *mockDataplane) expectLinkStateCb(ifaceName string, state ifacemonitor.State, idx int) {
	var upd linkUpdate
	Eventually(dp.linkC).Should(Receive(&upd))
	ExpectWithOffset(1, upd).To(Equal(linkUpdate{
		name:  ifaceName,
		state: state,
		index: idx,
	}), "Received unexpected link state callback.")
}

func (dp *mockDataplane) notExpectLinkStateCb() {
	ConsistentlyWithOffset(1, dp.linkC, "50ms", "5ms").ShouldNot(Receive())
}

func (dp *mockDataplane) addrStateCallback(ifaceName string, addrs set.Set[string]) {
	log.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"addrs":     addrs,
	}).Info("CALLBACK ADDR")
	dp.addrC <- addrState{ifaceName: ifaceName, addrs: addrs}
	log.Info("mock dataplane reported address callback")
}

func (dp *mockDataplane) notExpectAddrStateCb() {
	ConsistentlyWithOffset(1, dp.addrC, "50ms", "5ms").ShouldNot(Receive())
}

func (dp *mockDataplane) expectAddrStateCb(ifaceName string, addr string, present bool) {
	var cbIface addrState
	log.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"addr":      addr,
		"present":   present,
	}).Debug("expectAddrStateCb")

	Eventually(dp.addrC).Should(Receive(&cbIface))
	log.WithFields(log.Fields{
		"ifaceName": cbIface.ifaceName,
		"addrs":     cbIface.addrs,
	}).Debug("Mock dp got addr cb")
	ExpectWithOffset(1, cbIface.ifaceName).To(Equal(ifaceName),
		"Got update for unexpected interface name")
	if (addr == "") && (!present) {
		// Expected to get a nil addrs.
		ExpectWithOffset(1, cbIface.addrs).To(BeNil(), "Expected no addresses")
	}
	if (addr != "") && (!present) && cbIface.addrs != nil {
		// Expected addr to be missing
		ExpectWithOffset(1, cbIface.addrs.Contains(addr)).To(BeFalse(),
			fmt.Sprintf("Expected %v not to contain %v", cbIface.addrs, addr))
	}
	if (addr != "") && present {
		// Expected addr to be present
		ExpectWithOffset(1, cbIface.addrs.Contains(addr)).To(BeTrue(),
			fmt.Sprintf("Expected %v to contain %v", cbIface.addrs, addr))
	}
}

var errFatal = errors.New("fatal error")

var _ = Describe("ifacemonitor", func() {
	var nl *netlinkTest
	var resyncC chan time.Time
	var fatalErrC chan struct{}
	var im *ifacemonitor.InterfaceMonitor
	var dp *mockDataplane

	BeforeEach(func() {
		// Make an Interface Monitor that uses a test netlink stub implementation and resync
		// trigger channel - both controlled by this code.
		nl = &netlinkTest{
			userSubscribed: make(chan int),
			nextIndex:      10,
		}
		resyncC = make(chan time.Time)
		config := ifacemonitor.Config{
			// Test the regexp ability of interface excludes
			InterfaceExcludes: []*regexp.Regexp{
				regexp.MustCompile("^kube-ipvs.*"),
				regexp.MustCompile("^veth1$"),
				regexp.MustCompile("dummy"),
			},
		}
		fatalErrC = make(chan struct{})
		fatalErrCallback := func(err error) {
			log.WithError(err).Info("Fatal error reported")
			close(fatalErrC) // Signal to test code that we saw the fatal error callback.
			panic(errFatal)  // Break out of the MonitorInterfaces goroutine (this panic is recovered below).
		}
		im = ifacemonitor.NewWithStubs(config, nl, resyncC, fatalErrCallback)

		// Register this test code's callbacks, which (a) log; and (b) send to a 1- or
		// 2-buffered channel, so that the test code _must_ explicitly indicate when it
		// expects those callbacks to have occurred.  For the link channel a buffer of 1 is
		// enough, because link callbacks only result from link updates from the netlink
		// stub.  For the address channel we sometimes need a buffer of 2 because both link
		// and address updates from the stub can generate address callbacks.
		// expectAddrStateCb takes care to check that we eventually get the callback that we
		// expect.
		dp = &mockDataplane{
			linkC: make(chan linkUpdate, 1),
			addrC: make(chan addrState, 2),
		}
		im.StateCallback = dp.linkStateCallback
		im.AddrCallback = dp.addrStateCallback
	})

	JustBeforeEach(func() {
		// Start the monitor running, and wait until it has subscribed to our test netlink
		// stub.
		go func() {
			defer GinkgoRecover()
			defer func() {
				v := recover()
				if v == errFatal { // Our expected fatal error.
					return
				}
				panic(v)
			}()
			im.MonitorInterfaces()
		}()
		Eventually(nl.userSubscribed).Should(Receive())
		log.Info("Monitor interfaces subscribed")
	})

	Context("with an error from LinkList", func() {
		BeforeEach(func() {
			nl.LinkListErr = fmt.Errorf("dummy err")
		})

		It("should report a fatal error", func() {
			log.Info("Waiting for fatal error...")
			Eventually(fatalErrC).Should(BeClosed())
		})
	})

	It("should skip netlink address updates for ipvs", func() {
		var netlinkUpdates = func(iface string) {
			// Should not receive any address callbacks.
			idx := nl.nextIndex

			nl.addLink(iface)
			resyncC <- time.Time{}
			dp.notExpectAddrStateCb()
			dp.expectLinkStateCb(iface, ifacemonitor.StateDown, idx)
			nl.addAddr(iface, "10.100.0.1/32")
			dp.notExpectAddrStateCb()

			nl.changeLinkState(iface, "up")
			dp.expectLinkStateCb(iface, ifacemonitor.StateUp, idx)
			nl.changeLinkState(iface, "down")
			dp.expectLinkStateCb(iface, ifacemonitor.StateDown, idx)

			// Should notify not present from up on deletion.
			nl.changeLinkState(iface, "up")
			dp.expectLinkStateCb(iface, ifacemonitor.StateUp, idx)
			nl.delLink(iface)
			dp.notExpectAddrStateCb()
			dp.expectLinkStateCb(iface, ifacemonitor.StateNotPresent, idx)

			// Check it can be added again.
			idx = nl.nextIndex
			nl.addLink(iface)
			resyncC <- time.Time{}
			dp.expectLinkStateCb(iface, ifacemonitor.StateDown, idx)
			dp.notExpectAddrStateCb()

			// Clean it.
			nl.delLink(iface)
			dp.expectLinkStateCb(iface, ifacemonitor.StateNotPresent, idx)
			dp.notExpectAddrStateCb()
		}

		// Repeat for 3 different interfaces (to test regexp of interface excludes)
		for index := 0; index < 3; index++ {
			interfaceName := fmt.Sprintf("kube-ipvs%d", index)
			netlinkUpdates(interfaceName)
		}

		// Repeat test for second interface exclude entry
		netlinkUpdates("veth1")

		// Repeat test for third interface exclude entry
		netlinkUpdates("0dummy1")

		Expect(fatalErrC).ToNot(BeClosed())
	})

	It("should handle mainline netlink updates", func() {
		// Add a link and an address.  No link callback expected because the link is not up
		// yet.  But we do get an address callback because those are independent of link
		// state.  (Note that if the monitor's initial resync runs slowly enough, it might
		// see the new link and addr as part of that resync - whereas normally what happens
		// is that the resync completes as a no-op first, and the addLink causes a
		// notification afterwards.  But either way we expect to get the same callbacks to
		// the dataplane, so we don't need to distinguish between these two possibilities.
		idx := nl.nextIndex
		nl.addLink("eth0")
		resyncC <- time.Time{}
		dp.expectLinkStateCb("eth0", ifacemonitor.StateDown, idx)
		dp.expectAddrStateCb("eth0", "", true)
		nl.addAddr("eth0", "10.0.240.10/24")
		dp.expectAddrStateCb("eth0", "10.0.240.10", true)

		// Set the link up, and expect a link callback.  Addresses are unchanged, so there
		// is no address callback.
		nl.changeLinkState("eth0", "up")
		dp.expectLinkStateCb("eth0", ifacemonitor.StateUp, idx)

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
		dp.expectLinkStateCb("eth0", ifacemonitor.StateDown, idx)

		// Set link up again.
		nl.changeLinkState("eth0", "up")
		dp.expectLinkStateCb("eth0", ifacemonitor.StateUp, idx)

		// Test when a deleted link is detected in a resync.  The monitor should report
		// "Spotted interface removal on resync" and make link and address callbacks
		// accordingly.
		nl.delLinkNoSignal("eth0")
		resyncC <- time.Time{}
		dp.expectLinkStateCb("eth0", ifacemonitor.StateNotPresent, idx)
		dp.expectAddrStateCb("eth0", "", false)

		// Trigger another resync.  Nothing is expected.  We ensure that the resync
		// processing completes, before exiting from this test, by sending a further resync
		// trigger.  (This would block if the interface monitor's main loop was not yet
		// ready to read it.)
		resyncC <- time.Time{}
		resyncC <- time.Time{}

		Expect(fatalErrC).ToNot(BeClosed())
	})

	It("should handle an interface rename", func() {
		defer log.Info("Exiting...")
		// Add a link and an address.  No link callback expected because the link is not up
		// yet.  But we do get an address callback because those are independent of link
		// state.  (Note that if the monitor's initial resync runs slowly enough, it might
		// see the new link and addr as part of that resync - whereas normally what happens
		// is that the resync completes as a no-op first, and the addLink causes a
		// notification afterwards.  But either way we expect to get the same callbacks to
		// the dataplane, so we don't need to distinguish between these two possibilities.
		idx := nl.nextIndex
		nl.addLink("eth0")
		resyncC <- time.Time{}
		dp.expectAddrStateCb("eth0", "", true)
		nl.addAddr("eth0", "10.0.240.10/24")
		dp.expectAddrStateCb("eth0", "10.0.240.10", true)
		dp.expectLinkStateCb("eth0", ifacemonitor.StateDown, idx)

		// Set the link up, and expect a link callback.  Addresses are unchanged, so there
		// is no address callback.
		nl.changeLinkState("eth0", "up")
		dp.expectLinkStateCb("eth0", ifacemonitor.StateUp, idx)

		// Rename the interface, address and old name should be signalled as gone.
		nl.renameLink("eth0", "eth1")
		dp.expectLinkStateCb("eth0", ifacemonitor.StateNotPresent, idx)
		dp.expectAddrStateCb("eth0", "10.0.240.10", false)
		dp.expectLinkStateCb("eth1", ifacemonitor.StateUp, idx)
		dp.expectAddrStateCb("eth1", "10.0.240.10", true)

		// Trigger another resync.  Nothing is expected.  We ensure that the resync
		// processing completes, before exiting from this test, by sending a further resync
		// trigger.  (This would block if the interface monitor's main loop was not yet
		// ready to read it.)
		resyncC <- time.Time{}
		resyncC <- time.Time{}

		Expect(fatalErrC).ToNot(BeClosed())
	})

	It("should handle link flap", func() {
		// Add a link and an address.
		idx := nl.nextIndex
		nl.addLink("eth0")
		resyncC <- time.Time{}
		dp.expectLinkStateCb("eth0", ifacemonitor.StateDown, idx)
		dp.expectAddrStateCb("eth0", "", true)
		nl.addAddr("eth0", "10.0.240.10/24")
		dp.expectAddrStateCb("eth0", "10.0.240.10", true)

		// Set the link up, and expect a link callback.  Addresses are unchanged, so there
		// is no address callback.
		nl.changeLinkState("eth0", "up")
		dp.expectLinkStateCb("eth0", ifacemonitor.StateUp, idx)

		// Delete the link, and have that picked up by resync.  For this scenario we have to
		// assume that there is never any Netlink signal for the link deletion.
		_ = nl.delLinkNoSignal("eth0")
		resyncC <- time.Time{}
		dp.expectLinkStateCb("eth0", ifacemonitor.StateNotPresent, idx)
		dp.expectAddrStateCb("eth0", "", false)

		// Add the link again, with the same ifIndex, but hold the signal through Netlink.
		nl.nextIndex--
		nl.addLinkNoSignal("eth0")
		// Add the address, and let that go through Netlink.
		nl.addAddr("eth0", "10.0.240.10/24")
		// Now signal the link.
		nl.signalLink("eth0", 0)

		// Now we should see an address callback again.
		dp.expectAddrStateCb("eth0", "10.0.240.10", true)

		Expect(fatalErrC).ToNot(BeClosed())
	})

	It("should reconnect to netlink if channel goes down", func() {
		oldCancel := nl.cancel
		close(nl.linkUpdates)
		Eventually(oldCancel).Should(BeClosed())
		Eventually(nl.userSubscribed).Should(Receive())
		Expect(fatalErrC).ToNot(BeClosed())
	})

	It("should report a fatal error if routes channel goes down", func() {
		oldCancel := nl.cancel
		close(nl.routeUpdates)
		Eventually(oldCancel).Should(BeClosed())
		Eventually(nl.userSubscribed).Should(Receive())
		Expect(fatalErrC).ToNot(BeClosed())
	})
})
