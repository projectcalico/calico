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

var linkC = make(chan string, 1)

func linkStateCallback(ifaceName string, ifaceState ifacemonitor.State) {
	log.Info("linkStateCallback: ifaceName=", ifaceName)
	log.Info("linkStateCallback: ifaceState=", ifaceState)
	linkC <- ifaceName
}

func expectLinkStateCb(ifaceName string) {
	cbIface := <-linkC
	Expect(cbIface).To(Equal(ifaceName))
}

var addrC = make(chan string, 1)

func addrStateCallback(ifaceName string, addrs set.Set) {
	log.Info("addrStateCallback: ifaceName=", ifaceName)
	log.Info("addrStateCallback: addrs=", addrs)
	addrC <- ifaceName
}

func expectAddrStateCb(ifaceName string) {
	cbIface := <-addrC
	Expect(cbIface).To(Equal(ifaceName))
}

var _ = Describe("ifacemonitor", func() {
	It("New", func() {
		nl := &netlinkTest{}
		resyncC := make(chan time.Time)
		im := ifacemonitor.NewWithStubs(nl, resyncC)
		im.Callback = linkStateCallback
		im.AddrCallback = addrStateCallback
		go im.MonitorInterfaces()
		time.Sleep(10 * time.Millisecond)
		nl.addLink("eth0")
		nl.addAddr("eth0", "10.0.240.10/24")
		nl.changeLinkState("eth0", "up")
		expectLinkStateCb("eth0")
		expectAddrStateCb("eth0")
		nl.addAddr("eth0", "172.19.34.1/27")
		expectAddrStateCb("eth0")
		nl.delAddr("eth0", "172.19.34.1/27")
		expectAddrStateCb("eth0")
		nl.addAddr("eth0", "172.19.34.1/27")
		expectAddrStateCb("eth0")
		nl.delAddr("eth0", "8.8.8.8/32")
		nl.changeLinkState("eth0", "down")
		expectAddrStateCb("eth0")
		expectLinkStateCb("eth0")
		nl.changeLinkState("eth0", "up")
		expectLinkStateCb("eth0")
		expectAddrStateCb("eth0")
		// Allow a resync.
		resyncC <- time.Time{}
		nl.delLink("eth0")
		expectLinkStateCb("eth0")
		expectAddrStateCb("eth0")
		// Allow a resync.
		resyncC <- time.Time{}
	})
})
