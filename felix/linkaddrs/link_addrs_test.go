// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linkaddrs

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func init() {
	logrus.SetFormatter(&logutils.Formatter{})
	logrus.SetLevel(logrus.DebugLevel)
}

const (
	v6AddrOSAssigned = "fe80::ecee:eeff:feee:eeee/64"
	v4Addr200        = "169.254.0.200/32"
	v4Addr179        = "169.254.0.179/32"
	v6Addr200        = "fe80::200/128"
	v6Addr179        = "fe80::179/128"
)

func TestLinkAddrMgr_IPV4(t *testing.T) {
	dataplane, mgr := setup(t, 4)

	linkCali := dataplane.AddIface(5, "cali1", true, true)
	linkEth0 := dataplane.AddIface(6, "eth0", true, true)

	nl, err := mgr.nl.Handle()
	Expect(err).NotTo(HaveOccurred())

	// Prepare link addresses.
	err = nl.AddrAdd(linkCali, toNetlinkAddr(v6AddrOSAssigned))
	Expect(err).NotTo(HaveOccurred())
	err = nl.AddrAdd(linkCali, toNetlinkAddr(v4Addr200))
	Expect(err).NotTo(HaveOccurred())
	err = nl.AddrAdd(linkCali, toNetlinkAddr(v6Addr179))
	Expect(err).NotTo(HaveOccurred())

	err = nl.AddrAdd(linkEth0, toNetlinkAddr(v6AddrOSAssigned))
	Expect(err).NotTo(HaveOccurred())
	err = nl.AddrAdd(linkEth0, toNetlinkAddr(v4Addr200))
	Expect(err).NotTo(HaveOccurred())
	err = nl.AddrAdd(linkEth0, toNetlinkAddr(v6Addr179))
	Expect(err).NotTo(HaveOccurred())

	// Set address and apply changes.
	err = mgr.SetLinkLocalAddress("cali1", ip.MustParseCIDROrIP(v4Addr179))
	Expect(err).NotTo(HaveOccurred())
	Expect(mgr.resyncPending).To(BeTrue())
	err = mgr.Apply()
	Expect(err).NotTo(HaveOccurred())

	// With Cali1 interface, v4Addr200 should be replaced by v4Addr179
	addrs := listLinkAddrs(nl, linkCali)
	Expect(addrs).To(ConsistOf(v6AddrOSAssigned, v4Addr179, v6Addr179))

	// No changes on Eth0 interface
	err = mgr.SetLinkLocalAddress("eth0", ip.MustParseCIDROrIP(v4Addr179))
	Expect(err).To(HaveOccurred())
	addrs = listLinkAddrs(nl, linkEth0)
	Expect(addrs).To(ConsistOf(v6AddrOSAssigned, v4Addr200, v6Addr179))

	// Delete address and apply changes.
	mgr.RemoveLinkLocalAddress("cali1")
	err = mgr.Apply()
	Expect(err).NotTo(HaveOccurred())

	// v4 link address removed.
	addrs = listLinkAddrs(nl, linkCali)
	Expect(addrs).To(ConsistOf(v6AddrOSAssigned, v6Addr179))

	// No changes on Eth0 interface.
	addrs = listLinkAddrs(nl, linkEth0)
	Expect(addrs).To(ConsistOf(v6AddrOSAssigned, v4Addr200, v6Addr179))
}

func TestLinkAddrMgr_IPV6(t *testing.T) {
	dataplane, mgr := setup(t, 6)

	linkCali := dataplane.AddIface(5, "cali1", true, true)
	linkEth0 := dataplane.AddIface(6, "eth0", true, true)

	nl, err := mgr.nl.Handle()
	Expect(err).NotTo(HaveOccurred())

	// Prepare link addresses.
	err = nl.AddrAdd(linkCali, toNetlinkAddr(v6AddrOSAssigned))
	Expect(err).NotTo(HaveOccurred())
	err = nl.AddrAdd(linkCali, toNetlinkAddr(v4Addr200))
	Expect(err).NotTo(HaveOccurred())
	err = nl.AddrAdd(linkCali, toNetlinkAddr(v6Addr200))
	Expect(err).NotTo(HaveOccurred())

	err = nl.AddrAdd(linkEth0, toNetlinkAddr(v6AddrOSAssigned))
	Expect(err).NotTo(HaveOccurred())
	err = nl.AddrAdd(linkEth0, toNetlinkAddr(v4Addr200))
	Expect(err).NotTo(HaveOccurred())
	err = nl.AddrAdd(linkEth0, toNetlinkAddr(v6Addr179))
	Expect(err).NotTo(HaveOccurred())

	// Set address and apply changes.
	err = mgr.SetLinkLocalAddress("cali1", ip.MustParseCIDROrIP(v6Addr179))
	Expect(err).NotTo(HaveOccurred())
	Expect(mgr.resyncPending).To(BeTrue())
	err = mgr.Apply()
	Expect(err).NotTo(HaveOccurred())

	// With Cali1 interface, v6Addr200 should be replaced by v6Addr179
	addrs := listLinkAddrs(nl, linkCali)
	Expect(addrs).To(ConsistOf(v6AddrOSAssigned, v4Addr200, v6Addr179))

	// No changes on Eth0 interface
	err = mgr.SetLinkLocalAddress("eth0", ip.MustParseCIDROrIP(v4Addr179))
	Expect(err).To(HaveOccurred())
	addrs = listLinkAddrs(nl, linkEth0)
	Expect(addrs).To(ConsistOf(v6AddrOSAssigned, v4Addr200, v6Addr179))

	// Delete address and apply changes.
	mgr.RemoveLinkLocalAddress("cali1")
	err = mgr.Apply()
	Expect(err).NotTo(HaveOccurred())

	// v4 link address removed.
	addrs = listLinkAddrs(nl, linkCali)
	Expect(addrs).To(ConsistOf(v6AddrOSAssigned, v4Addr200))

	// No changes on Eth0 interface.
	addrs = listLinkAddrs(nl, linkEth0)
	Expect(addrs).To(ConsistOf(v6AddrOSAssigned, v4Addr200, v6Addr179))
}

func toNetlinkAddr(s string) *netlink.Addr {
	net, err := netlink.ParseIPNet(s)
	Expect(err).NotTo(HaveOccurred())
	return &netlink.Addr{IPNet: net}
}

func listLinkAddrs(nl netlinkshim.Interface, link netlink.Link) []string {
	netlinkAddrs, err := nl.AddrList(link, 4)
	Expect(err).NotTo(HaveOccurred())

	addrs := []string{}
	for _, a := range netlinkAddrs {
		addrs = append(addrs, a.IPNet.String())
	}
	return addrs
}

func setup(t *testing.T, family int) (*mocknetlink.MockNetlinkDataplane, *LinkAddrsManager) {
	RegisterTestingT(t)
	logutils.ConfigureLoggingForTestingT(t)

	dataplane := mocknetlink.New()
	m := New(
		family,
		[]string{"cali"},
		&environment.FakeFeatureDetector{
			Features: environment.Features{},
		},
		10*time.Second,
		WithNetlinkHandleShim(dataplane.NewMockNetlink),
	)

	return dataplane, m
}
