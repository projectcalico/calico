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

package mocknetlink

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func New() *MockNetlinkDataplane {
	dp := &MockNetlinkDataplane{
		NameToLink:      map[string]*MockLink{},
		RouteKeyToRoute: map[string]netlink.Route{},
		Rules: []netlink.Rule{
			{
				Priority: 0,
				Table:    255,
			},
			{
				Priority: 32766,
				Table:    254,
			},
			{
				Priority: 32767,
				Table:    253,
			},
		},
	}
	dp.ResetDeltas()
	return dp
}

// Validate the mock netlink adheres to the netlink interface.
var _ netlinkshim.Interface = (*MockNetlinkDataplane)(nil)

var (
	SimulatedError        = errors.New("dummy error")
	NotFoundError         = errors.New("not found")
	FileDoesNotExistError = errors.New("file does not exist")
	AlreadyExistsError    = errors.New("already exists")
	NotSupportedError     = errors.New("operation not supported")
)

type FailFlags uint32

const (
	FailNextLinkList FailFlags = 1 << iota
	FailNextLinkByName
	FailNextLinkByNameNotFound
	FailNextRouteList
	FailNextRouteAdd
	FailNextRouteDel
	FailNextAddARP
	FailNextNewNetlink
	FailNextSetSocketTimeout
	FailNextLinkAdd
	FailNextLinkAddNotSupported
	FailNextLinkDel
	FailNextLinkSetMTU
	FailNextLinkSetUp
	FailNextAddrList
	FailNextAddrAdd
	FailNextAddrDel
	FailNextRuleList
	FailNextRuleAdd
	FailNextRuleDel
	FailNextNewWireguard
	FailNextNewWireguardNotSupported
	FailNextWireguardClose
	FailNextWireguardDeviceByName
	FailNextWireguardConfigureDevice
	FailNone FailFlags = 0
)

var RoutetableFailureScenarios = []FailFlags{
	FailNone,
	FailNextLinkList,
	FailNextLinkByName,
	FailNextLinkByNameNotFound,
	FailNextRouteList,
	FailNextRouteAdd,
	FailNextRouteDel,
	FailNextAddARP,
	FailNextNewNetlink,
	FailNextSetSocketTimeout,
}

func (f FailFlags) String() string {
	parts := []string{}
	if f&FailNextLinkList != 0 {
		parts = append(parts, "FailNextLinkList")
	}
	if f&FailNextLinkByName != 0 {
		parts = append(parts, "FailNextLinkByName")
	}
	if f&FailNextLinkByNameNotFound != 0 {
		parts = append(parts, "FailNextLinkByNameNotFound")
	}
	if f&FailNextRouteList != 0 {
		parts = append(parts, "FailNextRouteList")
	}
	if f&FailNextRouteAdd != 0 {
		parts = append(parts, "FailNextRouteAdd")
	}
	if f&FailNextRouteDel != 0 {
		parts = append(parts, "FailNextRouteDel")
	}
	if f&FailNextAddARP != 0 {
		parts = append(parts, "FailNextAddARP")
	}
	if f&FailNextNewNetlink != 0 {
		parts = append(parts, "FailNextNewNetlink")
	}
	if f&FailNextSetSocketTimeout != 0 {
		parts = append(parts, "FailNextSetSocketTimeout")
	}
	if f&FailNextLinkAdd != 0 {
		parts = append(parts, "FailNextLinkAdd")
	}
	if f&FailNextLinkAddNotSupported != 0 {
		parts = append(parts, "FailNextLinkAddNotSupported")
	}
	if f&FailNextLinkDel != 0 {
		parts = append(parts, "FailNextLinkDel")
	}
	if f&FailNextLinkSetMTU != 0 {
		parts = append(parts, "FailNextLinkSetMTU")
	}
	if f&FailNextLinkSetUp != 0 {
		parts = append(parts, "FailNextLinkSetUp")
	}
	if f&FailNextAddrList != 0 {
		parts = append(parts, "FailNextAddrList")
	}
	if f&FailNextAddrAdd != 0 {
		parts = append(parts, "FailNextAddrAdd")
	}
	if f&FailNextAddrDel != 0 {
		parts = append(parts, "FailNextAddrDel")
	}
	if f&FailNextRuleList != 0 {
		parts = append(parts, "FailNextRuleList")
	}
	if f&FailNextRuleAdd != 0 {
		parts = append(parts, "FailNextRuleAdd")
	}
	if f&FailNextRuleDel != 0 {
		parts = append(parts, "FailNextRuleDel")
	}
	if f&FailNextNewWireguard != 0 {
		parts = append(parts, "FailNextNewWireguard")
	}
	if f&FailNextNewWireguardNotSupported != 0 {
		parts = append(parts, "FailNextNewWireguardNotSupported")
	}
	if f&FailNextWireguardClose != 0 {
		parts = append(parts, "FailNextWireguardClose")
	}
	if f&FailNextWireguardDeviceByName != 0 {
		parts = append(parts, "FailNextWireguardDeviceByName")
	}
	if f&FailNextWireguardConfigureDevice != 0 {
		parts = append(parts, "FailNextWireguardConfigureDevice")
	}
	if f == 0 {
		parts = append(parts, "FailNone")
	}
	return strings.Join(parts, "|")
}

type MockNetlinkDataplane struct {
	NameToLink   map[string]*MockLink
	AddedLinks   set.Set[string]
	DeletedLinks set.Set[string]
	AddedAddrs   set.Set[string]
	DeletedAddrs set.Set[string]

	Rules        []netlink.Rule
	AddedRules   []netlink.Rule
	DeletedRules []netlink.Rule

	RouteKeyToRoute  map[string]netlink.Route
	AddedRouteKeys   set.Set[string]
	DeletedRouteKeys set.Set[string]
	UpdatedRouteKeys set.Set[string]

	NumNewNetlinkCalls     int
	NetlinkOpen            bool
	NumNewWireguardCalls   int
	WireguardOpen          bool
	NumLinkAddCalls        int
	NumLinkDeleteCalls     int
	ImmediateLinkUp        bool
	NumRuleListCalls       int
	NumRuleAddCalls        int
	NumRuleDelCalls        int
	WireguardConfigUpdated bool
	LastWireguardUpdates   map[wgtypes.Key]wgtypes.PeerConfig

	PersistentlyFailToConnect bool

	PersistFailures    bool
	FailuresToSimulate FailFlags

	addedArpEntries set.Set[string]

	mutex                   sync.Mutex
	deletedConntrackEntries set.Set[ip.Addr]
	ConntrackSleep          time.Duration
}

func (d *MockNetlinkDataplane) ResetDeltas() {
	d.AddedLinks = set.New[string]()
	d.DeletedLinks = set.New[string]()
	d.AddedAddrs = set.New[string]()
	d.DeletedAddrs = set.New[string]()
	d.AddedRouteKeys = set.New[string]()
	d.DeletedRouteKeys = set.New[string]()
	d.UpdatedRouteKeys = set.New[string]()
	d.addedArpEntries = set.New[string]()
	d.NumLinkAddCalls = 0
	d.NumLinkDeleteCalls = 0
	d.NumNewNetlinkCalls = 0
	d.NumNewWireguardCalls = 0
	d.NumRuleListCalls = 0
	d.NumRuleAddCalls = 0
	d.NumRuleDelCalls = 0
	d.AddedRules = nil
	d.DeletedRules = nil
	d.WireguardConfigUpdated = false
	d.deletedConntrackEntries = set.NewBoxed[ip.Addr]()
}

// ----- Mock dataplane management functions for test code -----

func (d *MockNetlinkDataplane) GetDeletedConntrackEntries() []net.IP {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	cpy := make([]net.IP, 0, d.deletedConntrackEntries.Len())
	d.deletedConntrackEntries.Iter(func(addr ip.Addr) error {
		cpy = append(cpy, addr.AsNetIP())
		return nil
	})
	return cpy
}

func (d *MockNetlinkDataplane) AddIface(idx int, name string, up bool, running bool) *MockLink {
	t := "unknown"
	if strings.Contains(name, "wireguard") {
		t = "wireguard"
	}
	link := &MockLink{
		LinkAttrs: netlink.LinkAttrs{
			Name:  name,
			Index: idx,
		},
		LinkType: t,
	}
	d.NameToLink[name] = link
	d.SetIface(name, up, running)
	return link
}

func (d *MockNetlinkDataplane) SetIface(name string, up bool, running bool) {
	link, ok := d.NameToLink[name]
	Expect(ok).To(BeTrue())
	if up {
		link.LinkAttrs.Flags |= net.FlagUp
		link.LinkAttrs.RawFlags |= syscall.IFF_UP
	} else {
		link.LinkAttrs.Flags &^= net.FlagUp
		link.LinkAttrs.RawFlags &^= syscall.IFF_UP
	}
	if running {
		link.LinkAttrs.RawFlags |= syscall.IFF_RUNNING
	} else {
		link.LinkAttrs.RawFlags &^= syscall.IFF_RUNNING
	}
}

func (d *MockNetlinkDataplane) NewMockNetlink() (netlinkshim.Interface, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	d.NumNewNetlinkCalls++
	if d.PersistentlyFailToConnect || d.shouldFail(FailNextNewNetlink) {
		return nil, SimulatedError
	}
	Expect(d.NetlinkOpen).To(BeFalse())
	d.NetlinkOpen = true
	return d, nil
}

// ----- Netlink API -----

func (d *MockNetlinkDataplane) Delete() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	d.NetlinkOpen = false
}

func (d *MockNetlinkDataplane) SetSocketTimeout(to time.Duration) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextSetSocketTimeout) {
		return SimulatedError
	}
	return nil
}

func (d *MockNetlinkDataplane) LinkList() ([]netlink.Link, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkList) {
		return nil, SimulatedError
	}
	var links []netlink.Link
	for _, link := range d.NameToLink {
		links = append(links, link)
	}
	return links, nil
}

func (d *MockNetlinkDataplane) LinkByName(name string) (netlink.Link, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkByNameNotFound) {
		return nil, NotFoundError
	}
	if d.shouldFail(FailNextLinkByName) {
		return nil, SimulatedError
	}
	if link, ok := d.NameToLink[name]; ok {
		return link, nil
	}
	return nil, NotFoundError
}

func (d *MockNetlinkDataplane) LinkAdd(link netlink.Link) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	d.NumLinkAddCalls++

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkAdd) {
		return SimulatedError
	}
	if d.shouldFail(FailNextLinkAddNotSupported) {
		return NotSupportedError
	}
	if _, ok := d.NameToLink[link.Attrs().Name]; ok {
		return AlreadyExistsError
	}
	attrs := *link.Attrs()
	attrs.Index = 100 + d.NumLinkAddCalls
	d.NameToLink[link.Attrs().Name] = &MockLink{
		LinkAttrs: attrs,
		LinkType:  link.Type(),
	}
	d.AddedLinks.Add(link.Attrs().Name)
	return nil
}

func (d *MockNetlinkDataplane) LinkDel(link netlink.Link) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	d.NumLinkDeleteCalls++

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkDel) {
		return SimulatedError
	}

	if _, ok := d.NameToLink[link.Attrs().Name]; !ok {
		return NotFoundError
	}

	delete(d.NameToLink, link.Attrs().Name)
	d.DeletedLinks.Add(link.Attrs().Name)
	return nil
}

func (d *MockNetlinkDataplane) LinkSetMTU(link netlink.Link, mtu int) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkSetMTU) {
		return SimulatedError
	}
	if link, ok := d.NameToLink[link.Attrs().Name]; ok {
		link.LinkAttrs.MTU = mtu
		d.NameToLink[link.Attrs().Name] = link
		return nil
	}
	return NotFoundError
}

func (d *MockNetlinkDataplane) LinkSetUp(link netlink.Link) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkSetUp) {
		return SimulatedError
	}
	if link, ok := d.NameToLink[link.Attrs().Name]; ok {
		if d.ImmediateLinkUp {
			link.LinkAttrs.Flags |= net.FlagUp
		}
		link.LinkAttrs.RawFlags |= syscall.IFF_RUNNING
		d.NameToLink[link.Attrs().Name] = link
		return nil
	}
	return NotFoundError
}

func (d *MockNetlinkDataplane) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextAddrList) {
		return nil, SimulatedError
	}
	if link, ok := d.NameToLink[link.Attrs().Name]; ok {
		return link.Addrs, nil
	}
	return nil, NotFoundError
}

func (d *MockNetlinkDataplane) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(addr).NotTo(BeNil())
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextAddrAdd) {
		return SimulatedError
	}
	if link, ok := d.NameToLink[link.Attrs().Name]; ok {
		for _, linkaddr := range link.Addrs {
			if linkaddr.Equal(*addr) {
				return AlreadyExistsError
			}
		}
		d.AddedAddrs.Add(addr.IPNet.String())
		link.Addrs = append(link.Addrs, *addr)
		d.NameToLink[link.Attrs().Name] = link
		return nil
	}

	return NotFoundError
}

func (d *MockNetlinkDataplane) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(addr).NotTo(BeNil())
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextAddrDel) {
		return SimulatedError
	}
	if link, ok := d.NameToLink[link.Attrs().Name]; ok {
		newIdx := 0
		for idx, linkaddr := range link.Addrs {
			if linkaddr.Equal(*addr) {
				continue
			}
			link.Addrs[newIdx] = link.Addrs[idx]
			newIdx++
		}
		Expect(newIdx).To(Equal(len(link.Addrs) - 1))
		link.Addrs = link.Addrs[:newIdx]
		d.NameToLink[link.Attrs().Name] = link
		d.DeletedAddrs.Add(addr.IPNet.String())
		return nil
	}

	return nil
}

func (d *MockNetlinkDataplane) RuleList(family int) ([]netlink.Rule, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	d.NumRuleListCalls++
	if d.shouldFail(FailNextRuleList) {
		return nil, SimulatedError
	}

	return d.Rules, nil
}

func (d *MockNetlinkDataplane) RuleAdd(rule *netlink.Rule) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	d.NumRuleAddCalls++
	if d.shouldFail(FailNextRuleAdd) {
		return SimulatedError
	}

	for _, existing := range d.Rules {
		if reflect.DeepEqual(existing, *rule) {
			return AlreadyExistsError
		}
	}

	d.Rules = append(d.Rules, *rule)
	d.AddedRules = append(d.AddedRules, *rule)
	return nil
}

func (d *MockNetlinkDataplane) RuleDel(rule *netlink.Rule) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	d.NumRuleDelCalls++
	if d.shouldFail(FailNextRuleDel) {
		return SimulatedError
	}

	var offset int
	for idx, existing := range d.Rules {
		log.Debugf("Compare rule %#v against %#v", existing, *rule)
		if reflect.DeepEqual(existing, *rule) {
			offset++
			continue
		}
		if offset > 0 {
			d.Rules[idx-offset] = d.Rules[idx]
		}
	}
	if offset == 0 {
		return NotFoundError
	}
	d.Rules = d.Rules[:len(d.Rules)-offset]
	d.DeletedRules = append(d.DeletedRules, *rule)

	return nil
}

func (d *MockNetlinkDataplane) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextRouteList) {
		return nil, SimulatedError
	}
	var routes []netlink.Route
	for _, route := range d.RouteKeyToRoute {
		log.Debugf("Maybe include route: %v", route)
		if filter != nil && filterMask&netlink.RT_FILTER_OIF != 0 && route.LinkIndex != filter.LinkIndex {
			// Filtering by interface and link indices do not match.
			log.Debug("Does not match link")
			continue
		}
		if route.Table == 0 {
			// Mimic the kernel - the route table will be filled in.
			route.Table = unix.RT_TABLE_MAIN
		}
		if (filter == nil || filterMask&netlink.RT_FILTER_TABLE == 0) && route.Table != unix.RT_TABLE_MAIN {
			// Not filtering by table and does not match main table.
			log.Debug("Does not match main table")
			continue
		}
		if filter != nil && filterMask&netlink.RT_FILTER_TABLE != 0 && route.Table != filter.Table {
			// Filtering by table and table indices do not match.
			log.Debugf("Does not match table %d", filter.Table)
			continue
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func (d *MockNetlinkDataplane) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	panic("NOT IMPLEMENETED")
}

func (_ *MockNetlinkDataplane) Close() {
	panic("NOT IMPLEMENETED")
}

func (d *MockNetlinkDataplane) AddMockRoute(route *netlink.Route) {
	key := KeyForRoute(route)
	r := *route
	if r.Table == unix.RT_TABLE_MAIN {
		// Store the main table with index 0 for simplicity with comparisons.
		r.Table = 0
	}
	d.RouteKeyToRoute[key] = r
}

func (d *MockNetlinkDataplane) RemoveMockRoute(route *netlink.Route) {
	key := KeyForRoute(route)
	delete(d.RouteKeyToRoute, key)
}

func (d *MockNetlinkDataplane) RouteAdd(route *netlink.Route) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextRouteAdd) {
		return SimulatedError
	}
	key := KeyForRoute(route)
	log.WithField("routeKey", key).Info("Mock dataplane: RouteUpdate called")
	d.AddedRouteKeys.Add(key)
	if _, ok := d.RouteKeyToRoute[key]; ok {
		return AlreadyExistsError
	} else {
		r := *route
		if r.Table == unix.RT_TABLE_MAIN {
			// Store main table routes with 0 index for simplicity of comparison.
			r.Table = 0
		}
		d.RouteKeyToRoute[key] = r
		return nil
	}
}

func (d *MockNetlinkDataplane) RouteDel(route *netlink.Route) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextRouteDel) {
		return SimulatedError
	}
	key := KeyForRoute(route)
	log.WithField("routeKey", key).Info("Mock dataplane: RouteDel called")
	d.DeletedRouteKeys.Add(key)
	// Route was deleted, but is planned on being re-added
	if _, ok := d.RouteKeyToRoute[key]; ok {
		delete(d.RouteKeyToRoute, key)
		d.UpdatedRouteKeys.Add(key)
		return nil
	} else {
		return nil
	}
}

// ----- Routetable specific ARP and Conntrack functions -----

func (d *MockNetlinkDataplane) AddStaticArpEntry(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	if d.shouldFail(FailNextAddARP) {
		return SimulatedError
	}
	log.WithFields(log.Fields{
		"cidr":      cidr,
		"destMac":   destMAC,
		"ifaceName": ifaceName,
	}).Info("Mock dataplane: adding ARP entry")
	d.addedArpEntries.Add(getArpKey(cidr, destMAC, ifaceName))
	return nil
}

func (d *MockNetlinkDataplane) HasStaticArpEntry(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) bool {
	return d.addedArpEntries.Contains(getArpKey(cidr, destMAC, ifaceName))
}

func (d *MockNetlinkDataplane) RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP) {
	log.WithFields(log.Fields{
		"ipVersion": ipVersion,
		"ipAddr":    ipAddr,
		"sleepTime": d.ConntrackSleep,
	}).Info("Mock dataplane: Removing conntrack flows")
	d.mutex.Lock()
	d.deletedConntrackEntries.Add(ip.FromNetIP(ipAddr))
	d.mutex.Unlock()
	time.Sleep(d.ConntrackSleep)
}

func (d *MockNetlinkDataplane) NeighAdd(neigh *netlink.Neigh) error {
	return nil
}

// ----- Internals -----

func (d *MockNetlinkDataplane) shouldFail(flag FailFlags) bool {
	flagPresent := d.FailuresToSimulate&flag != 0
	if !d.PersistFailures {
		d.FailuresToSimulate &^= flag
	}
	if flagPresent {
		log.WithField("flag", flag).Warn("Mock dataplane: triggering failure")
	}
	return flagPresent
}

func KeyForRoute(route *netlink.Route) string {
	table := route.Table
	if table == 0 {
		table = unix.RT_TABLE_MAIN
	}
	key := fmt.Sprintf("%v-%v", table, route.Dst)
	log.WithField("routeKey", key).Debug("Calculated route key")
	return key
}

type MockLink struct {
	LinkAttrs netlink.LinkAttrs
	Addrs     []netlink.Addr
	LinkType  string

	WireguardPrivateKey   wgtypes.Key
	WireguardPublicKey    wgtypes.Key
	WireguardListenPort   int
	WireguardFirewallMark int
	WireguardPeers        map[wgtypes.Key]wgtypes.Peer
}

func (l *MockLink) Attrs() *netlink.LinkAttrs {
	return &l.LinkAttrs
}

func (l *MockLink) Type() string {
	return l.LinkType
}

func getArpKey(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) string {
	return cidr.String() + ":" + destMAC.String() + ":" + ifaceName
}
