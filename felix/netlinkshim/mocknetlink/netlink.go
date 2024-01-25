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
	"unsafe"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var globalMutex sync.Mutex

func New() *MockNetlinkDataplane {
	dp := &MockNetlinkDataplane{
		ExistingTables:  set.From(unix.RT_TABLE_MAIN, 253, 255),
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
		SetStrictCheckErr: SimulatedError,
		NeighsByFamily:    map[int]map[NeighKey]*netlink.Neigh{},

		// Use a single global mutex.  This works around an issue in the wireguard tests, which use multiple
		// mock dataplanes to hand to different parts of the code under test.  That led to concurrency bugs
		// where one dataplane modified another dataplane's object without holding the right lock.
		mutex: &globalMutex,
	}
	dp.ResetDeltas()
	dp.AddIface(1, "lo", true, true)
	return dp
}

// Validate the mock netlink adheres to the netlink interface.
var _ netlinkshim.Interface = (*MockNetlinkDataplane)(nil)

var (
	SimulatedError        = errors.New("dummy error")
	NotFoundError         = errors.New("not found")
	LinkNotFoundError     = netlink.LinkNotFoundError{}
	FileDoesNotExistError = errors.New("file does not exist")
	AlreadyExistsError    = errors.New("already exists")
	NotSupportedError     = errors.New("operation not supported")
)

func init() {
	// Ugh, the error field isn't exported and logging out the error
	// panics if the error field isn't set.  Use an unsafe cast to
	// set the value.

	// Copy of the netlink.LinkNotFoundError struct.
	type myLinkNotFoundError struct {
		error
	}

	// First check that our struct matches the netlink one...
	nlType := reflect.TypeOf(LinkNotFoundError)
	ourType := reflect.TypeOf(myLinkNotFoundError{})
	if nlType.NumField() != ourType.NumField() {
		panic("netlink.LinkNotFoundError structure appears to have changed (different number of fields)")
	}
	for i := 0; i < ourType.NumField(); i++ {
		nlFieldType := nlType.Field(i).Type
		ourFieldType := ourType.Field(i).Type
		if nlFieldType != ourFieldType {
			panic(fmt.Sprintf("netlink.LinkNotFoundError structure appears to have changed (field type %v != %v)",
				nlFieldType, ourType.Field(i).Type))
		}
	}

	// All good, proceed with the sketchy cast...
	var lnf = (*myLinkNotFoundError)((unsafe.Pointer)(&LinkNotFoundError))
	lnf.error = NotFoundError
}

type FailFlags uint32

const (
	FailNextLinkList FailFlags = 1 << iota
	FailNextLinkByName
	FailNextLinkByNameNotFound
	FailNextRouteList
	FailNextRouteAddOrReplace
	FailNextRouteAdd
	FailNextRouteReplace
	FailNextRouteDel
	FailNextAddARP
	FailNextNeighSet
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
	FailNextSetStrict
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
	FailNextSetStrict,
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
	if f&FailNextRouteAddOrReplace != 0 {
		parts = append(parts, "FailNextRouteAddOrReplace")
	}
	if f&FailNextRouteReplace != 0 {
		parts = append(parts, "FailNextRouteReplace")
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
	if f&FailNextSetStrict != 0 {
		parts = append(parts, "FailNextSetStrict")
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

	ExistingTables   set.Set[int]
	RouteKeyToRoute  map[string]netlink.Route
	AddedRouteKeys   set.Set[string]
	DeletedRouteKeys set.Set[string]
	UpdatedRouteKeys set.Set[string]

	NeighsByFamily map[int]map[NeighKey]*netlink.Neigh

	StrictEnabled               bool
	NumNewNetlinkCalls          int
	NetlinkOpen                 bool
	NumNewWireguardCalls        int
	WireguardOpen               bool
	NumLinkAddCalls             int
	NumLinkDeleteCalls          int
	ImmediateLinkUp             bool
	NumRuleListCalls            int
	NumRuleAddCalls             int
	NumRuleDelCalls             int
	WireguardConfigUpdated      bool
	HitRouteListFilteredNoDev   bool
	HitRouteListFilteredNoTable bool
	LastWireguardUpdates        map[wgtypes.Key]wgtypes.PeerConfig

	PersistentlyFailToConnect bool

	PersistFailures                bool
	FailuresToSimulate             FailFlags
	SetStrictCheckErr              error
	DeleteInterfaceAfterLinkByName bool

	addedArpEntries set.Set[string]

	mutex                   *sync.Mutex
	deletedConntrackEntries set.Set[ip.Addr]
	ConntrackSleep          time.Duration
}

type NeighKey struct {
	MAC string
	IP  ip.Addr
}

func (d *MockNetlinkDataplane) FeatureGate(name string) string {
	return ""
}

func (d *MockNetlinkDataplane) RefreshFeatures() {
}

func (d *MockNetlinkDataplane) GetFeatures() *environment.Features {
	return &environment.Features{
		KernelSideRouteFiltering: true,
	}
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
	d.deletedConntrackEntries = set.New[ip.Addr]()
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
	if idx == 0 {
		panic("0 is not a valid ifindex")
	}
	if idx == 1 && name != "lo" {
		panic("1 is always 'lo'")
	}
	t := "unknown"
	if strings.Contains(name, "wireguard") {
		t = "wireguard"
	}
	la := netlink.NewLinkAttrs()
	la.Name = name
	la.Index = idx
	link := &MockLink{
		LinkAttrs: la,
		LinkType:  t,
	}
	for otherName, link := range d.NameToLink {
		if link.LinkAttrs.Index == idx {
			Fail(fmt.Sprintf("ifindex %d already in use by %s, cannot add %s", idx, otherName, name))
		}
	}
	d.NameToLink[name] = link
	d.SetIface(name, up, running)
	return link.copy()
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

func (d *MockNetlinkDataplane) SetStrictCheck(b bool) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextSetStrict) {
		return d.SetStrictCheckErr
	}
	d.StrictEnabled = b
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
		links = append(links, link.copy())
	}
	return links, nil
}

func (d *MockNetlinkDataplane) LinkByName(name string) (netlink.Link, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkByNameNotFound) {
		return nil, LinkNotFoundError
	}
	if d.shouldFail(FailNextLinkByName) {
		return nil, SimulatedError
	}
	if d.DeleteInterfaceAfterLinkByName {
		defer delete(d.NameToLink, name)
	}
	if link, ok := d.NameToLink[name]; ok {
		return link.copy(), nil
	}
	return nil, LinkNotFoundError
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
		return LinkNotFoundError
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
	return LinkNotFoundError
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
	return LinkNotFoundError
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

	if d.StrictEnabled {
		// If strict mode is enabled, the kernel behaves differently in a few respects:
		// - It does kernel side route filtering.  This is why we enable strict mode.
		// - It returns errors in more cases: if the device we filter on doesn't exist or if the routing table
		//   doesn't exist.
		//
		// netlink library note: the netlink library does kernel-side filtering for all non-default fields
		// in the filter route, so it's right that we don't condition on filterMask for this part of the check.

		// Check if the filter's table exists.
		if filter.Table != 0 && !d.ExistingTables.Contains(filter.Table) {
			// No routing table gives ENOENT.
			d.HitRouteListFilteredNoTable = true
			return nil, unix.ENOENT
		}

		// Check if the link exists.
		if filter.LinkIndex != 0 {
			found := false
			for _, l := range d.NameToLink {
				if l.LinkAttrs.Index == filter.LinkIndex {
					found = true
					break
				}
			}
			if !found {
				d.HitRouteListFilteredNoDev = true
				return nil, unix.ENODEV
			}
		}

		{
			filterCopy := *filter
			filterCopy.Table = 0
			filterCopy.LinkIndex = 0
			Expect(filterCopy).To(Equal(netlink.Route{}), fmt.Sprintf(
				"filter route uses fields that mock doesn't understand: %+v", filterCopy))
		}
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

func (d *MockNetlinkDataplane) AddMockRoute(route *netlink.Route) {
	key := KeyForRoute(route)
	r := *route
	d.ExistingTables.Add(r.Table)
	if r.Table == 0 {
		// Table 0 is "unspecified", which gets defaulted to the main table.
		r.Table = unix.RT_TABLE_MAIN
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
	if d.shouldFail(FailNextRouteAdd) || d.shouldFail(FailNextRouteAddOrReplace) {
		return SimulatedError
	}
	key := KeyForRoute(route)
	log.WithField("routeKey", key).Info("Mock dataplane: RouteUpdate called")
	d.AddedRouteKeys.Add(key)
	d.ExistingTables.Add(route.Table)
	if _, ok := d.RouteKeyToRoute[key]; ok {
		return AlreadyExistsError
	} else {
		r := *route
		if r.Table == 0 {
			// Table 0 is "unspecified", which gets defaulted to the main table.
			r.Table = unix.RT_TABLE_MAIN
		}
		d.RouteKeyToRoute[key] = r
		return nil
	}
}

func (d *MockNetlinkDataplane) RouteReplace(route *netlink.Route) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	defer GinkgoRecover()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextRouteReplace) || d.shouldFail(FailNextRouteAddOrReplace) {
		return SimulatedError
	}
	key := KeyForRoute(route)
	log.WithField("routeKey", key).Info("Mock dataplane: RouteReplace called")
	d.AddedRouteKeys.Add(key)
	d.ExistingTables.Add(route.Table)
	if _, ok := d.RouteKeyToRoute[key]; ok {
		d.UpdatedRouteKeys.Add(key)
	} else {
		d.AddedRouteKeys.Add(key)
	}
	r := *route
	if r.Table == 0 {
		// Table 0 is "unspecified", which gets defaulted to the main table.
		r.Table = unix.RT_TABLE_MAIN
	}
	d.RouteKeyToRoute[key] = r
	return nil
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

func (d *MockNetlinkDataplane) NeighAdd(neigh *netlink.Neigh) error {
	family := neigh.Family
	err := d.checkNeighFamily(family)
	if err != nil {
		return err
	}

	if d.NeighsByFamily[family] == nil {
		d.NeighsByFamily[family] = map[NeighKey]*netlink.Neigh{}
	}
	if neigh.IP == nil {
		return unix.EINVAL
	}
	if neigh.HardwareAddr == nil {
		return unix.EINVAL
	}
	nk := NeighKey{
		MAC: neigh.HardwareAddr.String(),
		IP:  ip.FromNetIP(neigh.IP),
	}

	if _, ok := d.NeighsByFamily[family][nk]; ok {
		return unix.EEXIST
	}
	d.NeighsByFamily[family][nk] = neigh
	return nil
}

func (d *MockNetlinkDataplane) checkNeighFamily(family int) error {
	switch family {
	case unix.AF_INET, unix.AF_INET6, unix.AF_BRIDGE:
	// Supported
	default:
		return fmt.Errorf("unsupported family, should be AF_INET/INET6/BRIDGE")
	}
	return nil
}

func (d *MockNetlinkDataplane) NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	err := d.checkNeighFamily(family)
	if err != nil {
		return nil, err
	}
	var res []netlink.Neigh
	for _, n := range d.NeighsByFamily[family] {
		if linkIndex == 0 || n.LinkIndex == linkIndex {
			res = append(res, *n)
		}
	}
	return res, nil
}

func (d *MockNetlinkDataplane) NeighSet(neigh *netlink.Neigh) error {
	family := neigh.Family
	err := d.checkNeighFamily(family)
	if err != nil {
		return err
	}
	if d.shouldFail(FailNextNeighSet) {
		return SimulatedError
	}

	if d.NeighsByFamily[family] == nil {
		d.NeighsByFamily[family] = map[NeighKey]*netlink.Neigh{}
	}
	if neigh.IP == nil {
		return unix.EINVAL
	}
	if neigh.HardwareAddr == nil {
		return unix.EINVAL
	}
	nk := NeighKey{
		MAC: neigh.HardwareAddr.String(),
		IP:  ip.FromNetIP(neigh.IP),
	}

	d.NeighsByFamily[family][nk] = neigh
	return nil
}

func (d *MockNetlinkDataplane) NeighDel(neigh *netlink.Neigh) error {
	family := neigh.Family
	err := d.checkNeighFamily(family)
	if err != nil {
		return err
	}

	if d.NeighsByFamily[family] == nil {
		d.NeighsByFamily[family] = map[NeighKey]*netlink.Neigh{}
	}
	if neigh.IP == nil {
		return unix.EINVAL
	}
	if neigh.HardwareAddr == nil {
		return unix.EINVAL
	}
	nk := NeighKey{
		MAC: neigh.HardwareAddr.String(),
		IP:  ip.FromNetIP(neigh.IP),
	}

	if _, ok := d.NeighsByFamily[family][nk]; !ok {
		return unix.ENOENT
	}
	delete(d.NeighsByFamily[family], nk)
	return nil
}

// ----- Routetable specific Conntrack functions -----

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

	if d.NeighsByFamily[unix.AF_INET] == nil {
		d.NeighsByFamily[unix.AF_INET] = map[NeighKey]*netlink.Neigh{}
	}

	linkIndex := d.NameToLink[ifaceName].LinkAttrs.Index
	d.NeighsByFamily[unix.AF_INET][NeighKey{
		MAC: destMAC.String(),
		IP:  cidr.Addr(),
	}] = &netlink.Neigh{
		Family:       unix.AF_INET,
		LinkIndex:    linkIndex,
		State:        netlink.NUD_PERMANENT,
		Type:         unix.RTN_UNICAST,
		IP:           cidr.Addr().AsNetIP(),
		HardwareAddr: destMAC,
	}
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

func (d *MockNetlinkDataplane) IfIndex(name string) int {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return d.NameToLink[name].LinkAttrs.Index
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

func (l *MockLink) copy() *MockLink {
	var addrsCopy []netlink.Addr
	if l.Addrs != nil {
		addrsCopy = append(addrsCopy, l.Addrs...)
	}

	// Need to deep copy the map to avoid concurrent access.
	var wgPeersCopy map[wgtypes.Key]wgtypes.Peer
	if l.WireguardPeers != nil {
		wgPeersCopy = map[wgtypes.Key]wgtypes.Peer{}
		for k, v := range l.WireguardPeers {
			wgPeersCopy[k] = v
		}
	}

	return &MockLink{
		LinkAttrs: l.LinkAttrs, // Shallow copy, but we don't use the nested pointers AFAICT.
		Addrs:     addrsCopy,
		LinkType:  l.LinkType,

		WireguardPrivateKey:   l.WireguardPrivateKey,
		WireguardPublicKey:    l.WireguardPublicKey,
		WireguardListenPort:   l.WireguardListenPort,
		WireguardFirewallMark: l.WireguardFirewallMark,
		WireguardPeers:        wgPeersCopy,
	}
}

func getArpKey(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) string {
	return cidr.String() + ":" + destMAC.String() + ":" + ifaceName
}
