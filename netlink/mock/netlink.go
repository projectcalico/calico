package mock

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/ip"
	netlinkshim "github.com/projectcalico/felix/netlink"
	"github.com/projectcalico/libcalico-go/lib/set"
)

func NewMockNetlinkDataplane() *MockNetlinkDataplane {
	dp := &MockNetlinkDataplane{
		nameToLink:      map[string]*MockLink{},
		RouteKeyToRoute: map[string]netlink.Route{},
	}
	dp.ResetDeltas()
	return dp
}

// Validate the mock netlink adheres to the netlink interface.
var _ netlinkshim.Netlink = NewMockNetlinkDataplane()

var (
	SimulatedError = errors.New("dummy error")
	NotFound       = errors.New("not found")
	AlreadyExists  = errors.New("already exists")
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
	FailNextLinkDel
	FailNextLinkSetMTU
	FailNextLinkSetUp
	FailNextAddrList
	FailNextAddrAdd
	FailNextAddrDel
	FailNextRuleList
	FailNextRuleAdd
	FailNextRuleDel
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
	if f == 0 {
		parts = append(parts, "FailNone")
	}
	return strings.Join(parts, "|")
}

type MockNetlinkDataplane struct {
	nameToLink   map[string]*MockLink
	AddedLinks   set.Set
	DeletedLinks set.Set
	AddedAddrs   set.Set
	DeletedAddrs set.Set

	RouteKeyToRoute  map[string]netlink.Route
	AddedRouteKeys   set.Set
	DeletedRouteKeys set.Set
	UpdatedRouteKeys set.Set

	NumNewNetlinkCalls int
	NetlinkOpen        bool

	PersistentlyFailToConnect bool

	PersistFailures    bool
	FailuresToSimulate FailFlags

	addedArpEntries set.Set

	mutex                   sync.Mutex
	deletedConntrackEntries []net.IP
	ConntrackSleep          time.Duration
}

func (d *MockNetlinkDataplane) ResetDeltas() {
	d.AddedLinks = set.New()
	d.DeletedLinks = set.New()
	d.AddedAddrs = set.New()
	d.DeletedAddrs = set.New()
	d.AddedRouteKeys = set.New()
	d.DeletedRouteKeys = set.New()
	d.UpdatedRouteKeys = set.New()
	d.addedArpEntries = set.New()
}

func (d *MockNetlinkDataplane) AddIface(idx int, name string, up bool, running bool) *MockLink {
	flags := net.Flags(0)
	var rawFlags uint32
	if up {
		flags |= net.FlagUp
		rawFlags |= syscall.IFF_UP
	}
	if running {
		rawFlags |= syscall.IFF_RUNNING
	}
	link := &MockLink{
		LinkAttrs: netlink.LinkAttrs{
			Name:     name,
			Flags:    flags,
			RawFlags: rawFlags,
			Index:    idx,
		},
	}
	d.nameToLink[name] = link
	return link
}

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

func (d *MockNetlinkDataplane) NewMockNetlink() (netlinkshim.Netlink, error) {
	d.NumNewNetlinkCalls++
	if d.PersistentlyFailToConnect || d.shouldFail(FailNextNewNetlink) {
		return nil, SimulatedError
	}
	Expect(d.NetlinkOpen).To(BeFalse())
	d.NetlinkOpen = true
	return d, nil
}

func (d *MockNetlinkDataplane) Delete() {
	Expect(d.NetlinkOpen).To(BeTrue())
	d.NetlinkOpen = false
}

func (d *MockNetlinkDataplane) SetSocketTimeout(to time.Duration) error {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextSetSocketTimeout) {
		return SimulatedError
	}
	return nil
}

func (d *MockNetlinkDataplane) LinkList() ([]netlink.Link, error) {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkList) {
		return nil, SimulatedError
	}
	var links []netlink.Link
	for _, link := range d.nameToLink {
		links = append(links, link)
	}
	return links, nil
}

func (d *MockNetlinkDataplane) LinkByName(name string) (netlink.Link, error) {
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkByNameNotFound) {
		return nil, NotFound
	}
	if d.shouldFail(FailNextLinkByName) {
		return nil, SimulatedError
	}
	if link, ok := d.nameToLink[name]; ok {
		return link, nil
	}
	return nil, NotFound
}

func (d *MockNetlinkDataplane) LinkAdd(link netlink.Link) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkAdd) {
		return SimulatedError
	}

	if _, ok := d.nameToLink[link.Attrs().Name]; ok {
		return AlreadyExists
	}
	d.nameToLink[link.Attrs().Name] = &MockLink{
		LinkAttrs: *link.Attrs(),
		LinkType:  link.Type(),
	}
	d.AddedLinks.Add(link.Attrs().Name)
	return nil
}

func (d *MockNetlinkDataplane) LinkDel(link netlink.Link) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkDel) {
		return SimulatedError
	}

	if _, ok := d.nameToLink[link.Attrs().Name]; !ok {
		return NotFound
	}

	delete(d.nameToLink, link.Attrs().Name)
	d.DeletedLinks.Add(link.Attrs().Name)
	return nil
}

func (d *MockNetlinkDataplane) LinkSetMTU(link netlink.Link, mtu int) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkSetMTU) {
		return SimulatedError
	}
	if link, ok := d.nameToLink[link.Attrs().Name]; ok {
		link.Attrs().MTU = mtu
		d.nameToLink[link.Attrs().Name] = link
		return nil
	}
	return NotFound
}

func (d *MockNetlinkDataplane) LinkSetUp(link netlink.Link) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextLinkSetUp) {
		return SimulatedError
	}
	if link, ok := d.nameToLink[link.Attrs().Name]; ok {
		link.Attrs().Flags |= net.FlagUp
		link.Attrs().RawFlags |= syscall.IFF_RUNNING
		d.nameToLink[link.Attrs().Name] = link
		return nil
	}
	return NotFound
}

func (d *MockNetlinkDataplane) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextAddrList) {
		return nil, SimulatedError
	}
	if link, ok := d.nameToLink[link.Attrs().Name]; ok {
		return link.Addrs, nil
	}
	return nil, NotFound
}

func (d *MockNetlinkDataplane) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(addr).NotTo(BeNil())
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextAddrAdd) {
		return SimulatedError
	}
	if link, ok := d.nameToLink[link.Attrs().Name]; ok {
		for _, linkaddr := range link.Addrs {
			if linkaddr.Equal(*addr) {
				return AlreadyExists
			}
		}
		d.AddedAddrs.Add(addr.IPNet.String())
		link.Addrs = append(link.Addrs, *addr)
		d.nameToLink[link.Attrs().Name] = link
		return nil
	}

	return NotFound
}

func (d *MockNetlinkDataplane) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(addr).NotTo(BeNil())
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextAddrDel) {
		return SimulatedError
	}
	if link, ok := d.nameToLink[link.Attrs().Name]; ok {
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
		d.nameToLink[link.Attrs().Name] = link
		d.DeletedAddrs.Add(addr.IPNet.String())
		return nil
	}

	return nil
}

func (d *MockNetlinkDataplane) RuleList(family int) ([]netlink.Rule, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextRuleList) {
		return nil, SimulatedError
	}

	return nil, nil
}

func (d *MockNetlinkDataplane) RuleAdd(rule *netlink.Rule) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextRuleAdd) {
		return SimulatedError
	}

	return nil
}

func (d *MockNetlinkDataplane) RuleDel(rule *netlink.Rule) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextRuleDel) {
		return SimulatedError
	}

	return nil
}

func (d *MockNetlinkDataplane) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
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
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextRouteAdd) {
		return SimulatedError
	}
	key := KeyForRoute(route)
	log.WithField("routeKey", key).Info("Mock dataplane: RouteAdd called")
	d.AddedRouteKeys.Add(key)
	if _, ok := d.RouteKeyToRoute[key]; ok {
		return AlreadyExists
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
	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextRouteDel) {
		return SimulatedError
	}
	key := KeyForRoute(route)
	log.WithField("routeKey", key).Info("Mock dataplane: RouteDel called")
	d.DeletedRouteKeys.Add(key)
	// Route was deleted, but is planned on being readded
	if _, ok := d.RouteKeyToRoute[key]; ok {
		delete(d.RouteKeyToRoute, key)
		d.UpdatedRouteKeys.Add(key)
		return nil
	} else {
		return nil
	}
}

func (d *MockNetlinkDataplane) AddStaticArpEntry(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error {
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
	d.deletedConntrackEntries = append(d.deletedConntrackEntries, ipAddr)
	d.mutex.Unlock()
	time.Sleep(d.ConntrackSleep)
}

func (d *MockNetlinkDataplane) GetDeletedConntrackEntries() []net.IP {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	cpy := make([]net.IP, len(d.deletedConntrackEntries))
	copy(cpy, d.deletedConntrackEntries)
	return cpy
}

func KeyForRoute(route *netlink.Route) string {
	table := route.Table
	if table == 0 {
		table = unix.RT_TABLE_MAIN
	}
	key := fmt.Sprintf("%v-%v-%v", table, route.LinkIndex, route.Dst)
	log.WithField("routeKey", key).Debug("Calculated route key")
	return key
}

type MockLink struct {
	LinkAttrs netlink.LinkAttrs
	Addrs     []netlink.Addr
	LinkType  string
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
