package netlink

import (
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

type Netlink interface {
	SetSocketTimeout(to time.Duration) error
	LinkList() ([]netlink.Link, error)
	LinkByName(name string) (netlink.Link, error)
	LinkAdd(link netlink.Link) error
	LinkDel(link netlink.Link) error
	LinkSetMTU(link netlink.Link, mtu int) error
	LinkSetUp(link netlink.Link) error
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
	RouteAdd(route *netlink.Route) error
	RouteDel(route *netlink.Route) error
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
	AddrAdd(link netlink.Link, addr *netlink.Addr) error
	AddrDel(link netlink.Link, addr *netlink.Addr) error
	RuleList(family int) ([]netlink.Rule, error)
	RuleAdd(rule *netlink.Rule) error
	RuleDel(rule *netlink.Rule) error
	Delete()
}

func NewRealNetlink() (Netlink, error) {
	return netlink.NewHandle(syscall.NETLINK_ROUTE)
}
