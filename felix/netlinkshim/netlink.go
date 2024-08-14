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

package netlinkshim

import (
	"errors"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type Interface interface {
	SetSocketTimeout(to time.Duration) error
	SetStrictCheck(b bool) error
	LinkList() ([]netlink.Link, error)
	LinkByName(name string) (netlink.Link, error)
	LinkAdd(link netlink.Link) error
	LinkDel(link netlink.Link) error
	LinkSetMTU(link netlink.Link, mtu int) error
	LinkSetUp(link netlink.Link) error
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
	RouteAdd(route *netlink.Route) error
	RouteReplace(route *netlink.Route) error
	RouteDel(route *netlink.Route) error
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
	AddrAdd(link netlink.Link, addr *netlink.Addr) error
	AddrDel(link netlink.Link, addr *netlink.Addr) error
	RuleList(family int) ([]netlink.Rule, error)
	RuleAdd(rule *netlink.Rule) error
	RuleDel(rule *netlink.Rule) error
	Delete()
	NeighAdd(neigh *netlink.Neigh) error
	NeighList(linkIndex, family int) ([]netlink.Neigh, error)
	NeighSet(a *netlink.Neigh) error
	NeighDel(a *netlink.Neigh) error
}

type RealNetlink struct {
	nlHandle *netlink.Handle
}

func NewRealNetlink() (Interface, error) {
	nlHandle, err := netlink.NewHandle(syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	return &RealNetlink{
		nlHandle: nlHandle,
	}, nil
}

func (r *RealNetlink) SetSocketTimeout(to time.Duration) error {
	return r.nlHandle.SetSocketTimeout(to)
}

func (r *RealNetlink) SetStrictCheck(b bool) error {
	return r.nlHandle.SetStrictCheck(b)
}

func (r *RealNetlink) LinkList() ([]netlink.Link, error) {
	retries := 3
	for {
		links, err := r.nlHandle.LinkList()
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				retries--
				continue
			}
		}
		return links, err
	}
}

func (r *RealNetlink) LinkByName(name string) (netlink.Link, error) {
	return r.nlHandle.LinkByName(name)
}

func (r *RealNetlink) LinkAdd(link netlink.Link) error {
	return r.nlHandle.LinkAdd(link)
}

func (r *RealNetlink) LinkDel(link netlink.Link) error {
	return r.nlHandle.LinkDel(link)
}

func (r *RealNetlink) LinkSetMTU(link netlink.Link, mtu int) error {
	return r.nlHandle.LinkSetMTU(link, mtu)
}

func (r *RealNetlink) LinkSetUp(link netlink.Link) error {
	return r.nlHandle.LinkSetUp(link)
}

func (r *RealNetlink) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	retries := 3
	for {
		routes, err := r.nlHandle.RouteListFiltered(family, filter, filterMask)
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				retries--
				continue
			}
		}
		return routes, err
	}
}

func (r *RealNetlink) RouteAdd(route *netlink.Route) error {
	return r.nlHandle.RouteAdd(route)
}

func (r *RealNetlink) RouteReplace(route *netlink.Route) error {
	return r.nlHandle.RouteReplace(route)
}

func (r *RealNetlink) RouteDel(route *netlink.Route) error {
	return r.nlHandle.RouteDel(route)
}

func (r *RealNetlink) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	retries := 3
	for {
		addrs, err := r.nlHandle.AddrList(link, family)
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				retries--
				continue
			}
		}
		return addrs, err
	}
}

func (r *RealNetlink) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	return r.nlHandle.AddrAdd(link, addr)
}

func (r *RealNetlink) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	return r.nlHandle.AddrDel(link, addr)
}

func (r *RealNetlink) RuleList(family int) ([]netlink.Rule, error) {
	retries := 3
	for {
		rules, err := r.nlHandle.RuleList(family)
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				retries--
				continue
			}
		}
		return rules, err
	}
}

func (r *RealNetlink) RuleAdd(rule *netlink.Rule) error {
	return r.nlHandle.RuleAdd(rule)
}

func (r *RealNetlink) RuleDel(rule *netlink.Rule) error {
	return r.nlHandle.RuleDel(rule)
}

func (r *RealNetlink) Delete() {
	//nolint:staticcheck
	r.nlHandle.Delete()
}

func (r *RealNetlink) NeighAdd(neigh *netlink.Neigh) error {
	return r.nlHandle.NeighAdd(neigh)
}

func (r *RealNetlink) NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	retries := 3
	for {
		neighs, err := r.nlHandle.NeighList(linkIndex, family)
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				retries--
				continue
			}
		}
		return neighs, err
	}
}

func (r *RealNetlink) NeighSet(a *netlink.Neigh) error {
	return r.nlHandle.NeighSet(a)
}

func (r *RealNetlink) NeighDel(a *netlink.Neigh) error {
	return r.nlHandle.NeighDel(a)
}
