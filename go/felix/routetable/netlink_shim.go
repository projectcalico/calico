// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package routetable

import (
	. "github.com/vishvananda/netlink"
)

type netlinkIface interface {
	LinkList() ([]Link, error)
	LinkByName(name string) (Link, error)
	RouteList(link Link, family int) ([]Route, error)
	RouteAdd(route *Route) error
	RouteDel(route *Route) error
}

type realNetlink struct{}

func (r realNetlink) LinkList() ([]Link, error) {
	return LinkList()
}

func (r realNetlink) LinkByName(name string) (Link, error) {
	return LinkByName(name)
}

func (r realNetlink) RouteList(link Link, family int) ([]Route, error) {
	return RouteList(link, family)
}

func (r realNetlink) RouteAdd(route *Route) error {
	return RouteAdd(route)
}

func (r realNetlink) RouteDel(route *Route) error {
	return RouteDel(route)
}

var _ netlinkIface = realNetlink{}
