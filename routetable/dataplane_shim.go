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
	"github.com/projectcalico/felix/conntrack"
	"github.com/projectcalico/felix/ip"
	. "github.com/vishvananda/netlink"
	"net"
	"os/exec"
)

type dataplaneIface interface {
	LinkList() ([]Link, error)
	LinkByName(name string) (Link, error)
	RouteList(link Link, family int) ([]Route, error)
	RouteAdd(route *Route) error
	RouteDel(route *Route) error
	AddStaticArpEntry(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error
	RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP)
}

type realDataplane struct {
	conntrack *conntrack.Conntrack
}

func (r realDataplane) LinkList() ([]Link, error) {
	return LinkList()
}

func (r realDataplane) LinkByName(name string) (Link, error) {
	return LinkByName(name)
}

func (r realDataplane) RouteList(link Link, family int) ([]Route, error) {
	return RouteList(link, family)
}

func (r realDataplane) RouteAdd(route *Route) error {
	return RouteAdd(route)
}

func (r realDataplane) RouteDel(route *Route) error {
	return RouteDel(route)
}

func (r realDataplane) AddStaticArpEntry(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error {
	cmd := exec.Command("arp",
		"-s", cidr.Addr().String(), destMAC.String(),
		"-i", ifaceName)
	return cmd.Run()
}

func (r realDataplane) RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP) {
	r.conntrack.RemoveConntrackFlows(ipVersion, ipAddr)
}

var _ dataplaneIface = realDataplane{}
