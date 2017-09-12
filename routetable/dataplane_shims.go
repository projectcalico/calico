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
	"net"
	"os/exec"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/conntrack"
	"github.com/projectcalico/felix/ip"
)

type conntrackIface interface {
	RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP)
}

type HandleIface interface {
	SetSocketTimeout(to time.Duration) error
	LinkList() ([]netlink.Link, error)
	LinkByName(name string) (netlink.Link, error)
	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
	RouteAdd(route *netlink.Route) error
	RouteDel(route *netlink.Route) error
	Delete()
}

type realDataplane struct {
	conntrack *conntrack.Conntrack
}

func newNetlinkHandle() (HandleIface, error) {
	return netlink.NewHandle(syscall.NETLINK_ROUTE)
}

func addStaticARPEntry(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error {
	cmd := exec.Command("arp",
		"-s", cidr.Addr().String(), destMAC.String(),
		"-i", ifaceName)
	return cmd.Run()
}

// timeIface is our shim interface to the time package.
type timeIface interface {
	Now() time.Time
	Since(t time.Time) time.Duration
}

// realTime is the real implementation of timeIface, which calls through to the real time package.
type realTime struct{}

func (_ realTime) Now() time.Time {
	return time.Now()
}

func (_ realTime) Since(t time.Time) time.Duration {
	return time.Since(t)
}

var _ timeIface = realTime{}
