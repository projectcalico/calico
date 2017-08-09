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

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/conntrack"
	"github.com/projectcalico/felix/ip"
)

type dataplaneIface interface {
	LinkList() ([]netlink.Link, error)
	LinkByName(name string) (netlink.Link, error)
	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
	RouteAdd(route *netlink.Route) error
	RouteDel(route *netlink.Route) error
	AddStaticArpEntry(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error
	RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP)
}

type realDataplane struct {
	nlTimeout           time.Duration
	cachedNetlinkHandle *netlink.Handle

	conntrack *conntrack.Conntrack
}

func newRealDataplane(socketTimeout time.Duration) *realDataplane {
	return &realDataplane{
		nlTimeout: socketTimeout,
		conntrack: conntrack.New(),
	}
}

func (r *realDataplane) nl() (*netlink.Handle, error) {
	if r.cachedNetlinkHandle != nil {
		return r.cachedNetlinkHandle, nil
	}
	h, err := netlink.NewHandle(syscall.NETLINK_ROUTE)
	if err != nil {
		logrus.WithError(err).Error("Failed to (re)connect to netlink")
		return nil, err
	}
	if r.nlTimeout > 0 {
		err := h.SetSocketTimeout(r.nlTimeout)
		if err != nil {
			logrus.WithError(err).Error("Failed to set netlink socket timeout")
			return nil, err
		}
	}
	r.cachedNetlinkHandle = h
	return r.cachedNetlinkHandle, nil
}

func (r *realDataplane) reconnectIfErr(err error) {
	if err == nil || r.cachedNetlinkHandle == nil {
		return
	}
	r.cachedNetlinkHandle.Delete()
	r.cachedNetlinkHandle = nil
}

func (r *realDataplane) LinkList() ([]netlink.Link, error) {
	h, err := r.nl()
	if err != nil {
		return nil, err
	}
	l, err := h.LinkList()
	r.reconnectIfErr(err)
	return l, err
}

func (r *realDataplane) LinkByName(name string) (netlink.Link, error) {
	h, err := r.nl()
	if err != nil {
		return nil, err
	}
	l, err := h.LinkByName(name)
	r.reconnectIfErr(err)
	return l, err
}

func (r *realDataplane) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	h, err := r.nl()
	if err != nil {
		return nil, err
	}
	l, err := h.RouteList(link, family)
	r.reconnectIfErr(err)
	return l, err
}

func (r *realDataplane) RouteAdd(route *netlink.Route) error {
	h, err := r.nl()
	if err != nil {
		return err
	}
	err = h.RouteAdd(route)
	r.reconnectIfErr(err)
	return err
}

func (r *realDataplane) RouteDel(route *netlink.Route) error {
	h, err := r.nl()
	if err != nil {
		return err
	}
	err = h.RouteDel(route)
	r.reconnectIfErr(err)
	return err
}

func (r *realDataplane) AddStaticArpEntry(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error {
	cmd := exec.Command("arp",
		"-s", cidr.Addr().String(), destMAC.String(),
		"-i", ifaceName)
	return cmd.Run()
}

func (r *realDataplane) RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP) {
	r.conntrack.RemoveConntrackFlows(ipVersion, ipAddr)
}

var _ dataplaneIface = &realDataplane{}

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
