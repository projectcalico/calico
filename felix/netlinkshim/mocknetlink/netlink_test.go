// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	"net"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The expectations in this file were recorded against a real kernel (7.0)
// through the vishvananda/netlink library.

func cidr(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func newOpenDataplane(t *testing.T) *MockNetlinkDataplane {
	RegisterTestingT(t)
	d := New()
	d.NetlinkOpen = true
	d.AddIface(4, "eth0", true, true)
	d.AddIface(5, "eth1", true, true)
	d.AddIface(6, "down0", false, false)
	return d
}

func listRoutes(d *MockNetlinkDataplane, family int) []netlink.Route {
	routes, err := d.RouteListFiltered(family, &netlink.Route{Table: 100}, netlink.RT_FILTER_TABLE)
	Expect(err).NotTo(HaveOccurred())
	return routes
}

func TestRouteReadback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		route    netlink.Route
		expected netlink.Route
	}{
		{
			name:  "IPv4 keeps scope and priority",
			route: netlink.Route{Dst: cidr("10.0.0.1/32"), LinkIndex: 4, Scope: netlink.SCOPE_LINK, Type: unix.RTN_UNICAST, Protocol: 80},
			expected: netlink.Route{Family: unix.AF_INET, Dst: cidr("10.0.0.1/32"), LinkIndex: 4, Scope: netlink.SCOPE_LINK,
				Type: unix.RTN_UNICAST, Protocol: 80},
		},
		{
			name:  "IPv6 drops scope and defaults priority",
			route: netlink.Route{Dst: cidr("fd00::1/128"), LinkIndex: 4, Scope: netlink.SCOPE_LINK, Type: unix.RTN_UNICAST, Protocol: 80},
			expected: netlink.Route{Family: unix.AF_INET6, Dst: cidr("fd00::1/128"), LinkIndex: 4, Scope: netlink.SCOPE_UNIVERSE,
				Type: unix.RTN_UNICAST, Protocol: 80, Priority: 1024},
		},
		{
			name:  "IPv6 local route drops host scope",
			route: netlink.Route{Dst: cidr("fd00::2/128"), LinkIndex: 4, Scope: netlink.SCOPE_HOST, Type: unix.RTN_LOCAL, Protocol: 80},
			expected: netlink.Route{Family: unix.AF_INET6, Dst: cidr("fd00::2/128"), LinkIndex: 4, Scope: netlink.SCOPE_UNIVERSE,
				Type: unix.RTN_LOCAL, Protocol: 80, Priority: 1024},
		},
		{
			name:     "unset type and protocol get library defaults",
			route:    netlink.Route{Dst: cidr("10.0.0.3/32"), LinkIndex: 4},
			expected: netlink.Route{Family: unix.AF_INET, Dst: cidr("10.0.0.3/32"), LinkIndex: 4, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_BOOT},
		},
		{
			name:     "IPv4 throw route has no device",
			route:    netlink.Route{Dst: cidr("10.1.0.0/24"), Type: unix.RTN_THROW, Protocol: 80},
			expected: netlink.Route{Family: unix.AF_INET, Dst: cidr("10.1.0.0/24"), Type: unix.RTN_THROW, Protocol: 80},
		},
		{
			name:  "IPv6 throw route is reported via lo",
			route: netlink.Route{Dst: cidr("fd01::/64"), Type: unix.RTN_THROW, Protocol: 80},
			expected: netlink.Route{Family: unix.AF_INET6, Dst: cidr("fd01::/64"), LinkIndex: 1, Type: unix.RTN_THROW,
				Protocol: 80, Priority: 1024},
		},
		{
			name:  "IPv6 masks host bits",
			route: netlink.Route{Dst: &net.IPNet{IP: net.ParseIP("fd02::5"), Mask: net.CIDRMask(64, 128)}, LinkIndex: 4, Protocol: 80},
			expected: netlink.Route{Family: unix.AF_INET6, Dst: cidr("fd02::/64"), LinkIndex: 4, Type: unix.RTN_UNICAST,
				Protocol: 80, Priority: 1024},
		},
		{
			name: "multi-path flags are reported per next hop",
			route: netlink.Route{Dst: cidr("10.2.0.0/24"), Flags: unix.RTNH_F_ONLINK, Protocol: 80, MultiPath: []*netlink.NexthopInfo{
				{LinkIndex: 4, Gw: net.ParseIP("172.16.0.1"), Flags: unix.RTNH_F_ONLINK},
				{LinkIndex: 5, Gw: net.ParseIP("172.16.0.2"), Flags: unix.RTNH_F_ONLINK},
			}},
			expected: netlink.Route{Family: unix.AF_INET, Dst: cidr("10.2.0.0/24"), Type: unix.RTN_UNICAST, Protocol: 80, MultiPath: []*netlink.NexthopInfo{
				{LinkIndex: 4, Gw: net.ParseIP("172.16.0.1"), Flags: unix.RTNH_F_ONLINK},
				{LinkIndex: 5, Gw: net.ParseIP("172.16.0.2"), Flags: unix.RTNH_F_ONLINK},
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newOpenDataplane(t)
			route := tc.route
			route.Table = 100
			Expect(d.RouteReplace(&route)).To(Succeed())

			tc.expected.Table = 100
			Expect(listRoutes(d, tc.expected.Family)).To(ConsistOf(tc.expected))
		})
	}
}

func TestRouteWriteErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		route netlink.Route
		err   error
	}{
		{"IPv4 host bits set", netlink.Route{Dst: &net.IPNet{IP: net.ParseIP("10.0.0.5").To4(), Mask: net.CIDRMask(24, 32)}, LinkIndex: 4}, unix.EINVAL},
		{"link down", netlink.Route{Dst: cidr("10.0.0.0/24"), LinkIndex: 6}, unix.ENETDOWN},
		{"unknown link", netlink.Route{Dst: cidr("fd00::/64"), LinkIndex: 999}, unix.ENODEV},
		{"IPv6 multi-path without gateway", netlink.Route{Dst: cidr("fd00::/64"), MultiPath: []*netlink.NexthopInfo{{LinkIndex: 4}, {LinkIndex: 5}}}, unix.EINVAL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newOpenDataplane(t)
			route := tc.route
			Expect(d.RouteReplace(&route)).To(MatchError(tc.err))
		})
	}
}

func TestRouteIdentity(t *testing.T) {
	d := newOpenDataplane(t)

	// IPv6 priority 0 means the default, 1024.
	Expect(d.RouteAdd(&netlink.Route{Table: 100, Dst: cidr("fd00::1/128"), LinkIndex: 4})).To(Succeed())
	Expect(d.RouteAdd(&netlink.Route{Table: 100, Dst: cidr("fd00::1/128"), LinkIndex: 4, Priority: 1024})).To(MatchError(ErrAlreadyExists))

	// TOS is part of an IPv4 route's identity.
	Expect(d.RouteReplace(&netlink.Route{Table: 100, Dst: cidr("10.0.0.0/24"), LinkIndex: 4, Tos: 0x10})).To(Succeed())
	Expect(d.RouteReplace(&netlink.Route{Table: 100, Dst: cidr("10.0.0.0/24"), LinkIndex: 4})).To(Succeed())

	Expect(listRoutes(d, unix.AF_INET)).To(HaveLen(2))
	Expect(listRoutes(d, unix.AF_INET6)).To(HaveLen(1))
}

func TestRouteDel(t *testing.T) {
	d := newOpenDataplane(t)
	for _, prio := range []int{5, 7} {
		Expect(d.RouteAdd(&netlink.Route{Table: 100, Dst: cidr("fd00::/64"), LinkIndex: 4, Priority: prio})).To(Succeed())
	}

	// Priority 0 is a wildcard that deletes the lowest-priority route.
	Expect(d.RouteDel(&netlink.Route{Table: 100, Dst: cidr("fd00::/64")})).To(Succeed())
	routes := listRoutes(d, unix.AF_INET6)
	Expect(routes).To(HaveLen(1))
	Expect(routes[0].Priority).To(Equal(7))

	Expect(d.RouteDel(&netlink.Route{Table: 100, Dst: cidr("fd99::/64")})).To(MatchError(unix.ESRCH))
}

func TestLinkEvents(t *testing.T) {
	onlinkMultiPath := func(dst string, gws ...string) *netlink.Route {
		r := &netlink.Route{Table: 100, Dst: cidr(dst)}
		for i, gw := range gws {
			r.MultiPath = append(r.MultiPath, &netlink.NexthopInfo{LinkIndex: 4 + i, Gw: net.ParseIP(gw), Flags: unix.RTNH_F_ONLINK})
		}
		return r
	}

	d := newOpenDataplane(t)
	Expect(d.RouteReplace(&netlink.Route{Table: 100, Dst: cidr("10.1.0.0/24"), LinkIndex: 4})).To(Succeed())
	Expect(d.RouteReplace(&netlink.Route{Table: 100, Dst: cidr("fd01::/64"), LinkIndex: 4})).To(Succeed())
	Expect(d.RouteReplace(onlinkMultiPath("10.2.0.0/24", "172.16.0.1", "172.16.0.2"))).To(Succeed())
	Expect(d.RouteReplace(onlinkMultiPath("fd02::/64", "fd99::1", "fd99::2"))).To(Succeed())
	Expect(d.NeighSet(&netlink.Neigh{Family: unix.AF_INET, LinkIndex: 4, IP: net.ParseIP("10.1.0.5"),
		HardwareAddr: net.HardwareAddr{1, 2, 3, 4, 5, 6}, State: netlink.NUD_PERMANENT})).To(Succeed())

	// Link down flushes single-path routes and neighbours, and marks
	// multi-path next hops dead.
	d.SetIface("eth0", false, false)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes := listRoutes(d, family)
		Expect(routes).To(HaveLen(1))
		Expect(routes[0].MultiPath[0].Flags).To(Equal(unix.RTNH_F_ONLINK | unix.RTNH_F_DEAD | unix.RTNH_F_LINKDOWN))
		Expect(routes[0].MultiPath[1].Flags).To(Equal(unix.RTNH_F_ONLINK))
	}
	neighs, err := d.NeighList(4, unix.AF_INET)
	Expect(err).NotTo(HaveOccurred())
	Expect(neighs).To(BeEmpty())

	// Link up revives the next hops but doesn't restore the flushed routes.
	d.SetIface("eth0", true, true)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes := listRoutes(d, family)
		Expect(routes).To(HaveLen(1))
		Expect(routes[0].MultiPath[0].Flags).To(Equal(unix.RTNH_F_ONLINK))
	}

	// Link delete removes IPv4 multi-path routes; IPv6 drops the next hop.
	d.DelIface("eth1")
	Expect(listRoutes(d, unix.AF_INET)).To(BeEmpty())
	Expect(listRoutes(d, unix.AF_INET6)).To(ConsistOf(netlink.Route{
		Family: unix.AF_INET6, Table: 100, Dst: cidr("fd02::/64"), LinkIndex: 4, Gw: net.ParseIP("fd99::1"),
		Flags: unix.RTNH_F_ONLINK, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_BOOT, Priority: 1024,
	}))
}

func TestRules(t *testing.T) {
	d := newOpenDataplane(t)
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Priority = 100
	rule.Mark = 0x100
	rule.Table = 200
	Expect(d.RuleAdd(rule)).To(Succeed())

	v4Rules, err := d.RuleList(unix.AF_INET)
	Expect(err).NotTo(HaveOccurred())
	Expect(v4Rules).To(HaveLen(4))
	Expect(v4Rules).To(ContainElement(HaveField("Mask", HaveValue(Equal(uint32(0xffffffff))))),
		"kernel defaults the mask of a mark match")

	v6Rules, err := d.RuleList(unix.AF_INET6)
	Expect(err).NotTo(HaveOccurred())
	Expect(v6Rules).To(HaveLen(2), "IPv6 has no rule for the default table")

	// Deleting with the rule as originally specified (no mask) matches.
	Expect(d.RuleDel(rule)).To(Succeed())
}
