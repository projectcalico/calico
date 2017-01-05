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

package routetable_test

import (
	. "github.com/projectcalico/felix/go/felix/routetable"

	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/go/felix/ip"
	"github.com/projectcalico/felix/go/felix/set"
	"github.com/vishvananda/netlink"
	"net"
	"syscall"
)

var (
	notImplemented = errors.New("not implemented")
	notFound       = errors.New("not found")
	alreadyExists  = errors.New("already exists")

	mac1 = mustParseMAC("00:11:22:33:44:51")
	mac2 = mustParseMAC("00:11:22:33:44:52")
	mac3 = mustParseMAC("00:11:22:33:44:53")

	ip1  = ip.MustParseCIDR("10.0.0.1/32").ToIPNet()
	ip2  = ip.MustParseCIDR("10.0.0.2/32").ToIPNet()
	ip3  = ip.MustParseCIDR("10.0.0.3/32").ToIPNet()
	ip13 = ip.MustParseCIDR("10.0.1.3/32").ToIPNet()
)

func mustParseMAC(mac string) net.HardwareAddr {
	m, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	return m
}

var _ = Describe("RouteTable", func() {
	var dataplane *mockDataplane
	var rt *RouteTable

	BeforeEach(func() {
		dataplane = &mockDataplane{
			nameToLink:       map[string]netlink.Link{},
			routeKeyToRoute:  map[string]netlink.Route{},
			addedRouteKeys:   set.New(),
			deletedRouteKeys: set.New(),
		}
		rt = NewWithShims([]string{"cali"}, 4, dataplane)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})

	Describe("with some interfaces", func() {
		var cali1, cali2, cali3, eth0 *mockLink
		var gatewayRoute, cali1Route, cali3Route netlink.Route
		BeforeEach(func() {
			eth0 = dataplane.addIface(0, "eth0", true, true)
			cali1 = dataplane.addIface(1, "cali1", true, true)
			cali2 = dataplane.addIface(2, "cali2", true, false)
			cali3 = dataplane.addIface(3, "cali3", false, false)
			cali1Route = netlink.Route{
				LinkIndex: cali1.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.1/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  syscall.RTPROT_BOOT,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.addMockRoute(&cali1Route)
			cali3Route = netlink.Route{
				LinkIndex: cali3.attrs.Index,
				Dst:       mustParseCIDR("10.0.0.3/32"),
				Type:      syscall.RTN_UNICAST,
				Protocol:  syscall.RTPROT_BOOT,
				Scope:     netlink.SCOPE_LINK,
			}
			dataplane.addMockRoute(&cali3Route)
			gatewayRoute = netlink.Route{
				LinkIndex: eth0.attrs.Index,
				Type:      syscall.RTN_UNICAST,
				Protocol:  syscall.RTPROT_BOOT,
				Scope:     netlink.SCOPE_LINK,
				Gw:        net.ParseIP("12.0.0.1"),
			}
			dataplane.addMockRoute(&gatewayRoute)
		})
		It("should clean up only our routes", func() {
			rt.Apply()
			Expect(dataplane.routeKeyToRoute).To(ConsistOf(gatewayRoute))
			Expect(dataplane.addedRouteKeys).To(BeEmpty())
		})

		Describe("with some routes added", func() {
			BeforeEach(func() {
				rt.SetRoutes("cali1", []Target{
					{CIDR: ip.MustParseCIDR("10.0.0.1/32"), DestMAC: mac1},
				})
				rt.SetRoutes("cali2", []Target{
					{CIDR: ip.MustParseCIDR("10.0.0.2/32"), DestMAC: mac2},
				})
				rt.SetRoutes("cali3", []Target{
					{CIDR: ip.MustParseCIDR("10.0.1.3/32")},
				})
			})
			It("should keep correct route", func() {
				rt.Apply()
				Expect(dataplane.routeKeyToRoute["1-10.0.0.1/32"]).To(Equal(netlink.Route{
					LinkIndex: 1,
					Dst:       &ip1,
					Type:      syscall.RTN_UNICAST,
					Protocol:  syscall.RTPROT_BOOT,
					Scope:     netlink.SCOPE_LINK,
				}))
				Expect(dataplane.addedRouteKeys.Contains("1-10.0.0.1/32")).To(BeFalse())
			})
			It("should add new route", func() {
				rt.Apply()
				Expect(dataplane.routeKeyToRoute["2-10.0.0.2/32"]).To(Equal(netlink.Route{
					LinkIndex: 2,
					Dst:       &ip2,
					Type:      syscall.RTN_UNICAST,
					Protocol:  syscall.RTPROT_BOOT,
					Scope:     netlink.SCOPE_LINK,
				}))
			})
			It("should update changed route", func() {
				rt.Apply()
				Expect(dataplane.routeKeyToRoute["3-10.0.1.3/32"]).To(Equal(netlink.Route{
					LinkIndex: 3,
					Dst:       &ip13,
					Type:      syscall.RTN_UNICAST,
					Protocol:  syscall.RTPROT_BOOT,
					Scope:     netlink.SCOPE_LINK,
				}))
				Expect(dataplane.deletedRouteKeys.Contains("3-10.0.0.3/32")).To(BeTrue())
			})
			It("should have expected number of routes at the end", func() {
				rt.Apply()
				Expect(len(dataplane.routeKeyToRoute)).To(Equal(4),
					fmt.Sprintf("Wrong number of routes %v: %v",
						len(dataplane.routeKeyToRoute),
						dataplane.routeKeyToRoute))
			})
		})
	})
})

func mustParseCIDR(cidr string) *net.IPNet {
	_, c, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())
	return c
}

type mockDataplane struct {
	nameToLink       map[string]netlink.Link
	routeKeyToRoute  map[string]netlink.Route
	addedRouteKeys   set.Set
	deletedRouteKeys set.Set
}

func (d *mockDataplane) addIface(idx int, name string, up bool, running bool) *mockLink {
	flags := net.Flags(0)
	var rawFlags uint32
	if up {
		flags |= net.FlagUp
		rawFlags |= syscall.IFF_UP
	}
	if running {
		rawFlags |= syscall.IFF_RUNNING
	}
	link := &mockLink{
		attrs: netlink.LinkAttrs{
			Name:     name,
			Flags:    flags,
			RawFlags: rawFlags,
			Index:    idx,
		},
	}
	d.nameToLink[name] = link
	return link
}

func (d mockDataplane) LinkList() ([]netlink.Link, error) {
	var links []netlink.Link
	for _, link := range d.nameToLink {
		links = append(links, link)
	}
	return links, nil
}

func (d mockDataplane) LinkByName(name string) (netlink.Link, error) {
	if link, ok := d.nameToLink[name]; ok {
		return link, nil
	} else {
		return nil, notFound
	}
}

func (d mockDataplane) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	var routes []netlink.Route
	for _, route := range d.routeKeyToRoute {
		if route.LinkIndex == link.Attrs().Index {
			routes = append(routes, route)
		}
	}
	return routes, nil
}

func (d mockDataplane) addMockRoute(route *netlink.Route) {
	key := keyForRoute(route)
	d.routeKeyToRoute[key] = *route
}

func (d mockDataplane) RouteAdd(route *netlink.Route) error {
	key := keyForRoute(route)
	logrus.WithField("routeKey", key).Info("RouteAdd called")
	d.addedRouteKeys.Add(key)
	if _, ok := d.routeKeyToRoute[key]; ok {
		return alreadyExists
	} else {
		d.routeKeyToRoute[key] = *route
		return nil
	}
}

func (d mockDataplane) RouteDel(route *netlink.Route) error {
	key := keyForRoute(route)
	logrus.WithField("routeKey", key).Info("RouteDel called")
	d.deletedRouteKeys.Add(key)
	if _, ok := d.routeKeyToRoute[key]; ok {
		delete(d.routeKeyToRoute, key)
		return nil
	} else {
		return nil
	}
}

func (d mockDataplane) AddStaticArpEntry(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error {
	return nil
}

func keyForRoute(route *netlink.Route) string {
	key := fmt.Sprintf("%v-%v", route.LinkIndex, route.Dst)
	logrus.WithField("routeKey", key).Debug("Calculated route key")
	return key
}

type mockLink struct {
	attrs netlink.LinkAttrs
}

func (l *mockLink) Attrs() *netlink.LinkAttrs {
	return &l.attrs
}

func (l *mockLink) Type() string {
	return "not-implemented"
}
