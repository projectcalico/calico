// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/ip"
	"github.com/projectcalico/felix/go/felix/set"
	calinet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/vishvananda/netlink"
	"net"
	"regexp"
	"strings"
	"syscall"
)

var (
	listFailed = errors.New("netlink list operation failed")
)

type RouteTable struct {
	netlinkFamily int

	ifacePrefixes     set.Set
	ifacePrefixRegexp *regexp.Regexp

	ifaceNameToRoutes map[string]set.Set
}

func New(interfacePrefixes []string, ipVersion uint8) *RouteTable {
	prefixSet := set.New()
	regexpParts := []string{}
	for _, prefix := range interfacePrefixes {
		prefixSet.Add(prefix)
		regexpParts = append(regexpParts, "^"+prefix+".*")
	}

	ifaceNamePattern := strings.Join(regexpParts, "|")
	log.WithField("regex", ifaceNamePattern).Info("Calculated interface name regexp")

	family := netlink.FAMILY_V4
	if ipVersion == 6 {
		family = netlink.FAMILY_V6
	} else if ipVersion != 4 {
		log.WithField("ipVersion", ipVersion).Panic("Unknown IP version")
	}

	return &RouteTable{
		netlinkFamily:     family,
		ifacePrefixes:     prefixSet,
		ifacePrefixRegexp: regexp.MustCompile(ifaceNamePattern),
		ifaceNameToRoutes: map[string]set.Set{},
	}
}

func (r *RouteTable) SetRoutes(ifaceName string, routes []ip.CIDR) {
	if len(routes) == 0 {
		delete(r.ifaceNameToRoutes, ifaceName)
		return
	}
	routesSet := set.New()
	for _, route := range routes {
		routesSet.Add(route)
	}
	r.ifaceNameToRoutes[ifaceName] = routesSet
}

func (r *RouteTable) Apply() error {
	links, err := netlink.LinkList()
	if err != nil {
		log.WithError(err).Error("Failed to list interfaces, retrying...")
		return listFailed
	}

	for _, link := range links {
		linkAttrs := link.Attrs()
		ifaceName := linkAttrs.Name
		logCxt := log.WithField("ifaceName", ifaceName)
		logCxt.WithField("flags", linkAttrs.Flags).Debug("Interface flags")
		if linkAttrs.Flags&net.FlagUp == 0 {
			logCxt.Debug("Interface is down, skipping")
			continue
		}
		logCxt.Debug("Examining interface")
		if r.ifacePrefixRegexp.MatchString(ifaceName) {
			// One of our interfaces.
			logCxt.Debug("Interface matches our prefixes")
			expectedRoutes := r.ifaceNameToRoutes[ifaceName]
			if expectedRoutes == nil {
				expectedRoutes = set.Empty()
			}
			routes, err := netlink.RouteList(link, r.netlinkFamily)
			if err != nil {
				logCxt.WithError(err).WithField("link", ifaceName).Error(
					"Failed to list routes, retrying...")
				return listFailed
			}

			seenRoutes := set.New()
			for _, route := range routes {
				var dest ip.CIDR
				if route.Dst != nil {
					dest = ip.CIDRFromIPNet(calinet.IPNet{*route.Dst})
				}
				if !expectedRoutes.Contains(dest) {
					logCxt := logCxt.WithField("dest", dest)
					logCxt.Debug("Found unexpected route, deleting it")
					if err := netlink.RouteDel(&route); err != nil {
						// Probably a race with the interface being deleted.
						logCxt.WithError(err).Info(
							"Route deletion failed, assuming someone got there first.")
					}
				}
				seenRoutes.Add(dest)
			}

			expectedRoutes.Iter(func(item interface{}) error {
				cidr := item.(ip.CIDR)
				if !seenRoutes.Contains(cidr) {
					logCxt := logCxt.WithField("dest", cidr)
					logCxt.Debug("Adding missing route")
					ipNet := cidr.ToIPNet()
					route := netlink.Route{
						LinkIndex: linkAttrs.Index,
						Dst:       &ipNet,
						Type:      syscall.RTN_UNICAST,
						Protocol:  syscall.RTPROT_BOOT,
					}
					netlink.RouteAdd(&route)
				}
				return nil
			})
		}
	}
	return nil
}
