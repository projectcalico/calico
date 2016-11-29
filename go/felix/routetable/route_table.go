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
	"github.com/projectcalico/felix/go/felix/ifacemonitor"
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
	ListFailed   = errors.New("netlink list operation failed")
	UpdateFailed = errors.New("netlink update operation failed")
	IfaceDown    = errors.New("interface was down")
)

type RouteTable struct {
	netlinkFamily int

	activeUpIfaces set.Set
	dirtyIfaces    set.Set

	ifacePrefixes     set.Set
	ifacePrefixRegexp *regexp.Regexp

	ifaceNameToRoutes map[string]set.Set

	inSync bool
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
		activeUpIfaces:    set.New(),
		dirtyIfaces:       set.New(),
	}
}

func (r *RouteTable) OnIfaceStateChanged(ifaceName string, state ifacemonitor.State) {
	if state == ifacemonitor.StateUp {
		r.activeUpIfaces.Add(ifaceName)
		r.dirtyIfaces.Add(ifaceName)
	} else {
		r.activeUpIfaces.Discard(ifaceName)
		r.dirtyIfaces.Discard(ifaceName) // Can't update routes if it's down.
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
	r.dirtyIfaces.Add(ifaceName)
}

func (r *RouteTable) Apply() error {
	if !r.inSync {
		links, err := netlink.LinkList()
		if err != nil {
			log.WithError(err).Error("Failed to list interfaces, retrying...")
			return ListFailed
		}
		// Clear the dirty set; there's no point trying to update non-existent interfaces.
		r.dirtyIfaces = set.New()
		for _, link := range links {
			attrs := link.Attrs()
			if attrs == nil {
				continue
			}
			ifaceName := attrs.Name
			if r.ifacePrefixRegexp.MatchString(ifaceName) {
				r.dirtyIfaces.Add(ifaceName)
			}
		}
		r.inSync = true
	}

	r.dirtyIfaces.Iter(func(item interface{}) error {
		retries := 2
		ifaceName := item.(string)
		logCxt := log.WithField("ifaceName", ifaceName)
		for retries > 0 {
			link, err := netlink.LinkByName(ifaceName)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					// Interface has been deleted from under us.  Give up.
					logCxt.Warn("Route sync failed: interface is gone.")
					break
				} else {
					// Unexpected error, maybe retry.
					logCxt.WithError(err).Error(
						"Route sync failed: failed to get interface.")
					retries--
					continue
				}
			}
			err = r.syncRoutesForLink(link)
			if err != nil {
				logCxt.WithError(err).Warn("Failed to syncronise interface routes.")
				retries--
				continue
			}
			logCxt.Info("Synchronised routes on interface")
			break
		}
		if retries == 0 {
			logCxt.Error("Failed to sync routes to interface. Leaving it dirty.")
			return nil
		}
		return set.RemoveItem
	})

	if r.dirtyIfaces.Len() > 0 {
		log.Warn("Some interfaces still out-of sync.")
		r.inSync = false
		return UpdateFailed
	}

	return nil
}

func (r *RouteTable) syncRoutesForLink(link netlink.Link) error {
	linkAttrs := link.Attrs()
	ifaceName := linkAttrs.Name
	logCxt := log.WithField("ifaceName", ifaceName)
	logCxt.Debug("Syncing interface routes")
	if linkAttrs.Flags&net.FlagUp == 0 || linkAttrs.RawFlags&syscall.IFF_RUNNING == 0 {
		// Interface must have gone down but the monitoring thread hasn't told us yet.
		logCxt.Debug("Interface is down, skipping")
		return IfaceDown
	}
	expectedRoutes := r.ifaceNameToRoutes[ifaceName]
	if expectedRoutes == nil {
		expectedRoutes = set.Empty()
	}
	routes, err := netlink.RouteList(link, r.netlinkFamily)
	if err != nil {
		logCxt.WithError(err).WithField("link", ifaceName).Error(
			"Failed to list routes.")
		return ListFailed
	}

	updatesFailed := false
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
				updatesFailed = true
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
			if err := netlink.RouteAdd(&route); err != nil {
				logCxt.WithError(err).Warn("Failed to add route")
				updatesFailed = true
			}
		}
		return nil
	})

	if updatesFailed {
		return UpdateFailed
	}

	return nil
}
