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
	"github.com/projectcalico/felix/go/felix/conntrack"
	"github.com/projectcalico/felix/go/felix/ifacemonitor"
	"github.com/projectcalico/felix/go/felix/ip"
	"github.com/projectcalico/felix/go/felix/set"
	calinet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/vishvananda/netlink"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
)

var (
	ListFailed        = errors.New("netlink list operation failed")
	UpdateFailed      = errors.New("netlink update operation failed")
	IfaceDown         = errors.New("interface was down")
	IfaceNotPresent   = errors.New("interface not present")
	ipV6LinkLocalCIDR = ip.MustParseCIDR("fe80::/64")
)

type Target struct {
	CIDR    ip.CIDR
	DestMAC net.HardwareAddr
}

type RouteTable struct {
	logCxt *log.Entry

	ipVersion     uint8
	netlinkFamily int

	activeUpIfaces set.Set
	dirtyIfaces    set.Set

	ifacePrefixes     set.Set
	ifacePrefixRegexp *regexp.Regexp

	ifaceNameToTargets        map[string][]Target
	pendingIfaceNameToTargets map[string][]Target

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
		logCxt: log.WithFields(log.Fields{
			"ipVersion": ipVersion,
		}),
		ipVersion:                 ipVersion,
		netlinkFamily:             family,
		ifacePrefixes:             prefixSet,
		ifacePrefixRegexp:         regexp.MustCompile(ifaceNamePattern),
		ifaceNameToTargets:        map[string][]Target{},
		pendingIfaceNameToTargets: map[string][]Target{},
		activeUpIfaces:            set.New(),
		dirtyIfaces:               set.New(),
	}
}

func (r *RouteTable) OnIfaceStateChanged(ifaceName string, state ifacemonitor.State) {
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)
	if !r.ifacePrefixRegexp.MatchString(ifaceName) {
		logCxt.Debug("Ignoring interface state change, not a Calico interface.")
		return
	}
	if state == ifacemonitor.StateUp {
		logCxt.Debug("Interface up, marking for route sync")
		r.activeUpIfaces.Add(ifaceName)
		r.dirtyIfaces.Add(ifaceName)
	} else {
		logCxt.Debug("Interface down, blacklisting from route sync")
		r.activeUpIfaces.Discard(ifaceName)
	}
}

func (r *RouteTable) SetRoutes(ifaceName string, targets []Target) {
	r.pendingIfaceNameToTargets[ifaceName] = targets
	r.dirtyIfaces.Add(ifaceName)
}

func (r *RouteTable) Apply() error {
	if !r.inSync {
		links, err := netlink.LinkList()
		if err != nil {
			r.logCxt.WithError(err).Error("Failed to list interfaces, retrying...")
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
				r.logCxt.WithField("ifaceName", ifaceName).Debug(
					"Resync: found calico-owned interface")
				r.dirtyIfaces.Add(ifaceName)
			}
		}
		r.inSync = true
	}

	r.dirtyIfaces.Iter(func(item interface{}) error {
		retries := 2
		ifaceName := item.(string)
		logCxt := r.logCxt.WithField("ifaceName", ifaceName)
		for retries > 0 {
			err := r.syncRoutesForLink(ifaceName)
			if err == IfaceNotPresent {
				logCxt.Info("Interface missing, will retry if it appears.")
				break
			} else if err != nil {
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
		r.logCxt.Warn("Some interfaces still out-of sync.")
		r.inSync = false
		return UpdateFailed
	}

	return nil
}

func (r *RouteTable) syncRoutesForLink(ifaceName string) error {
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)
	logCxt.Debug("Syncing interface routes")

	// If this is a modify or delete, grab a copy of the existing targets so we can clean up
	// conntrack entries even if the routes have been removed.  We'll remove any still-required
	// CIDRs from this set below.
	oldCIDRs := set.New()
	if updatedTargets, ok := r.pendingIfaceNameToTargets[ifaceName]; ok {
		logCxt.Debug("Have updated targets.")
		oldTargets := r.ifaceNameToTargets[ifaceName]
		if updatedTargets == nil {
			delete(r.ifaceNameToTargets, ifaceName)
		} else {
			r.ifaceNameToTargets[ifaceName] = updatedTargets
		}
		for _, target := range oldTargets {
			oldCIDRs.Add(target.CIDR)
		}
		delete(r.pendingIfaceNameToTargets, ifaceName)
	}

	expectedTargets := r.ifaceNameToTargets[ifaceName]
	expectedCIDRs := set.New()
	for _, t := range expectedTargets {
		expectedCIDRs.Add(t.CIDR)
		oldCIDRs.Discard(t.CIDR)
	}
	if r.ipVersion == 6 {
		expectedCIDRs.Add(ipV6LinkLocalCIDR)
		oldCIDRs.Discard(ipV6LinkLocalCIDR)
	}

	updatesFailed := false
	linkFound := false

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		if !strings.Contains(err.Error(), "not found") {
			// Unexpected error, return it.
			logCxt.WithError(err).Error("Route sync failed: failed to get interface.")
			return err
		} else {
			logCxt.Info("Unable to sync interface routes, interface is not present.")
		}
	} else {
		// Got the link try to sync its routes.
		linkFound = true
		linkAttrs := link.Attrs()
		if linkAttrs.Flags&net.FlagUp == 0 || linkAttrs.RawFlags&syscall.IFF_RUNNING == 0 {
			// Interface must have gone down but the monitoring thread hasn't told us yet.
			logCxt.Debug("Interface is down, skipping")
			return IfaceDown
		}

		oldRoutes, err := netlink.RouteList(link, r.netlinkFamily)
		if err != nil {
			logCxt.WithError(err).WithField("link", ifaceName).Error(
				"Failed to list routes.")
			return ListFailed
		}

		seenCIDRs := set.New()
		for _, route := range oldRoutes {
			var dest ip.CIDR
			if route.Dst != nil {
				dest = ip.CIDRFromIPNet(calinet.IPNet{*route.Dst})
			}
			if !expectedCIDRs.Contains(dest) {
				logCxt := logCxt.WithField("dest", dest)
				logCxt.Info("Syncing routes: removing old route.")
				if err := netlink.RouteDel(&route); err != nil {
					// Probably a race with the interface being deleted.
					logCxt.WithError(err).Info(
						"Route deletion failed, assuming someone got there first.")
					updatesFailed = true
				}
				if dest != nil {
					// Collect any old route CIDRs that we find in the dataplane so we
					// can remove their conntrack entries later.
					oldCIDRs.Add(dest)
				}
			}
			seenCIDRs.Add(dest)
		}
		for _, target := range expectedTargets {
			cidr := target.CIDR
			if !seenCIDRs.Contains(cidr) {
				logCxt := logCxt.WithField("targetCIDR", target.CIDR)
				logCxt.Info("Syncing routes: adding new route.")
				ipNet := cidr.ToIPNet()
				route := netlink.Route{
					LinkIndex: linkAttrs.Index,
					Dst:       &ipNet,
					Type:      syscall.RTN_UNICAST,
					Protocol:  syscall.RTPROT_BOOT,
					Scope:     netlink.SCOPE_LINK,
				}
				if err := netlink.RouteAdd(&route); err != nil {
					logCxt.WithError(err).Warn("Failed to add route")
					updatesFailed = true
				}
			}
			if r.ipVersion == 4 && target.DestMAC != nil {
				// TODO(smc) clean up/sync old ARP entries
				cmd := exec.Command("arp",
					"-s", cidr.Addr().String(), target.DestMAC.String(),
					"-i", ifaceName)
				err := cmd.Run()
				if err != nil {
					logCxt.WithError(err).WithField("cmd", cmd).Warn("Failed to set ARP entry")
					updatesFailed = true
				}
			}
		}
	}

	// Now remove and conntrack entries that should no longer be there.
	oldCIDRs.Iter(func(item interface{}) error {
		dest := item.(ip.CIDR)
		conntrack.RemoveConntrackFlows(dest.Version(), dest.Addr().AsNetIP())
		return nil
	})

	if !linkFound {
		return IfaceNotPresent
	}
	if updatesFailed {
		return UpdateFailed
	}

	return nil
}
