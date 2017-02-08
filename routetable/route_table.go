// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	"net"
	"regexp"
	"strings"
	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/conntrack"
	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/set"
	calinet "github.com/projectcalico/libcalico-go/lib/net"
)

var (
	GetFailed       = errors.New("netlink get operation failed")
	ListFailed      = errors.New("netlink list operation failed")
	UpdateFailed    = errors.New("netlink update operation failed")
	IfaceNotPresent = errors.New("interface not present")
	IfaceDown       = errors.New("interface down")

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

	dirtyIfaces set.Set

	ifacePrefixes     set.Set
	ifacePrefixRegexp *regexp.Regexp

	ifaceNameToTargets        map[string][]Target
	pendingIfaceNameToTargets map[string][]Target

	inSync bool

	// dataplane is our shim for the netlink/arp interface.  In production, it maps directly
	// through to calls to the netlink package and the arp command.
	dataplane dataplaneIface
}

func New(interfacePrefixes []string, ipVersion uint8) *RouteTable {
	return NewWithShims(interfacePrefixes, ipVersion, realDataplane{conntrack: conntrack.New()})
}

// NewWithShims is a test constructor, which allows netlink to be replaced by a shim.
func NewWithShims(interfacePrefixes []string, ipVersion uint8, nl dataplaneIface) *RouteTable {
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
		dirtyIfaces:               set.New(),
		dataplane:                 nl,
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
		r.dirtyIfaces.Add(ifaceName)
	}
}

func (r *RouteTable) SetRoutes(ifaceName string, targets []Target) {
	r.pendingIfaceNameToTargets[ifaceName] = targets
	r.dirtyIfaces.Add(ifaceName)
}

func (r *RouteTable) QueueResync() {
	r.logCxt.Info("Queueing a resync of routing table.")
	r.inSync = false
}

func (r *RouteTable) Apply() error {
	if !r.inSync {
		links, err := r.dataplane.LinkList()
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
			} else if err == IfaceDown {
				logCxt.Info("Interface down, will retry if it goes up.")
				break
			} else if err != nil {
				logCxt.WithError(err).Warn("Failed to syncronise routes.")
				retries--
				continue
			}
			logCxt.Debug("Synchronised routes on interface")
			break
		}
		if retries == 0 {
			// The interface might be flapping or being deleted.
			logCxt.Warn("Failed to sync routes to interface even after retries. " +
				"Leaving it dirty.")
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

	// The code below may add some more CIDRs to clean up before it is done, make sure we
	// remove conntrack entries in any case.
	defer oldCIDRs.Iter(func(item interface{}) error {
		// Remove and conntrack entries that should no longer be there.
		dest := item.(ip.CIDR)
		r.dataplane.RemoveConntrackFlows(dest.Version(), dest.Addr().AsNetIP())
		return nil
	})

	// Try to get the link.  This may fail if it's been deleted out from under us.
	link, err := r.dataplane.LinkByName(ifaceName)
	if err != nil {
		// Filter the error so that we don't spam errors if the interface is being torn
		// down.
		filteredErr := r.filterErrorByIfaceState(ifaceName, GetFailed)
		if filteredErr == GetFailed {
			logCxt.WithError(err).Error("Failed to get interface.")
		} else {
			logCxt.WithError(err).Info("Failed to get interface; it's down/gone.")
		}
		return filteredErr
	}

	// Got the link; try to sync its routes.  Note: We used to check if the interface
	// was oper down before we tried to do the sync but that prevented us from removing
	// routes from an interface in some corner cases (such as being admin up but oper
	// down).
	linkAttrs := link.Attrs()
	oldRoutes, err := r.dataplane.RouteList(link, r.netlinkFamily)
	if err != nil {
		// Filter the error so that we don't spam errors if the interface is being torn
		// down.
		filteredErr := r.filterErrorByIfaceState(ifaceName, ListFailed)
		if filteredErr == ListFailed {
			logCxt.WithError(err).Error("Error listing routes")
		} else {
			logCxt.WithError(err).Info("Failed to list routes; interface down/gone.")
		}
		return filteredErr
	}

	seenCIDRs := set.New()
	updatesFailed := false
	for _, route := range oldRoutes {
		var dest ip.CIDR
		if route.Dst != nil {
			dest = ip.CIDRFromIPNet(calinet.IPNet{*route.Dst})
		}
		if !expectedCIDRs.Contains(dest) {
			logCxt := logCxt.WithField("dest", dest)
			logCxt.Info("Syncing routes: removing old route.")
			if err := r.dataplane.RouteDel(&route); err != nil {
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
			if err := r.dataplane.RouteAdd(&route); err != nil {
				logCxt.WithError(err).Warn("Failed to add route")
				updatesFailed = true
			}
		}
		if r.ipVersion == 4 && target.DestMAC != nil {
			// TODO(smc) clean up/sync old ARP entries
			err := r.dataplane.AddStaticArpEntry(cidr, target.DestMAC, ifaceName)
			if err != nil {
				logCxt.WithError(err).Warn("Failed to set ARP entry")
				updatesFailed = true
			}
		}
	}

	if updatesFailed {
		// Recheck whether the interface exists so we don't produce spammy logs during
		// interface removal.
		return r.filterErrorByIfaceState(ifaceName, UpdateFailed)
	}

	return nil
}

// filterErrorByIfaceState checks the current state of the interface; it's down or gone, it returns
// IfaceDown or IfaceError, otherwise, it returns the given defaultErr.
func (r *RouteTable) filterErrorByIfaceState(ifaceName string, defaultErr error) error {
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)
	if link, err := r.dataplane.LinkByName(ifaceName); err == nil {
		// Link still exists.  Check if it's up.
		if link.Attrs().Flags&net.FlagUp != 0 {
			// Link exists and it's up, no reason that we expect to fail.
			return defaultErr
		} else {
			// Special case: Link exists and it's down.  Assume that's the problem.
			return IfaceDown
		}
	} else if strings.Contains(err.Error(), "not found") {
		// Special case: Link no longer exists.
		return IfaceNotPresent
	} else {
		// Failed to list routes, then failed to check if interface exists.
		logCxt.WithError(err).Error("Failed to access interface after a failure")
		return defaultErr
	}
}
