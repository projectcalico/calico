// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linkaddrs

import (
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/netlinkshim/handlemgr"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// Linkaddrs manages link local addresses assigned to cali interfaces.

// ipNetStr is basically a comparable net.IPNet string.
type ipNetStr string

func netlinkAddrToipNetStr(addr netlink.Addr) ipNetStr {
	ipNet := addr.IPNet
	return ipNetStr(ipNet.String())
}

func (a ipNetStr) validate(family int) bool {
	ip, _, err := net.ParseCIDR(string(a))
	if err != nil {
		return false
	}

	if ip.To4() != nil && family != 4 {
		return false
	}

	if ip.To16() != nil && family != 6 {
		return false
	}

	return true
}

func (a ipNetStr) linkLocalNetlinkAddr() (*netlink.Addr, error) {
	ip, net, err := net.ParseCIDR(string(a))
	if err != nil {
		return nil, err
	}
	net.IP = ip
	return &netlink.Addr{IPNet: net, Scope: int(netlink.SCOPE_LINK)}, nil
}

func (a ipNetStr) netlinkAddrsContains(addrs []netlink.Addr) bool {
	parsedIP := net.ParseIP(string(a))
	if parsedIP == nil {
		return false
	}

	for _, addr := range addrs {
		if addr.IP.Equal(parsedIP) {
			return true
		}
	}
	return false
}

func (a ipNetStr) assignedByOS() bool {
	// OS assigns "inet6 fe80::ecee:eeff:feee:eeee/64 scope link" automatically when an
	// calico interface is created.
	return strings.HasPrefix(string(a), "fe80::") && strings.HasSuffix(string(a), "/64")
}

type LinkAddrsManager struct {
	family int

	wlIfacesPrefixes []string

	// ifaceNameToAddrs tracks the link local addresses that we want to program and
	// those that are actually in the dataplane.
	ifaceNameToAddrs *deltatracker.DeltaTracker[string, set.Set[ipNetStr]]
	resyncPending    bool
	nl               *handlemgr.HandleManager

	newNetlinkHandle func() (netlinkshim.Interface, error)
}

type Option func(*LinkAddrsManager)

func WithNetlinkHandleShim(newNetlinkHandle func() (netlinkshim.Interface, error)) Option {
	return func(la *LinkAddrsManager) {
		la.newNetlinkHandle = newNetlinkHandle
	}
}

func New(
	family int,
	wlIfacesPrefixes []string,
	featureDetector environment.FeatureDetectorIface,
	netlinkTimeout time.Duration,
	opts ...Option,
) *LinkAddrsManager {
	switch family {
	case 4, 6:
	default:
		log.WithField("family", family).Panic("Unknown family")
	}
	la := LinkAddrsManager{
		family:           family,
		wlIfacesPrefixes: wlIfacesPrefixes,
		ifaceNameToAddrs: deltatracker.New[string, set.Set[ipNetStr]](
			deltatracker.WithValuesEqualFn[string, set.Set[ipNetStr]](func(a, b set.Set[ipNetStr]) bool {
				return a == b
			}),
		),
		resyncPending:    true,
		newNetlinkHandle: netlinkshim.NewRealNetlink,
	}

	for _, o := range opts {
		o(&la)
	}

	la.nl = handlemgr.NewHandleManager(
		featureDetector,
		handlemgr.WithSocketTimeout(netlinkTimeout),
		handlemgr.WithNewHandleOverride(la.newNetlinkHandle),
	)
	return &la
}

func (la *LinkAddrsManager) QueueResync() {
	la.resyncPending = true
}

func (la *LinkAddrsManager) SetLinkLocalAddress(ifacename string, addr string) error {
	ip := ipNetStr(addr)
	if !ip.validate(la.family) {
		return fmt.Errorf("invalid address received")
	}

	// Add address to the address set of the desired view.
	var v set.Set[ipNetStr]
	if v, ok := la.ifaceNameToAddrs.Desired().Get(ifacename); ok {
		v.Add(ip)
	} else {
		v = set.New[ipNetStr]()
		v.Add(ip)
	}
	la.ifaceNameToAddrs.Desired().Set(ifacename, v)
	return nil
}

func (la *LinkAddrsManager) RemoveLinkLocalAddress(ifacename string, addr string) error {
	ip := ipNetStr(addr)
	if !ip.validate(la.family) {
		return fmt.Errorf("invalid address received")
	}

	// Remove address from the address set of the desired view.
	if v, ok := la.ifaceNameToAddrs.Desired().Get(ifacename); ok {
		v.Discard(ip)
		la.ifaceNameToAddrs.Desired().Set(ifacename, v)
	}

	return nil
}

func (la *LinkAddrsManager) RemoveLink(ifacename string) {
	la.ifaceNameToAddrs.Desired().Delete(ifacename)
}

func (la *LinkAddrsManager) Apply() error {
	nl, err := la.nl.Handle()
	if err != nil {
		return fmt.Errorf("failed to connect to netlink")
	}

	if la.resyncPending {
		if err := la.resync(nl); err != nil {
			return err
		}
		la.resyncPending = false
	}

	if err := la.apply(nl); err != nil {
		return err
	}

	return nil
}

func (la *LinkAddrsManager) apply(nl netlinkshim.Interface) error {
	errs := map[string]error{}

	la.ifaceNameToAddrs.PendingUpdates().Iter(func(k string, v set.Set[ipNetStr]) deltatracker.IterAction {
		ipsDataplane, ok := la.ifaceNameToAddrs.Dataplane().Get(k)
		if ok {
			ipsDataplane.Iter(func(item ipNetStr) error {
				if !v.Contains(item) {
					// Delete any IP not desired.
					if err := la.removeIPOnInterface(nl, k, item); err != nil {
						errs[k] = err
					}
				}
				return nil
			})
		}

		// Program desired IPs
		v.Iter(func(item ipNetStr) error {
			if err := la.assignIPOnInterface(nl, k, item); err != nil {
				errs[k] = err
			}
			return nil
		})

		if len(errs) != 0 {
			log.WithField("errs", errs).Error("error update pending ipNets")
			return deltatracker.IterActionNoOp
		}

		return deltatracker.IterActionUpdateDataplane
	})

	la.ifaceNameToAddrs.PendingDeletions().Iter(func(k string) deltatracker.IterAction {
		// Remove link from the dataplane.
		return deltatracker.IterActionUpdateDataplane
	})

	if len(errs) > 0 {
		log.WithField("numErrors", len(errs)).Warnf("Failed to apply link local address updates")
		return fmt.Errorf("Failed to apply link local address updates")
	}

	return nil
}

func (la *LinkAddrsManager) linkOwnedByCalico(name string) bool {
	for _, prefix := range la.wlIfacesPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func (la *LinkAddrsManager) resync(nl netlinkshim.Interface) error {
	// Get all network interfaces
	links, err := nl.LinkList()
	if err != nil {
		log.WithError(err).Error("Failed to list interfaces")
		return err
	}

	linkAddrMap := map[string][]netlink.Addr{}

	// Iterate over each link and fetch its addresses if it matches the prefix
	for _, link := range links {
		name := link.Attrs().Name
		if !la.linkOwnedByCalico(name) {
			continue // Skip interfaces that don't match the prefix
		}

		addrs, err := netlink.AddrList(link, la.netlinkFamily())
		if err != nil {
			log.WithError(err).WithField("link", name).Error("Failed to get address on link")
			return err
		}
		linkAddrMap[name] = addrs
	}

	return la.ifaceNameToAddrs.Dataplane().ReplaceAllIter(func(f func(k string, v set.Set[ipNetStr])) error {
		for name, addrs := range linkAddrMap {
			s := set.New[ipNetStr]()
			for _, addr := range addrs {
				ipNetStr := netlinkAddrToipNetStr(addr)
				if ipNetStr.assignedByOS() {
					log.Infof("Dataplane ReplaceFromIter ignore %v: %v", name, ipNetStr)
					continue
				}
				log.Infof("Dataplane ReplaceFromIter set %v: %v", name, ipNetStr)
				s.Add(ipNetStr)

			}
			f(name, s)
		}
		return nil
	})
}

func (la *LinkAddrsManager) netlinkFamily() int {
	// Remove IP from the inteface if it is present.
	family := netlink.FAMILY_V4
	if la.family == 6 {
		family = netlink.FAMILY_V6
	}
	return family
}

func (la *LinkAddrsManager) assignIPOnInterface(nl netlinkshim.Interface, name string, ip ipNetStr) error {
	// Remove IP from the inteface if it is present.
	link, err := nl.LinkByName(name)
	if err != nil {
		// Presumably the link is not up yet.  We will be called again when it is.
		log.WithError(err).Warning("Failed to look up device link")
		return err
	}
	addrs, err := nl.AddrList(link, la.netlinkFamily())
	if err != nil {
		// Not sure why this would happen, but pass it up.
		log.WithError(err).Warning("Failed to list address on the link")
		return err
	}

	// Do nothing if the address is already configured.
	if ip.netlinkAddrsContains(addrs) {
		return nil
	}

	addr, err := ip.linkLocalNetlinkAddr()
	if err != nil {
		log.WithError(err).Warning("Failed to get netlink addr")
		return err
	}

	if err = nl.AddrAdd(link, addr); err != nil {
		log.WithError(err).Warning("Failed to add peer ip")
		return err
	}

	log.WithFields(log.Fields{"address": addr}).Info("Assigned host side address to workload interface to set up local BGP peer")
	return nil
}

func (la *LinkAddrsManager) removeIPOnInterface(nl netlinkshim.Interface, name string, ip ipNetStr) error {
	// Look up the interface.
	link, err := nl.LinkByName(name)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		// The link has been removed.  Address already gone.
		return nil
	} else if err != nil {
		log.WithError(err).Warning("Failed to look up device link")
		return err
	}

	addrs, err := nl.AddrList(link, la.netlinkFamily())
	if err != nil {
		// CNI may delete link at this point, pass it up.
		log.WithError(err).Warning("Failed to list address on the link")
		return err
	}

	if !ip.netlinkAddrsContains(addrs) {
		return nil
	}

	log.WithField("iface", name).Info("About to remove peer ip on device link")

	addr, err := ip.linkLocalNetlinkAddr()
	if err != nil {
		log.WithError(err).Warning("Failed to get netlink addr")
		return err
	}

	if err = nl.AddrDel(link, addr); err != nil {
		// Only emit the following warning log if the link still exists.
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			// The link has been removed.  Address already gone.
			return nil
		} else if err != nil {
			log.WithField("address", addr).WithError(err).Warning("Failed to remove host side address on workload interface")
		}
		return err
	}

	log.WithField("address", addr).Info("Removed host side address on workload interface")
	return nil
}
