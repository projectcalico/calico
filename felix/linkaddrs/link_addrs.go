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
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/netlinkshim/handlemgr"
)

// Linkaddrs manages link local addresses assigned to cali interfaces.
// In some use cases (e.g. local BGP Peering), Felix (endpoint_manager) programs a single v4 and/or v6
// link local address to workload interface.

// Note: Currently, LinkAddrs ensures that only one IP from an IP family can be attached with SCOPE_LINK on an interface.
// It does not support assigning multiple IPs to the interface.

func netlinkAddrToipAddr(addr netlink.Addr) (ip.Addr, error) {
	ipNet := addr.IPNet
	if ipNet == nil {
		return nil, fmt.Errorf("netlink address converted to nil address")
	}

	a := ip.FromNetIP(addr.IPNet.IP)
	if a == nil {
		return nil, fmt.Errorf("netlink address converted to nil address")
	}
	return a, nil
}

func ipAddrToNetlinkAddr(addr ip.Addr) (*netlink.Addr, error) {
	net := addr.AsCIDR().ToIPNet()
	return &netlink.Addr{IPNet: &net, Scope: int(netlink.SCOPE_LINK)}, nil
}

func programmedByOS(addr netlink.Addr) bool {
	// OS programs "inet6 fe80::ecee:eeff:feee:eeee/64 scope link" automatically when an
	// calico interface is created.
	a := addr.IPNet.String()
	return strings.HasPrefix(string(a), "fe80::") && strings.HasSuffix(string(a), "/64")
}

type LinkAddrsManager struct {
	family int

	wlIfacesPrefixes []string

	// ifaceNameToAddrs tracks the link local address that we want to program and
	// those that are actually in the dataplane.
	ifaceNameToAddrs *deltatracker.DeltaTracker[string, ip.Addr]
	resyncPending    bool

	nl               *handlemgr.HandleManager
	newNetlinkHandle func() (netlinkshim.Interface, error)

	logCtx *log.Entry
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
		ifaceNameToAddrs: deltatracker.New[string, ip.Addr](
			deltatracker.WithValuesEqualFn[string, ip.Addr](func(a, b ip.Addr) bool {
				return a == b
			}),
		),
		resyncPending:    true,
		newNetlinkHandle: netlinkshim.NewRealNetlink,
		logCtx: log.WithFields(log.Fields{
			"family": family,
		}),
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

func (la *LinkAddrsManager) SetLinkLocalAddress(ifacename string, ipAddr ip.Addr) error {
	if !la.linkOwnedByCalico(ifacename) {
		return fmt.Errorf("invalid iface name")
	}

	if ipAddr == nil {
		return fmt.Errorf("nil address received")
	}

	if ipAddr.Version() != (uint8)(la.family) {
		return fmt.Errorf("invalid address received")
	}
	la.logCtx.WithFields(log.Fields{
		"iface": ifacename,
		"addr":  ipAddr,
	}).Debug("set link local address")

	la.ifaceNameToAddrs.Desired().Set(ifacename, ipAddr)
	return nil
}

func (la *LinkAddrsManager) RemoveLinkLocalAddress(ifacename string) {
	if !la.linkOwnedByCalico(ifacename) {
		la.logCtx.WithField("iface", ifacename).Warn("trying to remove a link local address on non-calico interface")
		return
	}
	la.logCtx.WithField("iface", ifacename).Debug("remove link local address")
	la.ifaceNameToAddrs.Desired().Delete(ifacename)
}

func (la *LinkAddrsManager) GetNlHandle() (netlinkshim.Interface, error) {
	nl, err := la.nl.Handle()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to netlink")
	}
	return nl, nil
}

func (la *LinkAddrsManager) Apply() error {
	nl, err := la.GetNlHandle()
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
	var lastErr error
	la.ifaceNameToAddrs.PendingUpdates().Iter(func(k string, v ip.Addr) deltatracker.IterAction {
		if err := la.ensureLinkLocalAddress(nl, k, v); err != nil {
			la.logCtx.WithError(err).Error("error updating link local address")
			lastErr = err
			return deltatracker.IterActionNoOp
		}

		return deltatracker.IterActionUpdateDataplane
	})

	la.ifaceNameToAddrs.PendingDeletions().Iter(func(k string) deltatracker.IterAction {
		if err := la.ensureLinkLocalAddress(nl, k, nil); err != nil {
			la.logCtx.WithError(err).Error("error deleting link local address")
			lastErr = err
			return deltatracker.IterActionNoOp
		}
		return deltatracker.IterActionUpdateDataplane
	})

	return lastErr
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
		la.logCtx.WithError(err).Error("Failed to list interfaces")
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
			la.logCtx.WithError(err).WithField("link", name).Error("Failed to get address on link")
			return err
		}
		linkAddrMap[name] = addrs
	}

	return la.ifaceNameToAddrs.Dataplane().ReplaceAllIter(func(f func(k string, v ip.Addr)) error {
		var ipAddr ip.Addr
		for name, addrs := range linkAddrMap {
			for _, addr := range addrs {
				if programmedByOS(addr) {
					// ignore address which is programmed by OS.
					continue
				}

				ipAddr, err = netlinkAddrToipAddr(addr)
				if err != nil {
					la.logCtx.WithError(err).WithField("link", name).Error("link has wrong ip format")
					continue
				}
				if ipAddr.Version() != (uint8)(la.family) {
					// ignore address which is not in the same family.
					continue
				}

				// This should be a valid address in the dataplane.
				break
			}
			f(name, ipAddr)
		}
		return nil
	})
}

func (la *LinkAddrsManager) netlinkFamily() int {
	family := netlink.FAMILY_V4
	if la.family == 6 {
		family = netlink.FAMILY_V6
	}
	return family
}

// ensureLinkLocalAddress programs an address to the interface and delete all other valid addresses.
// If newIPAddr is nil, it deletes all valid addresses.
func (la *LinkAddrsManager) ensureLinkLocalAddress(nl netlinkshim.Interface, name string, newIPAddr ip.Addr) error {
	link, err := nl.LinkByName(name)
	if err != nil {
		// Presumably the link is not up yet.  We will be called again when it is.
		la.logCtx.WithError(err).Warning("Failed to look up device link")
		return err
	}
	addrs, err := nl.AddrList(link, la.netlinkFamily())
	if err != nil {
		la.logCtx.WithError(err).Warning("Failed to list address on the link")
		return err
	}

	var programAddr bool
	if newIPAddr != nil {
		programAddr = true
	}
	for _, netlinkAddr := range addrs {
		removeAddr := false
		if programmedByOS(netlinkAddr) {
			// ignore address which is programmed by OS.
			continue
		}

		ipAddr, err := netlinkAddrToipAddr(netlinkAddr)
		if err != nil {
			la.logCtx.WithError(err).WithField("link", name).Error("link has wrong ip format")
			continue
		}
		if ipAddr.Version() != (uint8)(la.family) {
			// ignore address which is not in the same family.
			continue
		}

		if newIPAddr != nil {
			// New address is defined.
			if ipAddr != newIPAddr {
				removeAddr = true
			} else {
				// Address exists already. Do nothing.
				programAddr = false
			}
		} else {
			removeAddr = true
		}

		if removeAddr {
			// Remove old address
			err := la.removeIPOnInterface(nl, link, netlinkAddr)
			if err != nil {
				la.logCtx.WithError(err).Warning("Failed to remove netlink addr")
				return err
			}
		}
	}

	if programAddr {
		addr, err := ipAddrToNetlinkAddr(newIPAddr)
		if err != nil {
			la.logCtx.WithError(err).Warning("Failed to get netlink addr")
			return err
		}

		if err = nl.AddrAdd(link, addr); err != nil {
			la.logCtx.WithError(err).Warning("Failed to add peer ip")
			return err
		}

		la.logCtx.WithFields(log.Fields{"address": addr}).Info("Assigned host side address to workload interface.")
	}

	return nil
}

func (la *LinkAddrsManager) removeIPOnInterface(nl netlinkshim.Interface, link netlink.Link, addr netlink.Addr) error {
	if err := nl.AddrDel(link, &addr); err != nil {
		// Only emit the following warning log if the link still exists.
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			// The link has been removed.  Address already gone.
			return nil
		} else {
			la.logCtx.WithField("address", addr).WithError(err).Warning("Failed to remove host side address on workload interface")
		}
		return err
	}

	la.logCtx.WithField("address", addr).Info("Removed host side address on workload interface")
	return nil
}
