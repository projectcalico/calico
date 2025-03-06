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
)

// Linkaddrs manages link local addresses assigned to cali interfaces.
// In some use cases, Felix (endpoint_manager) programs a single v4 and/or v6
// link local address to workload interface.

// ipNetStr is string format of net.IPNet.
type ipNetStr string

func netlinkAddrToipNetStr(addr netlink.Addr) ipNetStr {
	ipNet := addr.IPNet
	return ipNetStr(ipNet.String())
}

// Return true if ipNetStr is in a valid v4 or v6 ipNet format.
func (a ipNetStr) validate(family int) bool {
	ip, _, err := net.ParseCIDR(string(a))
	if err != nil {
		return false
	}

	if ip.To4() != nil {
		if family != 4 {
			return false
		}
	} else if family != 6 {
		return false
	}

	return true
}

func (a ipNetStr) toNetlinkAddr() (*netlink.Addr, error) {
	ip, net, err := net.ParseCIDR(string(a))
	if err != nil {
		return nil, err
	}
	net.IP = ip
	return &netlink.Addr{IPNet: net, Scope: int(netlink.SCOPE_LINK)}, nil
}

func (a ipNetStr) programmedByOS() bool {
	// OS programs "inet6 fe80::ecee:eeff:feee:eeee/64 scope link" automatically when an
	// calico interface is created.
	return strings.HasPrefix(string(a), "fe80::") && strings.HasSuffix(string(a), "/64")
}

type LinkAddrsManager struct {
	family int

	wlIfacesPrefixes []string

	// ifaceNameToAddrs tracks the link local address that we want to program and
	// those that are actually in the dataplane.
	ifaceNameToAddrs *deltatracker.DeltaTracker[string, ipNetStr]
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
		ifaceNameToAddrs: deltatracker.New[string, ipNetStr](
			deltatracker.WithValuesEqualFn[string, ipNetStr](func(a, b ipNetStr) bool {
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

	runShow = true
	return &la
}

func (la *LinkAddrsManager) QueueResync() {
	la.resyncPending = true
}

func (la *LinkAddrsManager) SetLinkLocalAddress(ifacename string, addr string) error {
	if !la.linkOwnedByCalico(ifacename) {
		return fmt.Errorf("invalid iface name")
	}

	ipNet := ipNetStr(addr)
	if !ipNet.validate(la.family) {
		return fmt.Errorf("invalid address received")
	}
	la.logCtx.Infof("set link local address ifacename %s, addr %s", ifacename, addr)

	la.ifaceNameToAddrs.Desired().Set(ifacename, ipNet)
	return nil
}

func (la *LinkAddrsManager) RemoveLinkLocalAddress(ifacename string) {
	if !la.linkOwnedByCalico(ifacename) {
		la.logCtx.Warnf("trying to remove a link local address on non-calico interface %s", ifacename)
		return
	}
	la.logCtx.Infof("remove link local address ifacename %s", ifacename)
	la.ifaceNameToAddrs.Desired().Delete(ifacename)
}

func (la *LinkAddrsManager) Show() {
	la.ifaceNameToAddrs.Dataplane().Iter(func(k string, v ipNetStr) {
		la.logCtx.Infof("show -- dataplane : k %v, v %v", k, v)
	})
	la.ifaceNameToAddrs.Desired().Iter(func(k string, v ipNetStr) {
		la.logCtx.Infof("show -- desired : k %v, v %v", k, v)
	})
	la.ifaceNameToAddrs.PendingUpdates().Iter(func(k string, v ipNetStr) deltatracker.IterAction {
		la.logCtx.Infof("show -- pendingupdates : k %v, v %v", k, v)
		return deltatracker.IterActionNoOp
	})
	la.ifaceNameToAddrs.PendingDeletions().Iter(func(k string) deltatracker.IterAction {
		la.logCtx.Infof("show -- pendingdeletion : k %v", k)
		return deltatracker.IterActionNoOp
	})
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

var runShow bool

func (la *LinkAddrsManager) apply(nl netlinkshim.Interface) error {
	if runShow {
		la.Show()
	}

	la.ifaceNameToAddrs.PendingUpdates().Iter(func(k string, v ipNetStr) deltatracker.IterAction {
		la.logCtx.Infof("pending updates k %v, v %v", k, v)
		if err := la.ensureLinkLocalAddress(nl, k, &v); err != nil {
			log.WithError(err).Error("error update pending ipNets")
			return deltatracker.IterActionNoOp
		}

		runShow = true
		return deltatracker.IterActionUpdateDataplane
	})

	la.ifaceNameToAddrs.PendingDeletions().Iter(func(k string) deltatracker.IterAction {
		// Remove link from the dataplane.
		la.logCtx.Infof("k %v remove pending deletion", k)
		if err := la.ensureLinkLocalAddress(nl, k, nil); err != nil {
			log.WithError(err).Error("error update pending ipNets")
			return deltatracker.IterActionNoOp
		}
		runShow = true
		return deltatracker.IterActionUpdateDataplane
	})

	if runShow {
		la.Show()
		runShow = false
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

	return la.ifaceNameToAddrs.Dataplane().ReplaceAllIter(func(f func(k string, v ipNetStr)) error {
		var ipNetStr ipNetStr
		for name, addrs := range linkAddrMap {
			for _, addr := range addrs {
				ipNetStr = netlinkAddrToipNetStr(addr)
				if !ipNetStr.validate(la.family) {
					la.logCtx.Infof("Dataplane ReplaceFromIter ignore %v: %v", name, ipNetStr)
					continue
				}
				if ipNetStr.programmedByOS() {
					la.logCtx.Infof("Dataplane ReplaceFromIter ignore %v: %v", name, ipNetStr)
					continue
				}

				// Find first valid address.
				la.logCtx.Infof("Dataplane ReplaceFromIter set %v: %v", name, ipNetStr)
				break

			}
			f(name, ipNetStr)
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

// ensureLinkLocalAddress programs a address to the interface and delete all other valid addresses.
// If newIPNet is nil, it deletes all valid addresses.
func (la *LinkAddrsManager) ensureLinkLocalAddress(nl netlinkshim.Interface, name string, newIPNet *ipNetStr) error {
	link, err := nl.LinkByName(name)
	if err != nil {
		// Presumably the link is not up yet.  We will be called again when it is.
		log.WithError(err).Warning("Failed to look up device link")
		return err
	}
	addrs, err := nl.AddrList(link, la.netlinkFamily())
	if err != nil {
		log.WithError(err).Warning("Failed to list address on the link")
		return err
	}

	var programAddr bool
	if newIPNet != nil {
		programAddr = true
	}
	for _, addr := range addrs {
		removeAddr := false
		currentIPNet := netlinkAddrToipNetStr(addr)
		if !currentIPNet.validate(la.family) {
			continue
		}
		if currentIPNet.programmedByOS() {
			continue
		}

		if newIPNet != nil {
			// Address is defined.
			if currentIPNet != *newIPNet {
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
			err := la.removeIPOnInterface(nl, link, currentIPNet)
			if err != nil {
				log.WithError(err).Warning("Failed to remove netlink addr")
				return err
			}
		}
	}

	if programAddr {
		addr, err := newIPNet.toNetlinkAddr()
		if err != nil {
			log.WithError(err).Warning("Failed to get netlink addr")
			return err
		}

		if err = nl.AddrAdd(link, addr); err != nil {
			log.WithError(err).Warning("Failed to add peer ip")
			return err
		}

		log.WithFields(log.Fields{"address": addr}).Info("Assigned host side address to workload interface to set up local BGP peer")
	}

	return nil
}

func (la *LinkAddrsManager) removeIPOnInterface(nl netlinkshim.Interface, link netlink.Link, ipNet ipNetStr) error {
	log.WithField("iface", link.Attrs().Name).Info("About to remove peer ip on device link")

	addr, err := ipNet.toNetlinkAddr()
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
