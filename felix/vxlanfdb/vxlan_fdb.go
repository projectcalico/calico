// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package vxlanfdb

import (
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/netlinkshim/handlemgr"
)

type L2Target struct {
	// For VXLAN targets, this is the node's real IP address.
	IP ip.Addr

	// For VXLAN targets, this is the MAC address of the remote VTEP.
	VTEPMAC net.HardwareAddr

	// For VXLAN targets, this is the IP address of the remote VTEP.
	GW ip.Addr
}

type VXLANFDB struct {
	ifaceName     string
	ifIndex       int
	arpEntries    *deltatracker.DeltaTracker[string, ipMACMapping]
	fdbEntries    *deltatracker.DeltaTracker[string, ipMACMapping]
	logCxt        *log.Entry
	resyncPending bool
	nl            *handlemgr.HandleManager
	family        int
}

type ipMACMapping struct {
	IP  ip.Addr
	MAC net.HardwareAddr
}

func New(family int, ifaceName string, featureDetector environment.FeatureDetectorIface, netlinkTimeout time.Duration) *VXLANFDB {
	f := VXLANFDB{
		family:     family,
		ifaceName:  ifaceName,
		arpEntries: deltatracker.New[string, ipMACMapping](),
		fdbEntries: deltatracker.New[string, ipMACMapping](),
		logCxt: log.WithFields(log.Fields{
			"iface":  ifaceName,
			"family": family,
		}),
		resyncPending: true,
		nl: handlemgr.NewHandleManager(
			featureDetector,
			handlemgr.WithSocketTimeout(netlinkTimeout),
			// The Netlink library doesn't seem to be able to list
			// both types of neighbors in strict mode.
			handlemgr.WithStrictModeOverride(false),
		),
	}
	return &f
}

func (r *VXLANFDB) OnIfaceStateChanged(ifaceName string, state ifacemonitor.State) {
	if ifaceName != r.ifaceName {
		return
	}
	if state == ifacemonitor.StateUp {
		r.logCxt.Debug("VXLAN device came up, doing a resync.")
		r.resyncPending = true
	}
}

func (r *VXLANFDB) SetL2Routes(targets []L2Target) {
	r.arpEntries.Desired().DeleteAll()
	r.fdbEntries.Desired().DeleteAll()
	for _, t := range targets {
		r.arpEntries.Desired().Set(t.VTEPMAC.String(), ipMACMapping{
			MAC: t.VTEPMAC,
			IP:  t.GW,
		})
		r.fdbEntries.Desired().Set(t.VTEPMAC.String(), ipMACMapping{
			MAC: t.VTEPMAC,
			IP:  t.IP,
		})
	}
}

func (r *VXLANFDB) Apply() error {
	nl, err := r.nl.Handle()
	if err != nil {
		return fmt.Errorf("failed to connect to netlink")
	}

	if r.resyncPending {
		if err := r.resync(nl); err != nil {
			return err
		}
		r.resyncPending = false
	}

	errs := map[string]error{}
	r.arpEntries.PendingUpdates().Iter(func(macStr string, entry ipMACMapping) deltatracker.IterAction {
		a := &netlink.Neigh{
			LinkIndex:    r.ifIndex,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           entry.IP.AsNetIP(),
			HardwareAddr: entry.MAC,
		}
		if err := nl.NeighSet(a); err != nil {
			if len(errs) == 0 {
				log.WithError(err).WithField("entry", entry).Warn("Failed to add ARP entry, only logging first instance.")
			}
			errs[macStr] = err
			return deltatracker.IterActionNoOp
		}
		return deltatracker.IterActionUpdateDataplane
	})
	if len(errs) > 0 {
		log.WithField("numErrors", len(errs)).Warn("Failed to add some ARP entries")
		r.resyncPending = true
		r.nl.CloseHandle() // Defensive: force a netlink reconnection next time.
		clear(errs)
	}

	r.arpEntries.PendingDeletions().Iter(func(macStr string) deltatracker.IterAction {
		entry, _ := r.arpEntries.Dataplane().Get(macStr)
		a := &netlink.Neigh{
			LinkIndex:    r.ifIndex,
			Type:         unix.RTN_UNICAST,
			IP:           entry.IP.AsNetIP(),
			HardwareAddr: entry.MAC,
		}
		if err := nl.NeighDel(a); err != nil && !errors.Is(err, unix.ENOENT) {
			if len(errs) == 0 {
				log.WithError(err).WithField("entry", entry).Warn("Failed to delete ARP entry, only logging first instance.")
			}
			errs[macStr] = err
		}
		return deltatracker.IterActionUpdateDataplane
	})
	if len(errs) > 0 {
		log.WithField("numErrors", len(errs)).Warn("Failed to remove some ARP entries")
		r.resyncPending = true
		r.nl.CloseHandle() // Defensive: force a netlink reconnection next time.
		clear(errs)
	}

	r.fdbEntries.PendingUpdates().Iter(func(macStr string, entry ipMACMapping) deltatracker.IterAction {
		a := &netlink.Neigh{
			LinkIndex:    r.ifIndex,
			State:        netlink.NUD_PERMANENT,
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			IP:           entry.IP.AsNetIP(),
			HardwareAddr: entry.MAC,
		}
		if err := nl.NeighSet(a); err != nil {
			if len(errs) == 0 {
				log.WithError(err).WithField("entry", entry).Warn("Failed to add FDB entry, only logging first instance.")
			}
			errs[macStr] = err
			return deltatracker.IterActionNoOp
		}
		return deltatracker.IterActionUpdateDataplane
	})
	if len(errs) > 0 {
		log.WithField("numErrors", len(errs)).Warn("Failed to add some FDB entries")
		r.resyncPending = true
		r.nl.CloseHandle() // Defensive: force a netlink reconnection next time.
		clear(errs)
	}

	r.fdbEntries.PendingDeletions().Iter(func(macStr string) deltatracker.IterAction {
		entry, _ := r.arpEntries.Dataplane().Get(macStr)
		a := &netlink.Neigh{
			LinkIndex:    r.ifIndex,
			State:        netlink.NUD_PERMANENT,
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			IP:           entry.IP.AsNetIP(),
			HardwareAddr: entry.MAC,
		}
		if err := nl.NeighDel(a); err != nil && !errors.Is(err, unix.ENOENT) {
			if len(errs) == 0 {
				log.WithError(err).WithField("entry", entry).Warn("Failed to delete FDB entry, only logging first instance.")
			}
			errs[macStr] = err
		}
		return deltatracker.IterActionUpdateDataplane
	})
	if len(errs) > 0 {
		log.WithField("numErrors", len(errs)).Warn("Failed to remove some ARP entries")
		r.resyncPending = true
		r.nl.CloseHandle() // Defensive: force a netlink reconnection next time.
		clear(errs)
	}

	return nil
}

func (r *VXLANFDB) resync(nl netlinkshim.Interface) error {
	// Refresh the link ID.  If the VXLAN device gets recreated then
	// this can change.
	link, err := nl.LinkByName(r.ifaceName)
	if err != nil {
		r.resyncPending = false // OnIfaceStateChanged will trigger a resync when iface appears.
		return fmt.Errorf("failed to get interface: %w", err)
	}
	r.ifIndex = link.Attrs().Index

	// Refresh the neighbours.
	existingNeigh, err := nl.NeighList(r.ifIndex, unix.AF_INET)
	if err != nil {
		r.logCxt.WithError(err).Error("Failed to list neighbors")
		return fmt.Errorf("failed to list neighbors: %w", err)
	}
	existingFDB, err := nl.NeighList(r.ifIndex, unix.AF_BRIDGE)
	if err != nil {
		r.logCxt.WithError(err).Error("Failed to list FDB entries")
		return fmt.Errorf("failed to list FDB entries: %w", err)
	}
	err = r.arpEntries.Dataplane().ReplaceAllIter(func(f func(macStr string, v ipMACMapping)) error {
		for _, n := range existingNeigh {
			if n.HardwareAddr == nil {
				continue
			}
			hwAddrStr := n.HardwareAddr.String()
			f(hwAddrStr, ipMACMapping{
				IP:  ip.FromNetIP(n.IP),
				MAC: n.HardwareAddr,
			})
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update arpEntries: %w", err)
	}
	err = r.fdbEntries.Dataplane().ReplaceAllIter(func(f func(k string, v ipMACMapping)) error {
		for _, n := range existingFDB {
			if n.HardwareAddr == nil {
				continue
			}
			hwAddrStr := n.HardwareAddr.String()
			f(hwAddrStr, ipMACMapping{
				IP:  ip.FromNetIP(n.IP),
				MAC: n.HardwareAddr,
			})
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update fdbEntries: %w", err)
	}

	return nil
}
