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
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

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

type VTEP struct {
	// HostIP is the remote node's real IP address; the IP that we send the
	// VXLAN packets to.
	HostIP ip.Addr
	// TunnelIP is the IP of the remote tunnel device, which we use as
	// a gateway for the remote workloads..
	TunnelIP ip.Addr
	// TunnelMAC is the MAC address of the remote tunnel device.
	TunnelMAC net.HardwareAddr
}

// VXLANFDB manages the FDB and ARP/NDP entries for a VXLAN device. I.e.
// all the layer-2 state for the VXLAN device.
//
// Overall, we use VXLAN to create a layer 3 routed network.  We do that
// by
//
//   - Giving each node a "tunnel IP" which is an IP on the Calico VXLAN network.
//     this IP is allocated from a VXLAN IP pool.
//   - (In this object) setting up static ARP/NDP entries for the tunnel IPs.
//   - (In this object) setting up static FDB entries for the tunnel MACs.
//   - (Elsewhere) setting up a routes to remote workloads via the tunnel IPs.
//
// ARP/NDP entries and FDB entries are confusingly similar(!) Both are MAC/IP
// tuples, but they mean very different things.  ARP/NDP entries tell the
// kernel what MAC address to use for the inner ethernet frame inside the
// VXLAN packet.  FDB entries tell the kernel what IP address to use for the
// outer IP header, given a particular inner MAC.  So, ARP maps IP->(inner)MAC;
// FDB maps (inner)MAC->(outer)IP.
//
// From a packet's point of view, routing works like this:
//
//   - A local workload or this host sends a packet to a remote workload.
//   - The packet hits a route of the form
//     <remote workload IPAM block> via <remote tunnel IP> dev <VXLAN device> onlink
//     which sends it to the VXLAN device for encapsulation.
//   - The ARP entry resolves the remote tunnel IP to the remote tunnel MAC.
//   - The FDP entry resolves the remote tunnel MAC to the remote host's real IP.
//   - The packet is encapsulated and sent to the remote host's real IP.
type VXLANFDB struct {
	family         int
	ifaceName      string
	ifIndex        int
	arpEntries     *deltatracker.DeltaTracker[string, ipMACMapping]
	fdbEntries     *deltatracker.DeltaTracker[string, ipMACMapping]
	logCxt         *log.Entry
	resyncPending  bool
	logNextSuccess bool
	nl             *handlemgr.HandleManager

	newNetlinkHandle func() (netlinkshim.Interface, error)
}

type ipMACMapping struct {
	IP  ip.Addr
	MAC net.HardwareAddr
}

type VXLANFDBOption func(*VXLANFDB)

func WithNetlinkHandleShim(newNetlinkHandle func() (netlinkshim.Interface, error)) VXLANFDBOption {
	return func(fdb *VXLANFDB) {
		fdb.newNetlinkHandle = newNetlinkHandle
	}
}

func New(
	family int,
	ifaceName string,
	featureDetector environment.FeatureDetectorIface,
	netlinkTimeout time.Duration,
	opts ...VXLANFDBOption,
) *VXLANFDB {
	switch family {
	case unix.AF_INET, unix.AF_INET6:
	default:
		log.WithField("family", family).Panic("Unknown family")
	}
	f := VXLANFDB{
		family:    family,
		ifaceName: ifaceName,
		arpEntries: deltatracker.New[string, ipMACMapping](
			deltatracker.WithValuesEqualFn[string, ipMACMapping](func(a, b ipMACMapping) bool {
				return a.IP == b.IP && slices.Equal(a.MAC, b.MAC)
			}),
		),
		fdbEntries: deltatracker.New[string, ipMACMapping](),
		logCxt: log.WithFields(log.Fields{
			"iface":  ifaceName,
			"family": family,
		}),
		resyncPending:    true,
		logNextSuccess:   true,
		newNetlinkHandle: netlinkshim.NewRealNetlink,
	}

	for _, o := range opts {
		o(&f)
	}

	f.nl = handlemgr.NewHandleManager(
		featureDetector,
		handlemgr.WithSocketTimeout(netlinkTimeout),
		// The Netlink library doesn't seem to be able to list
		// both types of neighbors in strict mode.
		handlemgr.WithStrictModeOverride(false),
		handlemgr.WithNewHandleOverride(f.newNetlinkHandle),
	)
	return &f
}

func (f *VXLANFDB) OnIfaceStateChanged(ifaceName string, state ifacemonitor.State) {
	if ifaceName != f.ifaceName {
		return
	}
	if state == ifacemonitor.StateUp {
		f.logCxt.Debug("VXLAN device came up, doing a resync.")
		f.resyncPending = true
	} else {
		f.logCxt.WithField("state", state).Debug("VXLAN device changed state.")
	}
}

func (f *VXLANFDB) QueueResync() {
	f.resyncPending = true
}

func (f *VXLANFDB) SetVTEPs(vteps []VTEP) {
	f.arpEntries.Desired().DeleteAll()
	f.fdbEntries.Desired().DeleteAll()
	for _, t := range vteps {
		macStr := t.TunnelMAC.String()
		// Add an ARP entry, for the remote tunnel IP.  This allows the
		// kernel to calculate the inner ethernet header without doing a
		// broadcast ARP to all VXLAN peers.
		f.arpEntries.Desired().Set(macStr, ipMACMapping{
			IP:  t.TunnelIP,
			MAC: t.TunnelMAC,
		})
		// Add an FDB entry.  While this is also a MAC/IP tuple, it tells
		// the kernel something very different!  The FDB entry tells the
		// kernel that, if it needs to send traffic to the VTEP MAC, it
		// should send the VXLAN packet to a particular host's real IP
		// address.
		f.fdbEntries.Desired().Set(macStr, ipMACMapping{
			MAC: t.TunnelMAC,
			IP:  t.HostIP,
		})
	}
}

func (f *VXLANFDB) Apply() error {
	nl, err := f.nl.Handle()
	if err != nil {
		return fmt.Errorf("failed to connect to netlink")
	}

	if f.resyncPending {
		if err := f.resync(nl); err != nil {
			return err
		}
		f.resyncPending = false
	}
	defer func() {
		if f.resyncPending {
			f.logNextSuccess = true
		}
	}()

	if f.ifIndex == 0 {
		return ErrLinkDown
	}

	f.applyFamily(nl, "ARP/NDP", f.arpEntries,
		func(mapping ipMACMapping) *netlink.Neigh {
			return &netlink.Neigh{
				Family:       f.family,
				LinkIndex:    f.ifIndex,
				State:        netlink.NUD_PERMANENT,
				Type:         unix.RTN_UNICAST,
				IP:           mapping.IP.AsNetIP(),
				HardwareAddr: mapping.MAC,
			}
		},
	)

	f.applyFamily(nl, "FDB", f.fdbEntries,
		func(mapping ipMACMapping) *netlink.Neigh {
			return &netlink.Neigh{
				Family:       unix.AF_BRIDGE,
				LinkIndex:    f.ifIndex,
				State:        netlink.NUD_PERMANENT,
				Flags:        netlink.NTF_SELF,
				IP:           mapping.IP.AsNetIP(),
				HardwareAddr: mapping.MAC,
			}
		},
	)

	if !f.resyncPending && f.logNextSuccess {
		f.logCxt.Info("VXLAN FDB now in sync.")
		f.logNextSuccess = false
	}
	if f.resyncPending {
		return fmt.Errorf("failed to add/delete some neighbor entries")
	}

	return nil
}

func (f *VXLANFDB) applyFamily(
	nl netlinkshim.Interface,
	description string,
	entries *deltatracker.DeltaTracker[string, ipMACMapping],
	entryToNeigh func(mapping ipMACMapping) *netlink.Neigh,
) {
	debug := log.IsLevelEnabled(log.DebugLevel)
	errs := map[string]error{}
	entries.PendingUpdates().Iter(func(macStr string, entry ipMACMapping) deltatracker.IterAction {
		if debug {
			log.WithField("entry", entry).Debugf("Adding %s entry.", description)
		}
		neigh := entryToNeigh(entry)
		if err := nl.NeighSet(neigh); err != nil {
			if len(errs) == 0 {
				log.WithError(err).WithField("entry", entry).Warnf("Failed to add %s entry, only logging first instance.", description)
			}
			errs[macStr] = err
			return deltatracker.IterActionNoOp
		}
		return deltatracker.IterActionUpdateDataplane
	})
	if len(errs) > 0 {
		log.WithField("numErrors", len(errs)).Warnf("Failed to add some %s entries", description)
		f.resyncPending = true
		f.nl.MarkHandleForReopen() // Defensive: force a netlink reconnection next time.
		clear(errs)
	}

	entries.PendingDeletions().Iter(func(macStr string) deltatracker.IterAction {
		entry, _ := entries.Dataplane().Get(macStr)
		if debug {
			log.WithField("entry", entry).Debug("Deleting ARP entry.")
		}
		neigh := entryToNeigh(entry)
		if err := nl.NeighDel(neigh); err != nil && !errors.Is(err, unix.ENOENT) {
			if len(errs) == 0 {
				log.WithError(err).WithField("entry", entry).Warnf("Failed to delete %s entry, only logging first instance.", description)
			}
			errs[macStr] = err
		}
		return deltatracker.IterActionUpdateDataplane
	})
	if len(errs) > 0 {
		log.WithField("numErrors", len(errs)).Warnf("Failed to remove some %s entries", description)
		f.resyncPending = true
		f.nl.MarkHandleForReopen() // Defensive: force a netlink reconnection next time.
		clear(errs)
	}
}

var ErrLinkDown = fmt.Errorf("VXLAN device is down")

func (f *VXLANFDB) resync(nl netlinkshim.Interface) error {
	// Refresh the link ID.  If the VXLAN device gets recreated then
	// this can change.
	link, err := nl.LinkByName(f.ifaceName)
	if err != nil {
		f.resyncPending = false // OnIfaceStateChanged will trigger a resync when iface appears.
		return fmt.Errorf("failed to get interface: %w", err)
	}
	if !ifacemonitor.LinkIsOperUp(link) {
		f.resyncPending = false // OnIfaceStateChanged will trigger a resync when iface appears.
		return ErrLinkDown
	}
	f.ifIndex = link.Attrs().Index

	err = f.resyncFamily(nl, "ARP/NDP", f.family, f.arpEntries)
	if err != nil {
		return err
	}
	err = f.resyncFamily(nl, "FDB", unix.AF_BRIDGE, f.fdbEntries)
	if err != nil {
		return err
	}

	return nil
}

func (f *VXLANFDB) resyncFamily(
	nl netlinkshim.Interface,
	description string,
	family int,
	entries *deltatracker.DeltaTracker[string, ipMACMapping],
) error {
	// Refresh the neighbors.
	existingNeigh, err := nl.NeighList(f.ifIndex, family)
	if err != nil {
		f.logCxt.WithError(err).Errorf("Failed to list %s entries", description)
		f.nl.MarkHandleForReopen() // Defensive: force a netlink reconnection next time.
		return fmt.Errorf("failed to list neighbors: %w", err)
	}

	err = entries.Dataplane().ReplaceAllIter(func(f func(macStr string, v ipMACMapping)) error {
		for _, n := range existingNeigh {
			if len(n.HardwareAddr) == 0 {
				// Kernel creates transient entries with no MAC, ignore
				continue
			}
			if n.State&unix.NUD_PERMANENT == 0 {
				// We only manage static entries so ignore this one.
				continue
			}
			hwAddrStr := n.HardwareAddr.String()
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"mac": hwAddrStr,
					"ip":  n.IP.String(),
				}).Debugf("Loaded %s entry from kernel.", description)
			}
			f(hwAddrStr, ipMACMapping{
				IP:  ip.FromNetIP(n.IP),
				MAC: n.HardwareAddr,
			})
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update %s entries: %w", description, err)
	}
	return nil
}
