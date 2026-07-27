// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package intdataplane

import (
	"regexp"
	"sort"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// flowtableTarget pairs a flowtable handler with the overlay/tunnel devices that belong in its
// flowtable. Overlay device names are IP-version specific (vxlan.calico vs vxlan-v6.calico), so
// each handler carries its own list rather than sharing one.
type flowtableTarget struct {
	handler        nftables.FlowTableHandler
	overlayDevices []string
}

// flowtableManager keeps each nftables flowtable's device set in sync with the host interfaces
// that currently exist. Every device is gated on an interface-monitor up/down event: nft rejects
// the whole transaction if a flowtable references a device the kernel doesn't have, which takes
// down the entire table. It covers overlay/tunnel devices (matched by exact name, per handler,
// since tunnel devices are created asynchronously after Felix starts) and external data
// interfaces (matched against the configured pattern, shared by all handlers). Workload veths are
// gated separately by the endpoint manager.
type flowtableManager struct {
	targets       []flowtableTarget
	devicePattern *regexp.Regexp

	// activeOverlay holds overlay device names, and activeExternal pattern-matched interfaces,
	// that are currently up. Kept separate so overlay devices only reach the handler that owns
	// them, while external devices go to all of them.
	activeOverlay  set.Set[string]
	activeExternal set.Set[string]

	dirty bool
}

func newFlowtableManager(targets []flowtableTarget, devicePattern *regexp.Regexp) *flowtableManager {
	return &flowtableManager{
		targets:        targets,
		devicePattern:  devicePattern,
		activeOverlay:  set.New[string](),
		activeExternal: set.New[string](),
		dirty:          true,
	}
}

func (m *flowtableManager) OnUpdate(protoBufMsg any) {
	update, ok := protoBufMsg.(*ifaceStateUpdate)
	if !ok {
		return
	}

	var active set.Set[string]
	switch {
	case m.isOverlayDevice(update.Name):
		active = m.activeOverlay
	case m.devicePattern != nil && m.devicePattern.MatchString(update.Name):
		active = m.activeExternal
	default:
		return
	}

	if update.State == ifacemonitor.StateUp {
		if active.Contains(update.Name) {
			return
		}
		active.Add(update.Name)
	} else {
		if !active.Contains(update.Name) {
			return
		}
		active.Discard(update.Name)
	}
	m.dirty = true
}

func (m *flowtableManager) isOverlayDevice(name string) bool {
	for _, t := range m.targets {
		for _, d := range t.overlayDevices {
			if d == name {
				return true
			}
		}
	}
	return false
}

func (m *flowtableManager) CompleteDeferredWork() error {
	if !m.dirty {
		return nil
	}

	external := m.activeExternal.Slice()
	sort.Strings(external)
	for _, t := range m.targets {
		overlay := make([]string, 0, len(t.overlayDevices))
		for _, d := range t.overlayDevices {
			if m.activeOverlay.Contains(d) {
				overlay = append(overlay, d)
			}
		}
		sort.Strings(overlay)
		t.handler.SetOverlayDevices(overlay)
		t.handler.SetExternalDevices(external)
	}
	m.dirty = false

	logrus.WithFields(logrus.Fields{
		"external": external,
		"overlay":  m.activeOverlay.Slice(),
	}).Debug("Updated flowtable devices")
	return nil
}
