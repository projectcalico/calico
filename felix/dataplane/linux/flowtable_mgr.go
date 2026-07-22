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

// flowtableManager keeps the nftables flowtable's external device set in sync with the host
// interfaces matching the configured data-interface pattern, so traffic forwarded between those
// interfaces and local workloads is offloaded. It is only registered when offload is enabled and
// the pattern is non-nil.
type flowtableManager struct {
	handlers      []nftables.FlowTableHandler
	devicePattern *regexp.Regexp
	activeDevices set.Set[string]
	dirty         bool
}

func newFlowtableManager(handlers []nftables.FlowTableHandler, devicePattern *regexp.Regexp) *flowtableManager {
	return &flowtableManager{
		handlers:      handlers,
		devicePattern: devicePattern,
		activeDevices: set.New[string](),
		dirty:         true,
	}
}

func (m *flowtableManager) OnUpdate(protoBufMsg any) {
	update, ok := protoBufMsg.(*ifaceStateUpdate)
	if !ok {
		return
	}
	if !m.devicePattern.MatchString(update.Name) {
		return
	}

	if update.State == ifacemonitor.StateUp {
		if m.activeDevices.Contains(update.Name) {
			return
		}
		m.activeDevices.Add(update.Name)
	} else {
		if !m.activeDevices.Contains(update.Name) {
			return
		}
		m.activeDevices.Discard(update.Name)
	}
	m.dirty = true
}

func (m *flowtableManager) CompleteDeferredWork() error {
	if !m.dirty {
		return nil
	}

	devices := m.activeDevices.Slice()
	sort.Strings(devices)
	for _, h := range m.handlers {
		h.SetExternalDevices(devices)
	}
	m.dirty = false

	logrus.WithField("devices", devices).Debug("Updated flowtable external devices")
	return nil
}
