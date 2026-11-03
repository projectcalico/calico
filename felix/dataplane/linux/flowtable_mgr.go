// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package intdataplane

import (
	"regexp"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
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

// flowtableExclusionManager tracks the endpoints that must not take the flowtable fast path.
// See felix/design/dataplane.md.
type flowtableExclusionManager struct {
	ipVersion       uint8
	ipsetsDataplane dpsets.IPSetsDataplane
	ipSetMetadata   ipsets.IPSetMetadata

	// IPs of each excluded endpoint, keyed by endpoint ID.
	wepIPs map[types.WorkloadEndpointID][]string
	hepIPs map[types.HostEndpointID][]string
	dirty  bool

	logCtx *logrus.Entry
}

func newFlowtableExclusionManager(
	ipsetsDataplane dpsets.IPSetsDataplane,
	ipVersion uint8,
	maxIPSetSize int,
) *flowtableExclusionManager {
	return &flowtableExclusionManager{
		ipVersion:       ipVersion,
		ipsetsDataplane: ipsetsDataplane,
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: maxIPSetSize,
			SetID:   rules.IPSetIDNoFlowOffload,
			Type:    ipsets.IPSetTypeHashIP,
		},
		wepIPs: map[types.WorkloadEndpointID][]string{},
		hepIPs: map[types.HostEndpointID][]string{},
		dirty:  true,
		logCtx: logrus.WithField("ipVersion", ipVersion),
	}
}

func (m *flowtableExclusionManager) OnUpdate(protoBufMsg any) {
	switch msg := protoBufMsg.(type) {
	case *proto.WorkloadEndpointUpdate:
		id := types.ProtoToWorkloadEndpointID(msg.GetId())
		if !workloadNeedsForwardHooks(msg.Endpoint) {
			m.removeWorkload(id)
			return
		}
		nets := msg.Endpoint.Ipv4Nets
		if m.ipVersion == 6 {
			nets = msg.Endpoint.Ipv6Nets
		}
		m.wepIPs[id] = stripSubnetMasks(nets)
		m.dirty = true
	case *proto.WorkloadEndpointRemove:
		m.removeWorkload(types.ProtoToWorkloadEndpointID(msg.GetId()))
	case *proto.HostEndpointUpdate:
		id := types.ProtoToHostEndpointID(msg.GetId())
		if len(msg.Endpoint.QosPolicies) == 0 {
			m.removeHost(id)
			return
		}
		ips := msg.Endpoint.ExpectedIpv4Addrs
		if m.ipVersion == 6 {
			ips = msg.Endpoint.ExpectedIpv6Addrs
		}
		m.hepIPs[id] = stripSubnetMasks(ips)
		m.dirty = true
	case *proto.HostEndpointRemove:
		m.removeHost(types.ProtoToHostEndpointID(msg.GetId()))
	}
}

// Bandwidth QoS is deliberately absent: it runs in tc, which the fast path still traverses.
func workloadNeedsForwardHooks(wep *proto.WorkloadEndpoint) bool {
	if wep == nil {
		return false
	}
	if len(wep.QosPolicies) > 0 {
		return true
	}
	qos := wep.QosControls
	if qos == nil {
		return false
	}
	return qos.IngressMaxConnections != 0 || qos.EgressMaxConnections != 0 ||
		qos.IngressPacketRate != 0 || qos.EgressPacketRate != 0
}

func stripSubnetMasks(addrs []string) []string {
	ips := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, strings.Split(addr, "/")[0])
	}
	return ips
}

func (m *flowtableExclusionManager) removeWorkload(id types.WorkloadEndpointID) {
	if _, exists := m.wepIPs[id]; exists {
		delete(m.wepIPs, id)
		m.dirty = true
	}
}

func (m *flowtableExclusionManager) removeHost(id types.HostEndpointID) {
	if _, exists := m.hepIPs[id]; exists {
		delete(m.hepIPs, id)
		m.dirty = true
	}
}

func (m *flowtableExclusionManager) CompleteDeferredWork() error {
	if !m.dirty {
		return nil
	}

	members := make([]string, 0, len(m.wepIPs)+len(m.hepIPs))
	for _, ips := range m.wepIPs {
		members = append(members, ips...)
	}
	for _, ips := range m.hepIPs {
		members = append(members, ips...)
	}
	m.ipsetsDataplane.AddOrReplaceIPSet(m.ipSetMetadata, members)
	m.dirty = false

	m.logCtx.WithField("members", members).Debug("Updated flowtable exclusion IP set")
	return nil
}
