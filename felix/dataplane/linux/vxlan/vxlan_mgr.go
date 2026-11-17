// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
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

package vxlan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	bpfnat "github.com/projectcalico/calico/felix/bpf/nat"
	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/dataplane/linux/route"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/vxlanfdb"
	"github.com/projectcalico/calico/lib/logrusr"
)

type Manager struct {
	// Our dependencies.
	hostname string
	routeMgr *route.Manager
	fdb      FDB

	ipsetsDataplane dpsets.IPSetsDataplane
	ipSetMetadata   ipsets.IPSetMetadata

	// Hold pending updates.
	vtepsByNode map[string]*proto.VXLANTunnelEndpointUpdate

	// Holds this node's VTEP information.
	myVTEPLock sync.Mutex
	myVTEP     *proto.VXLANTunnelEndpointUpdate

	// VXLAN configuration.
	vxlanDevice     string
	vxlanID         int
	vxlanPort       int
	vxlanSrcPortMin int
	vxlanSrcPortMax int
	ipVersion       uint8
	mtu             int
	vniFilter       bool

	// Indicates if configuration has changed since the last apply.
	vtepsDirty        bool
	externalNodeCIDRs []string
	dpConfig          dataplanedefs.Config

	// Log context
	logCtx     *logrus.Entry
	opRecorder logrusr.OpRecorder
}

type Option func(m *Manager)

func WithDualStack() Option {
	return func(m *Manager) {
		m.routeMgr.SetMaintainIPOnly()
	}
}

// WithVNIFilter makes the flow-based BPF device accept only Calico's VNIs, so
// other VXLAN devices can share its port. overlayVNI is the VNI that BPF encapsulates with.
// BPF decaps the NodePort VNI on host endpoints, so the filter only reserves it.
func WithVNIFilter(overlayVNI uint32) Option {
	return func(m *Manager) {
		m.vniFilter = true
		m.routeMgr.SetVNIFilter([]uint32{overlayVNI, bpfnat.NodePortVXLANTunnelVNI})
	}
}

type FDB interface {
	SetVTEPs(vteps []vxlanfdb.VTEP)
}

func NewManager(
	ipsetsDataplane dpsets.IPSetsDataplane,
	mainRouteTable routetable.Interface,
	fdb FDB,
	deviceName string,
	ipVersion uint8,
	mtu int,
	dpConfig dataplanedefs.Config,
	opRecorder logrusr.OpRecorder,
	opts ...Option,
) *Manager {
	nlHandle, _ := netlinkshim.NewRealNetlink()
	return NewManagerWithShims(
		ipsetsDataplane,
		mainRouteTable,
		fdb,
		deviceName,
		ipVersion,
		mtu,
		dpConfig,
		opRecorder,
		nlHandle,
		opts...,
	)
}

func NewManagerWithShims(
	ipsetsDataplane dpsets.IPSetsDataplane,
	mainRouteTable routetable.Interface,
	fdb FDB,
	deviceName string,
	ipVersion uint8,
	mtu int,
	dpConfig dataplanedefs.Config,
	opRecorder logrusr.OpRecorder,
	nlHandle netlinkshim.Interface,
	opts ...Option,
) *Manager {
	m := &Manager{
		ipsetsDataplane: ipsetsDataplane,
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: dpConfig.MaxIPSetSize,
			SetID:   rules.IPSetIDAllVXLANSourceNets,
			Type:    ipsets.IPSetTypeHashNet,
		},
		hostname:          dpConfig.Hostname,
		fdb:               fdb,
		vtepsByNode:       map[string]*proto.VXLANTunnelEndpointUpdate{},
		vxlanDevice:       deviceName,
		vxlanID:           dpConfig.RulesConfig.VXLANVNI,
		vxlanPort:         dpConfig.RulesConfig.VXLANPort,
		vxlanSrcPortMin:   dpConfig.VXLANSrcPortMin,
		vxlanSrcPortMax:   dpConfig.VXLANSrcPortMax,
		ipVersion:         ipVersion,
		mtu:               mtu,
		externalNodeCIDRs: dpConfig.ExternalNodesCidrs,
		vtepsDirty:        true,
		dpConfig:          dpConfig,
		logCtx: logrus.WithFields(logrus.Fields{
			"ipVersion": ipVersion,
			"device":    deviceName,
		}),
		opRecorder: opRecorder,
		routeMgr: route.NewManager(
			mainRouteTable,
			routetable.RouteClassVXLANTunnel,
			routetable.RouteClassVXLANSameSubnet,
			proto.IPPoolType_VXLAN,
			deviceName,
			ipVersion,
			mtu,
			dpConfig,
			opRecorder,
			nlHandle,
		),
	}

	for _, o := range opts {
		o(m)
	}

	m.routeMgr.SetTunnelRouteFunc(m.tunnelRoute)
	m.routeMgr.TriggerRouteUpdate()
	return m
}

func (m *Manager) OnUpdate(protoBufMsg any) {
	switch msg := protoBufMsg.(type) {
	case *proto.VXLANTunnelEndpointUpdate:
		// Check to make sure that we are dealing with messages of the correct IP version.
		if (m.ipVersion == 4 && msg.Ipv4Addr == "") || (m.ipVersion == 6 && msg.Ipv6Addr == "") {
			// Skip since the update is for a mismatched IP version
			m.logCtx.WithField("msg", msg).Debug("Skipping mismatched IP version update")
			return
		}

		m.logCtx.WithField("msg", msg).Debug("VXLAN manager received VTEP update")
		if msg.Node == m.hostname {
			m.setLocalVTEP(msg)
		} else {
			m.vtepsByNode[msg.Node] = msg
		}
		m.vtepsDirty = true
		m.routeMgr.TriggerRouteUpdate()
	case *proto.VXLANTunnelEndpointRemove:
		m.logCtx.WithField("msg", msg).Debug("VXLAN manager received VTEP remove")
		if msg.Node == m.hostname {
			m.setLocalVTEP(nil)
		} else {
			delete(m.vtepsByNode, msg.Node)
		}
		m.vtepsDirty = true
		m.routeMgr.TriggerRouteUpdate()
	default:
		m.routeMgr.OnUpdate(msg)
	}
}

func (m *Manager) setLocalVTEP(vtep *proto.VXLANTunnelEndpointUpdate) {
	m.myVTEPLock.Lock()
	defer m.myVTEPLock.Unlock()
	m.myVTEP = vtep
	var parentAddr string
	if vtep != nil {
		parentAddr = vtep.ParentDeviceIp
		if m.ipVersion == 6 {
			parentAddr = vtep.ParentDeviceIpv6
		}
	}
	m.routeMgr.UpdateParentIfaceAddr(parentAddr)
}

func (m *Manager) getLocalVTEP() *proto.VXLANTunnelEndpointUpdate {
	m.myVTEPLock.Lock()
	defer m.myVTEPLock.Unlock()
	return m.myVTEP
}

func (m *Manager) CompleteDeferredWork() error {
	if m.vtepsDirty {
		m.updateNeighborsAndAllowedSources()
		m.vtepsDirty = false
	}

	return m.routeMgr.CompleteDeferredWork()
}

func (m *Manager) updateNeighborsAndAllowedSources() {
	m.logCtx.Debug("VTEPs are dirty, updating allowed VXLAN sources and L2 neighbors.")
	m.opRecorder.RecordOperation("update-vxlan-vteps")

	// We allow VXLAN packets from configured external sources as well as
	// each Calico node with a valid VTEP.
	allowedVXLANSources := make([]string, 0, len(m.vtepsByNode)+len(m.externalNodeCIDRs))
	allowedVXLANSources = append(allowedVXLANSources, m.externalNodeCIDRs...)

	// Collect the L2 neighbors and the VTEPS.
	var l2routes []vxlanfdb.VTEP
	for _, u := range m.vtepsByNode {
		mac, err := parseMacForIPVersion(u, m.ipVersion)
		if err != nil {
			// Don't block programming of other VTEPs if somehow we receive one with a bad mac.
			m.logCtx.WithError(err).Warn("Failed to parse VTEP mac address")
			continue
		}
		addr := u.Ipv4Addr
		parentDeviceIP := u.ParentDeviceIp
		if m.ipVersion == 6 {
			addr = u.Ipv6Addr
			parentDeviceIP = u.ParentDeviceIpv6
		}
		l2routes = append(l2routes, vxlanfdb.VTEP{
			TunnelMAC: mac,
			TunnelIP:  ip.FromIPOrCIDRString(addr),
			HostIP:    ip.FromIPOrCIDRString(parentDeviceIP),
		})
		allowedVXLANSources = append(allowedVXLANSources, parentDeviceIP)
	}

	m.logCtx.WithField("l2routes", l2routes).Debug("VXLAN manager sending L2 updates")
	m.fdb.SetVTEPs(l2routes)
	m.ipsetsDataplane.AddOrReplaceIPSet(m.ipSetMetadata, allowedVXLANSources)
}

func (m *Manager) tunnelRoute(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
	if route.IsRemoteTunnel(r, proto.IPPoolType_VXLAN) || route.IsBorrowed(r, proto.IPPoolType_VXLAN) {
		// We treat remote tunnel routes as directly connected. They don't have a gateway of
		// the VTEP because they ARE the VTEP!
		return &routetable.Target{
			RouteKey: routetable.RouteKey{
				CIDR: cidr,
			},
			MTU: m.mtu,
		}
	}

	// Extract the gateway addr for this route based on its remote VTEP.
	vtep, ok := m.vtepsByNode[r.DstNodeName]
	if !ok {
		// When the VTEP arrives, it'll mark routes as dirsty so this loop will execute again.
		return nil
	}
	vtepAddr := vtep.Ipv4Addr
	if m.ipVersion == 6 {
		vtepAddr = vtep.Ipv6Addr
	}
	return &routetable.Target{
		Type: routetable.TargetTypeVXLAN,
		RouteKey: routetable.RouteKey{
			CIDR: cidr,
		},
		GW:  ip.FromString(vtepAddr),
		MTU: m.mtu,
	}
}

func (m *Manager) KeepDeviceInSync(
	ctx context.Context,
	mtu int,
	xsumBroken bool,
	wait time.Duration,
	parentIfaceC chan string,
) {
	m.routeMgr.KeepDeviceInSync(ctx, mtu, xsumBroken, wait, parentIfaceC, m.device)
}

func (m *Manager) device(parent netlink.Link) (netlink.Link, string, error) {
	if parent == nil {
		return nil, "", fmt.Errorf("no parent device available")
	}

	localVTEP := m.getLocalVTEP()
	mac, err := parseMacForIPVersion(localVTEP, m.ipVersion)
	if err != nil {
		return nil, "", err
	}

	addr := localVTEP.Ipv4Addr
	parentDeviceIP := localVTEP.ParentDeviceIp
	if m.ipVersion == 6 {
		addr = localVTEP.Ipv6Addr
		parentDeviceIP = localVTEP.ParentDeviceIpv6
	}

	la := netlink.NewLinkAttrs()
	la.Name = m.vxlanDevice
	la.HardwareAddr = mac
	vxlan := &netlink.Vxlan{
		LinkAttrs: la,
		Port:      m.vxlanPort,
		PortLow:   m.vxlanSrcPortMin,
		PortHigh:  m.vxlanSrcPortMax,
	}

	if m.dpConfig.BPFEnabled {
		vxlan.FlowBased = true
		vxlan.VniFilter = m.vniFilter
		if !m.dpConfig.BPFOverlayIPOnDevice {
			// BPF dataplane handles encap/decap and source IP selection itself,
			// so it doesn't need an IP assigned to the overlay device.
			addr = ""
		}
	} else {
		vxlan.VxlanId = m.vxlanID
		vxlan.VtepDevIndex = parent.Attrs().Index
		vxlan.SrcAddr = ip.FromString(parentDeviceIP).AsNetIP()
	}
	return vxlan, addr, nil
}

func parseMacForIPVersion(vtep *proto.VXLANTunnelEndpointUpdate, ipVersion uint8) (net.HardwareAddr, error) {
	switch ipVersion {
	case 4:
		return net.ParseMAC(vtep.Mac)
	case 6:
		return net.ParseMAC(vtep.MacV6)
	default:
		return nil, fmt.Errorf("invalid IP version")
	}
}

func CleanUpDevice(deviceName string) {
	// If VXLAN is not enabled, check to see if there is a VXLAN device and delete it if there is.
	logrus.Debug("Checking if we need to clean up the VXLAN device")

	var errFound bool
	for i := 0; i <= dataplanedefs.MaxCleanupRetries; i++ {
		errFound = false
		if i > 0 {
			logrus.Debugf("Retrying %v/%v times", i, dataplanedefs.MaxCleanupRetries)
		}
		link, err := netlink.LinkByName(deviceName)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); ok {
				logrus.Debug("VXLAN disabled and no VXLAN device found")
				return
			}
			logrus.WithError(err).Warn("VXLAN disabled and failed to query VXLAN device.")
			errFound = true

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			continue
		}
		if err = netlink.LinkDel(link); err != nil {
			logrus.WithError(err).Error("VXLAN disabled and failed to delete unwanted VXLAN device.")
			errFound = true

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			continue
		}
	}
	if errFound {
		logrus.Warnf("Giving up trying to clean up VXLAN device after retrying %v times", dataplanedefs.MaxCleanupRetries)
	}
}

// OnParentDeviceUpdate records the tunnel's parent device and reports whether it
// changed.
func (m *Manager) OnParentDeviceUpdate(name string) bool {
	return m.routeMgr.OnParentDeviceUpdate(name)
}
