// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	bpfutils "github.com/projectcalico/calico/felix/bpf/utils"
	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/vxlanfdb"
)

type vxlanManager struct {
	// Our dependencies.
	hostname string
	routeMgr *routeManager
	fdb      VXLANFDB

	ipsetsDataplane dpsets.IPSetsDataplane
	ipSetMetadata   ipsets.IPSetMetadata

	// Hold pending updates.
	vtepsByNode map[string]*proto.VXLANTunnelEndpointUpdate

	// Holds this node's VTEP information.
	myVTEPLock sync.Mutex
	myVTEP     *proto.VXLANTunnelEndpointUpdate

	// VXLAN configuration.
	vxlanDevice string
	vxlanID     int
	vxlanPort   int
	ipVersion   uint8
	mtu         int

	// Indicates if configuration has changed since the last apply.
	vtepsDirty        bool
	externalNodeCIDRs []string
	dpConfig          Config

	// Log context
	logCtx     *logrus.Entry
	opRecorder logutils.OpRecorder
}

type vxlanMgrOption func(m *vxlanManager)

func vxlanMgrWithDualStack() vxlanMgrOption {
	return func(m *vxlanManager) {
		m.routeMgr.maintainIPOnly = true
	}
}

type VXLANFDB interface {
	SetVTEPs(vteps []vxlanfdb.VTEP)
}

func newVXLANManager(
	ipsetsDataplane dpsets.IPSetsDataplane,
	mainRouteTable routetable.Interface,
	fdb VXLANFDB,
	deviceName string,
	ipVersion uint8,
	mtu int,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	opts ...vxlanMgrOption,
) *vxlanManager {
	nlHandle, _ := netlinkshim.NewRealNetlink()
	return newVXLANManagerWithShims(
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

func newVXLANManagerWithShims(
	ipsetsDataplane dpsets.IPSetsDataplane,
	mainRouteTable routetable.Interface,
	fdb VXLANFDB,
	deviceName string,
	ipVersion uint8,
	mtu int,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	nlHandle netlinkHandle,
	opts ...vxlanMgrOption,
) *vxlanManager {
	m := &vxlanManager{
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
		routeMgr: newRouteManager(
			mainRouteTable,
			proto.IPPoolType_VXLAN,
			deviceName,
			ipVersion,
			mtu,
			dpConfig,
			opRecorder,
			nlHandle,
		),
	}

	m.routeMgr.routeClassTunnel = routetable.RouteClassVXLANTunnel
	m.routeMgr.routeClassSameSubnet = routetable.RouteClassVXLANSameSubnet
	m.routeMgr.setTunnelRouteFunc(m.route)
	m.routeMgr.triggerRouteUpdate()

	for _, o := range opts {
		o(m)
	}

	return m
}

func (m *vxlanManager) OnUpdate(protoBufMsg interface{}) {
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
		m.routeMgr.triggerRouteUpdate()
	case *proto.VXLANTunnelEndpointRemove:
		m.logCtx.WithField("msg", msg).Debug("VXLAN manager received VTEP remove")
		if msg.Node == m.hostname {
			m.setLocalVTEP(nil)
		} else {
			delete(m.vtepsByNode, msg.Node)
		}
		m.vtepsDirty = true
		m.routeMgr.triggerRouteUpdate()
	default:
		m.routeMgr.OnUpdate(msg)
	}
}

func (m *vxlanManager) setLocalVTEP(vtep *proto.VXLANTunnelEndpointUpdate) {
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
	m.routeMgr.updateParentIfaceAddr(parentAddr)
}

func (m *vxlanManager) getLocalVTEP() *proto.VXLANTunnelEndpointUpdate {
	m.myVTEPLock.Lock()
	defer m.myVTEPLock.Unlock()
	return m.myVTEP
}

func (m *vxlanManager) CompleteDeferredWork() error {
	if m.vtepsDirty {
		m.updateNeighborsAndAllowedSources()
		m.vtepsDirty = false
	}

	return m.routeMgr.CompleteDeferredWork()
}

func (m *vxlanManager) updateNeighborsAndAllowedSources() {
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

func (m *vxlanManager) route(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
	if isRemoteTunnelRoute(r, proto.IPPoolType_VXLAN) {
		// We treat remote tunnel routes as directly connected. They don't have a gateway of
		// the VTEP because they ARE the VTEP!
		return &routetable.Target{
			CIDR: cidr,
			MTU:  m.mtu,
		}
	}

	// Extract the gateway addr for this route based on its remote VTEP.
	vtep, ok := m.vtepsByNode[r.DstNodeName]
	if !ok {
		// When the VTEP arrives, it'll set routesDirty=true so this loop will execute again.
		return nil
	}
	vtepAddr := vtep.Ipv4Addr
	if m.ipVersion == 6 {
		vtepAddr = vtep.Ipv6Addr
	}
	return &routetable.Target{
		Type: routetable.TargetTypeVXLAN,
		CIDR: cidr,
		GW:   ip.FromString(vtepAddr),
		MTU:  m.mtu,
	}
}

func (m *vxlanManager) KeepVXLANDeviceInSync(
	ctx context.Context,
	mtu int,
	xsumBroken bool,
	wait time.Duration,
	parentIfaceC chan string,
) {
	m.routeMgr.KeepDeviceInSync(ctx, mtu, xsumBroken, wait, parentIfaceC, m.device)
}

func (m *vxlanManager) device(parent netlink.Link) (netlink.Link, string, error) {
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
	}

	if m.dpConfig.BPFEnabled && bpfutils.BTFEnabled {
		vxlan.FlowBased = true
	} else {
		vxlan.VxlanId = m.vxlanID
		vxlan.VtepDevIndex = parent.Attrs().Index
		vxlan.SrcAddr = ip.FromString(parentDeviceIP).AsNetIP()
	}
	return vxlan, addr, nil
}

// vlanLinksIncompat takes two vxlan devices and compares them to make sure they match. If they do not match,
// this function will return a message indicating which configuration is mismatched.
func vxlanLinksIncompat(l1, l2 netlink.Link) string {
	if l1.Type() != l2.Type() {
		return fmt.Sprintf("link type: %v vs %v", l1.Type(), l2.Type())
	}

	v1 := l1.(*netlink.Vxlan)
	v2 := l2.(*netlink.Vxlan)

	if v1.VxlanId != v2.VxlanId {
		return fmt.Sprintf("vni: %v vs %v", v1.VxlanId, v2.VxlanId)
	}

	if v1.VtepDevIndex != v2.VtepDevIndex {
		return fmt.Sprintf("vtep (external) interface: %v vs %v", v1.VtepDevIndex, v2.VtepDevIndex)
	}

	if len(v1.SrcAddr) > 0 && len(v2.SrcAddr) > 0 && !v1.SrcAddr.Equal(v2.SrcAddr) {
		return fmt.Sprintf("vtep (external) IP: %v vs %v", v1.SrcAddr, v2.SrcAddr)
	}

	if len(v1.Group) > 0 && len(v2.Group) > 0 && !v1.Group.Equal(v2.Group) {
		return fmt.Sprintf("group address: %v vs %v", v1.Group, v2.Group)
	}

	if v1.L2miss != v2.L2miss {
		return fmt.Sprintf("l2miss: %v vs %v", v1.L2miss, v2.L2miss)
	}

	if v1.Port > 0 && v2.Port > 0 && v1.Port != v2.Port {
		return fmt.Sprintf("port: %v vs %v", v1.Port, v2.Port)
	}

	if v1.GBP != v2.GBP {
		return fmt.Sprintf("gbp: %v vs %v", v1.GBP, v2.GBP)
	}

	if len(v1.Attrs().HardwareAddr) > 0 && len(v2.Attrs().HardwareAddr) > 0 && !bytes.Equal(v1.Attrs().HardwareAddr, v2.Attrs().HardwareAddr) {
		return fmt.Sprintf("vtep mac addr: %v vs %v", v1.Attrs().HardwareAddr, v2.Attrs().HardwareAddr)
	}

	return ""
}

func parseMacForIPVersion(vtep *proto.VXLANTunnelEndpointUpdate, ipVersion uint8) (net.HardwareAddr, error) {
	switch ipVersion {
	case 4:
		return net.ParseMAC(vtep.Mac)
	case 6:
		return net.ParseMAC(vtep.MacV6)
	default:
		return nil, fmt.Errorf("Invalid IP version")
	}
}
