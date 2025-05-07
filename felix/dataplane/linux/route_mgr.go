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
	"fmt"
	"net"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/ethtool"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/vxlanfdb"
)

type routeManager struct {
	// Our dependencies.
	routeTable routetable.Interface
	ipVersion  uint8
	ippoolType proto.IPPoolType

	// Device information
	dataDevice      string
	tunnelDevice    string
	tunnelDeviceMTU int

	// activeHostnameToIP maps hostname to string IP address. We don't bother to parse into
	// net.IPs because we're going to pass them directly to the IPSet API.
	activeHostnameToIP map[string]string
	ipsetsDataplane    dpsets.IPSetsDataplane
	ipSetMetadata      ipsets.IPSetMetadata

	// Hold pending updates.
	routesByDest    map[string]*proto.RouteUpdate
	localIPAMBlocks map[string]*proto.RouteUpdate
	vtepsByNode     map[string]*proto.VXLANTunnelEndpointUpdate

	// Local information
	hostname       string
	hostAddr       string
	myVTEP         *proto.VXLANTunnelEndpointUpdate
	myInfoLock     sync.Mutex
	myInfoChangedC chan struct{}

	// VXLAN configuration.
	vxlanID   int
	vxlanPort int
	fdb       VXLANFDB

	// Indicates if configuration has changed since the last apply.
	routesDirty       bool
	ipSetDirty        bool
	vtepsDirty        bool
	externalNodeCIDRs []string
	nlHandle          netlinkHandle
	dpConfig          Config
	routeProtocol     netlink.RouteProtocol

	// Log context
	logCtx     *logrus.Entry
	opRecorder logutils.OpRecorder
}

type VXLANFDB interface {
	SetVTEPs(vteps []vxlanfdb.VTEP)
}

func newRouteManager(
	ipsetsDataplane dpsets.IPSetsDataplane,
	mainRouteTable routetable.Interface,
	fdb VXLANFDB,
	tunnelDevice string,
	ippoolType proto.IPPoolType,
	ipVersion uint8,
	mtu int,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
) *routeManager {
	nlHandle, _ := netlinkshim.NewRealNetlink()
	return newRouteManagerWithShims(
		ipsetsDataplane,
		mainRouteTable,
		fdb,
		tunnelDevice,
		ippoolType,
		ipVersion,
		mtu,
		dpConfig,
		opRecorder,
		nlHandle,
	)
}

func newRouteManagerWithShims(
	ipsetsDataplane dpsets.IPSetsDataplane,
	mainRouteTable routetable.Interface,
	fdb VXLANFDB,
	tunnelDevice string,
	ippoolType proto.IPPoolType,
	ipVersion uint8,
	mtu int,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	nlHandle netlinkHandle,
) *routeManager {

	ipsetID := rules.IPSetIDAllVXLANSourceNets
	if ippoolType == proto.IPPoolType_IPIP {
		if ipVersion != 4 {
			logrus.Errorf("Route manager only supports IPIP pool in IPv4")
			return nil
		}

		ipsetID = rules.IPSetIDAllHostNets
	}

	return &routeManager{
		ipsetsDataplane: ipsetsDataplane,
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: dpConfig.MaxIPSetSize,
			SetID:   ipsetID,
			Type:    ipsets.IPSetTypeHashNet,
		},
		activeHostnameToIP: map[string]string{},
		hostname:           dpConfig.Hostname,
		routeTable:         mainRouteTable,
		fdb:                fdb,
		routesByDest:       map[string]*proto.RouteUpdate{},
		localIPAMBlocks:    map[string]*proto.RouteUpdate{},
		vtepsByNode:        map[string]*proto.VXLANTunnelEndpointUpdate{},
		myInfoChangedC:     make(chan struct{}, 1),
		tunnelDevice:       tunnelDevice,
		tunnelDeviceMTU:    mtu,
		vxlanID:            dpConfig.RulesConfig.VXLANVNI,
		vxlanPort:          dpConfig.RulesConfig.VXLANPort,
		ipVersion:          ipVersion,
		ippoolType:         ippoolType,
		externalNodeCIDRs:  dpConfig.ExternalNodesCidrs,
		routesDirty:        true,
		ipSetDirty:         ippoolType == proto.IPPoolType_IPIP,
		vtepsDirty:         ippoolType == proto.IPPoolType_VXLAN,
		dpConfig:           dpConfig,
		nlHandle:           nlHandle,
		routeProtocol:      calculateRouteProtocol(dpConfig),
		logCtx: logrus.WithFields(logrus.Fields{
			"ipVersion":     ipVersion,
			"tunnel device": tunnelDevice,
		}),
		opRecorder: opRecorder,
	}
}

// isRemoteTunnelRoute returns true if the route update signifies a need to program
// a directly connected route on the VXLAN device for a remote tunnel endpoint. This is needed
// in a few cases in order to ensure host <-> pod connectivity over the tunnel.
func isRemoteTunnelRoute(msg *proto.RouteUpdate) bool {
	if msg.IpPoolType != proto.IPPoolType_VXLAN {
		// Not VXLAN - can skip this update.
		return false
	}

	var isRemoteTunnel bool
	var isBlock bool
	isRemoteTunnel = isType(msg, proto.RouteType_REMOTE_TUNNEL)
	isBlock = isType(msg, proto.RouteType_REMOTE_WORKLOAD)

	if isRemoteTunnel && msg.Borrowed {
		// If we receive a route for a borrowed VXLAN tunnel IP, we need to make sure to program a route for it as it
		// won't be covered by the block route.
		return true
	}
	if isRemoteTunnel && isBlock {
		// This happens when tunnel addresses are selected from an IP pool with blocks of a single address.
		// These also need routes of the form "<IP> dev vxlan.calico" rather than "<block> via <VTEP>".
		return true
	}
	return false
}

func (m *routeManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.RouteUpdate:
		// Check to make sure that we are dealing with messages of the correct IP version.
		cidr, err := ip.CIDRFromString(msg.Dst)
		if err != nil {
			m.logCtx.WithError(err).WithField("msg", msg).Warning("Unable to parse route update destination. Skipping update.")
			return
		}
		if m.ipVersion != cidr.Version() {
			// Skip since the update is for a mismatched IP version
			return
		}

		// In case the route changes type to one we no longer care about...
		m.deleteRoute(msg.Dst)

		// Process remote IPAM blocks.
		if isType(msg, proto.RouteType_REMOTE_WORKLOAD) && msg.IpPoolType == m.ippoolType {
			m.logCtx.WithField("msg", msg).Debug("VXLAN data plane received route update")
			m.routesByDest[msg.Dst] = msg
			m.routesDirty = true
		}

		if isRemoteTunnelRoute(msg) {
			m.logCtx.WithField("msg", msg).Debug("VXLAN data plane received route update for remote tunnel endpoint")
			m.routesByDest[msg.Dst] = msg
			m.routesDirty = true
		}

		// Process IPAM blocks that aren't associated to a single or /32 local workload
		if routeIsLocalBlock(msg, m.ippoolType) {
			m.logCtx.WithField("msg", msg).Debug("VXLAN data plane received route update for IPAM block")
			m.localIPAMBlocks[msg.Dst] = msg
			m.routesDirty = true
		} else if _, ok := m.localIPAMBlocks[msg.Dst]; ok {
			m.logCtx.WithField("msg", msg).Debug("VXLAN data plane IPAM block changed to something else")
			delete(m.localIPAMBlocks, msg.Dst)
			m.routesDirty = true
		}

	case *proto.RouteRemove:
		// Check to make sure that we are dealing with messages of the correct IP version.
		cidr, err := ip.CIDRFromString(msg.Dst)
		if err != nil {
			m.logCtx.WithError(err).WithField("msg", msg).Warning("Unable to parse route removal destination. Skipping update.")
			return
		}
		if m.ipVersion != cidr.Version() {
			// Skip since the update is for a mismatched IP version
			return
		}
		m.deleteRoute(msg.Dst)
	case *proto.VXLANTunnelEndpointUpdate:
		if m.ippoolType != proto.IPPoolType_VXLAN {
			// Skip since the update is for a mismatched IP pool type.
			m.logCtx.WithField("msg", msg).Debug("Skipping mismatched ip pool update")
			return
		}

		// Check to make sure that we are dealing with messages of the correct IP version.
		if (m.ipVersion == 4 && msg.Ipv4Addr == "") || (m.ipVersion == 6 && msg.Ipv6Addr == "") {
			// Skip since the update is for a mismatched IP version
			m.logCtx.WithField("msg", msg).Debug("Skipping mismatched IP version update")
			return
		}

		m.logCtx.WithField("msg", msg).Debug("VXLAN data plane received VTEP update")
		if msg.Node == m.hostname {
			m.setLocalVTEP(msg)
		} else {
			m.vtepsByNode[msg.Node] = msg
		}
		m.routesDirty = true
		m.vtepsDirty = true
	case *proto.VXLANTunnelEndpointRemove:
		if m.ippoolType != proto.IPPoolType_VXLAN {
			// Skip since the update is for a mismatched IP pool type.
			m.logCtx.WithField("msg", msg).Debug("Skipping mismatched ip pool update")
			return
		}

		m.logCtx.WithField("msg", msg).Debug("VXLAN data plane received VTEP remove")
		if msg.Node == m.hostname {
			m.setLocalVTEP(nil)
		} else {
			delete(m.vtepsByNode, msg.Node)
		}
		m.routesDirty = true
		m.vtepsDirty = true
	case *proto.HostMetadataUpdate:
		if m.ippoolType != proto.IPPoolType_IPIP {
			// Skip since the update is for a mismatched IP pool type.
			m.logCtx.WithField("msg", msg).Debug("Skipping mismatched ip pool update")
			return
		}

		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host update/create")
		if msg.Hostname == m.hostname {
			logrus.Info("pepsi")
			m.setLocalHostAddr(msg.Ipv4Addr)
		}
		m.activeHostnameToIP[msg.Hostname] = msg.Ipv4Addr
		m.ipSetDirty = true
		m.routesDirty = true
	case *proto.HostMetadataRemove:
		if m.ippoolType != proto.IPPoolType_IPIP {
			// Skip since the update is for a mismatched IP pool type.
			m.logCtx.WithField("msg", msg).Debug("Skipping mismatched ip pool update")
			return
		}

		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host removed")
		if msg.Hostname == m.hostname {
			m.setLocalHostAddr("")
		}
		delete(m.activeHostnameToIP, msg.Hostname)
		m.ipSetDirty = true
		m.routesDirty = true
	}
}

func (m *routeManager) deleteRoute(dst string) {
	_, exists := m.routesByDest[dst]
	if exists {
		logrus.Debug("deleting route dst ", dst)
		// In case the route changes type to one we no longer care about...
		delete(m.routesByDest, dst)
		m.routesDirty = true
	}

	if _, exists := m.localIPAMBlocks[dst]; exists {
		logrus.Debug("deleting local ipam dst ", dst)
		delete(m.localIPAMBlocks, dst)
		m.routesDirty = true
	}
}

func (m *routeManager) setLocalVTEP(vtep *proto.VXLANTunnelEndpointUpdate) {
	m.myInfoLock.Lock()
	defer m.myInfoLock.Unlock()
	m.myVTEP = vtep
	select {
	case m.myInfoChangedC <- struct{}{}:
	default:
	}
}

func (m *routeManager) getLocalVTEP() *proto.VXLANTunnelEndpointUpdate {
	m.myInfoLock.Lock()
	defer m.myInfoLock.Unlock()
	return m.myVTEP
}

func (m *routeManager) setLocalHostAddr(address string) {
	m.myInfoLock.Lock()
	defer m.myInfoLock.Unlock()
	m.hostAddr = address
	select {
	case m.myInfoChangedC <- struct{}{}:
	default:
	}
}

func (m *routeManager) getLocalHostAddr() string {
	m.myInfoLock.Lock()
	defer m.myInfoLock.Unlock()
	return m.hostAddr
}

func (m *routeManager) ipipEnabled() bool {
	return m.ippoolType == proto.IPPoolType_IPIP
}

func (m *routeManager) vxlanEnabled() bool {
	return m.ippoolType == proto.IPPoolType_VXLAN
}

func (m *routeManager) CompleteDeferredWork() error {
	if m.dataDevice == "" {
		// Background goroutine hasn't sent us the parent interface name yet,
		// but we can look it up synchronously.  OnParentNameUpdate will handle
		// any duplicate update when it arrives.
		dataIface, err := m.detectDataIface()
		if err != nil {
			// If we can't look up the parent interface then we're in trouble.
			// It likely means that our VTEP is missing or conflicting.  We
			// won't be able to program same-subnet routes at all, so we'll
			// fall back to programming all tunnel routes.  However, unless the
			// VXLAN device happens to already exist, we won't be able to
			// program tunnel routes either.  The RouteTable will be the
			// component that spots that the interface is missing.
			//
			// Note: this behaviour changed when we unified all the main
			// RouteTable instances into one.  Before that change, we chose to
			// defer creation of our "no encap" RouteTable, so that the
			// dataplane would stay untouched until the conflict was resolved.
			// With only a single RouteTable, we need a different fallback.
			m.logCtx.WithError(err).WithField("localVTEP", m.getLocalVTEP()).Error(
				"Failed to find VXLAN tunnel device parent. Missing/conflicting local VTEP? VXLAN route " +
					"programming is likely to fail.")
		} else {
			m.dataDevice = dataIface.Attrs().Name
			m.routesDirty = true
		}
	}

	if m.ipSetDirty {
		m.updateAllHostsIPSet()
		m.ipSetDirty = false
	}

	if m.vtepsDirty {
		m.updateNeighborsAndAllowedSources()
		m.vtepsDirty = false
	}

	if m.routesDirty {
		m.updateRoutes()
		m.routesDirty = false
	}

	return nil
}

func (m *routeManager) updateAllHostsIPSet() {
	// For simplicity (and on the assumption that host add/removes are rare) rewrite
	// the whole IP set whenever we get a change. To replace this with delta handling
	// would require reference counting the IPs because it's possible for two hosts
	// to (at least transiently) share an IP. That would add occupancy and make the
	// code more complex.
	m.logCtx.Info("All-hosts IP set out-of sync, refreshing it.")
	members := make([]string, 0, len(m.activeHostnameToIP)+len(m.externalNodeCIDRs))
	for _, ip := range m.activeHostnameToIP {
		members = append(members, ip)
	}
	members = append(members, m.externalNodeCIDRs...)
	m.ipsetsDataplane.AddOrReplaceIPSet(m.ipSetMetadata, members)
}

func (m *routeManager) updateNeighborsAndAllowedSources() {
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

func (m *routeManager) updateRoutes() {
	// Iterate through all of our L3 routes and send them through to the
	// RouteTable.  It's a little wasteful to recalculate everything but the
	// RouteTable will avoid making dataplane changes for routes that haven't
	// changed.
	m.opRecorder.RecordOperation("update-vxlan-routes")
	var vxlanRoutes []routetable.Target
	var noEncapRoutes []routetable.Target
	for _, r := range m.routesByDest {
		logCtx := m.logCtx.WithField("route", r)
		cidr, err := ip.CIDRFromString(r.Dst)
		if err != nil {
			// Don't block programming of other routes if somehow we receive one with a bad dst.
			logCtx.WithError(err).Warn("Failed to parse VXLAN route destination")
			continue
		}

		if noEncapRoute := noEncapRoute(m.dataDevice, cidr, r, m.routeProtocol); noEncapRoute != nil {
			// We've got everything we need to program this route as a no-encap route.
			noEncapRoutes = append(noEncapRoutes, *noEncapRoute)
			logCtx.WithField("route", r).Debug("Destination in same subnet, using no-encap route.")
		} else if vxlanRoute := m.tunneledRoute(cidr, r); vxlanRoute != nil {
			vxlanRoutes = append(vxlanRoutes, *vxlanRoute)
			logCtx.WithField("route", vxlanRoute).Debug("adding vxlan route to list for addition")
		} else {
			logCtx.Debug("Not enough information to program route; missing VTEP?")
		}
	}

	m.logCtx.WithField("routes", vxlanRoutes).Debug("VXLAN manager setting VXLAN tunneled routes")
	m.routeTable.SetRoutes(routetable.RouteClassVXLANTunnel, m.tunnelDevice, vxlanRoutes)

	bhRoutes := blackholeRoutes(m.localIPAMBlocks, m.routeProtocol)
	m.logCtx.WithField("routes", bhRoutes).Debug("VXLAN manager setting blackhole routes")
	m.routeTable.SetRoutes(routetable.RouteClassIPAMBlockDrop, routetable.InterfaceNone, bhRoutes)

	if m.dataDevice != "" {
		m.logCtx.WithFields(logrus.Fields{
			"noEncapDevice": m.dataDevice,
			"routes":        noEncapRoutes,
		}).Debug("VXLAN manager sending unencapsulated L3 updates")
		m.routeTable.SetRoutes(routetable.RouteClassVXLANSameSubnet, m.dataDevice, noEncapRoutes)
	} else {
		m.logCtx.Debug("VXLAN manager not sending unencapsulated L3 updates, no parent interface.")
	}
}

func (m *routeManager) tunneledRoute(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
	switch m.ippoolType {
	case proto.IPPoolType_IPIP:
		return m.ipipRoute(cidr, r)
	case proto.IPPoolType_VXLAN:
		return m.vxlanRoute(cidr, r)
	default:
		panic("unknown IP pool type is set.")
	}
}

func (m *routeManager) ipipRoute(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
	// Extract the gateway addr for this route based on its remote address.
	remoteAddr, ok := m.activeHostnameToIP[r.DstNodeName]
	if !ok {
		// When the local address arrives, it'll set routesDirty=true so this loop will execute again.
		return nil
	}

	return &routetable.Target{
		Type:     routetable.TargetTypeOnLink,
		CIDR:     cidr,
		GW:       ip.FromString(remoteAddr),
		Protocol: m.routeProtocol,
		MTU:      m.dpConfig.IPIPMTU,
	}
}

func (m *routeManager) vxlanRoute(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
	if isRemoteTunnelRoute(r) {
		// We treat remote tunnel routes as directly connected. They don't have a gateway of
		// the VTEP because they ARE the VTEP!
		return &routetable.Target{
			CIDR: cidr,
			MTU:  m.tunnelDeviceMTU,
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
		MTU:  m.tunnelDeviceMTU,
	}
}

func (m *routeManager) OnDataDeviceUpdate(name string) {
	if name == "" {
		m.logCtx.Warn("Empty data interface name? Ignoring.")
		return
	}
	if name == m.dataDevice {
		return
	}
	if m.dataDevice != "" {
		// We're changing parent interface, remove the old routes.
		routeClass := routetable.RouteClassVXLANSameSubnet
		if m.ipipEnabled() {
			routeClass = routetable.RouteClassIPIPSameSubnet
		}
		m.routeTable.SetRoutes(routeClass, m.dataDevice, nil)
	}
	m.dataDevice = name
	m.routesDirty = true
}

// checks that it is still correctly configured.
func (m *routeManager) KeepDeviceInSync(mtu int, xsumBroken bool, wait time.Duration, dataIfaceC chan string) {
	m.logCtx.WithFields(logrus.Fields{
		"device":     m.tunnelDevice,
		"mtu":        mtu,
		"xsumBroken": xsumBroken,
		"wait":       wait,
	}).Info("IPIP device thread started.")
	logNextSuccess := true
	dataIface := ""

	sleepMonitoringChans := func(maxDuration time.Duration) {
		timer := time.NewTimer(maxDuration)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-m.myInfoChangedC:
			logrus.Debug("Sleep returning early: local information changed.")
		}
	}

	for {
		if m.missingLocalInfo() {
			m.logCtx.Debug("Missing local address information, retrying...")
			sleepMonitoringChans(10 * time.Second)
			continue
		}

		dataDevice, err := m.detectDataIface()
		if err != nil {
			m.logCtx.WithError(err).Warn("Failed to find noEncap device, retrying...")
			sleepMonitoringChans(1 * time.Second)
			continue
		}

		m.logCtx.Debug("Configuring IPIP device")
		if m.ipipEnabled() {
			err = m.configureIPIPDevice(mtu, xsumBroken)
		} else {
			err = m.configureVXLANDevice(mtu, xsumBroken)
		}
		if err != nil {
			m.logCtx.WithError(err).Warn("Failed to configure IPIP tunnel device, retrying...")
			logNextSuccess = true
			sleepMonitoringChans(1 * time.Second)
			continue
		}

		newDataIface := dataDevice.Attrs().Name
		if newDataIface != dataIface {
			// Send a message back to the main loop to tell it to update the
			// routing tables.
			m.logCtx.Infof("data device changed from %q to %q", dataIface, newDataIface)
			select {
			case dataIfaceC <- newDataIface:
				dataIface = newDataIface
			case <-m.myInfoChangedC:
				m.logCtx.Info("My information changed; restarting configuration.")
				continue
			}
		}

		if logNextSuccess {
			m.logCtx.Info("IPIP tunnel device configured")
			logNextSuccess = false
		}
		sleepMonitoringChans(wait)
	}
}

func (m *routeManager) missingLocalInfo() bool {
	return (m.vxlanEnabled() && m.getLocalVTEP() == nil) ||
		(m.ipipEnabled() && m.getLocalHostAddr() == "")
}

func (m *routeManager) detectDataIface() (netlink.Link, error) {
	var dataAddr string
	if m.vxlanEnabled() {
		localVTEP := m.getLocalVTEP()
		if localVTEP == nil {
			return nil, fmt.Errorf("local VTEP not yet known")
		}
		dataAddr = localVTEP.ParentDeviceIp
		if m.ipVersion == 6 {
			dataAddr = localVTEP.ParentDeviceIpv6
		}
	} else if m.ipipEnabled() {
		dataAddr = m.getLocalHostAddr()
	}

	if dataAddr == "" {
		return nil, fmt.Errorf("failed to find data interface address")
	}

	m.logCtx.WithField("address", dataAddr).Debug("Getting data interface")
	links, err := m.nlHandle.LinkList()
	if err != nil {
		return nil, err
	}

	family := netlink.FAMILY_V4
	if m.ipVersion == 6 {
		family = netlink.FAMILY_V6
	}

	for _, link := range links {
		addrs, err := m.nlHandle.AddrList(link, family)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if addr.IPNet.IP.String() == dataAddr {
				m.logCtx.Debugf("Found data interface: %s", link)
				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("Unable to find data interface with address %s", dataAddr)
}

// configureVXLANDevice ensures the VXLAN tunnel device is up and configured correctly.
func (m *routeManager) configureVXLANDevice(mtu int, xsumBroken bool) error {
	localVTEP := m.getLocalVTEP()
	addr := localVTEP.Ipv4Addr
	parentDeviceIP := localVTEP.ParentDeviceIp
	if m.ipVersion == 6 {
		addr = localVTEP.Ipv6Addr
		parentDeviceIP = localVTEP.ParentDeviceIpv6
	}
	parent, err := m.detectDataIface()
	if err != nil {
		return err
	}
	mac, err := parseMacForIPVersion(localVTEP, m.ipVersion)
	if err != nil {
		return err
	}
	la := netlink.NewLinkAttrs()
	la.Name = m.tunnelDevice
	la.HardwareAddr = mac
	vxlan := &netlink.Vxlan{
		LinkAttrs:    la,
		VxlanId:      m.vxlanID,
		Port:         m.vxlanPort,
		VtepDevIndex: parent.Attrs().Index,
		SrcAddr:      ip.FromString(parentDeviceIP).AsNetIP(),
	}

	return m.configureTunnelDevice(vxlan, addr, mtu, xsumBroken)
}

// configureIPIPDevice ensures the IPIP tunnel device is up and configures correctly.
func (m *routeManager) configureIPIPDevice(mtu int, xsumBroken bool) error {
	la := netlink.NewLinkAttrs()
	la.Name = m.tunnelDevice
	ipip := &netlink.Iptun{
		LinkAttrs: la,
	}
	address := m.dpConfig.RulesConfig.IPIPTunnelAddress

	if len(address) == 0 {
		return fmt.Errorf("Address is not set")
	}
	return m.configureTunnelDevice(ipip, address.String(), mtu, xsumBroken)
}

func (m *routeManager) configureTunnelDevice(newLink netlink.Link, addr string, mtu int, xsumBroken bool) error {
	if newLink == nil {
		return fmt.Errorf("no tunnel link provided")
	}
	logCtx := m.logCtx.WithFields(logrus.Fields{
		"mtu":        mtu,
		"tunnelAddr": addr,
	})
	logCtx.Debug("Configuring tunnel device")
	// Try to get the device.
	link, err := m.nlHandle.LinkByName(m.tunnelDevice)
	if err != nil {
		m.logCtx.WithError(err).Info("Failed to get VXLAN tunnel device, assuming it isn't present")
		if err := m.nlHandle.LinkAdd(newLink); err == syscall.EEXIST {
			// Device already exists - likely a race.
			m.logCtx.Debug("VXLAN device already exists, likely created by someone else.")
		} else if err != nil {
			// Error other than "device exists" - return it.
			return err
		}

		// The device now exists - requery it to check that the link exists and is a vxlan device.
		link, err = m.nlHandle.LinkByName(m.tunnelDevice)
		if err != nil {
			return fmt.Errorf("can't locate created vxlan device %v", m.tunnelDevice)
		}
	}

	if m.vxlanEnabled() {
		// At this point, we have successfully queried the existing device, or made sure it exists if it didn't
		// already. Check for mismatched configuration. If they don't match, recreate the device.
		if incompat := vxlanLinksIncompat(newLink, link); incompat != "" {
			// Existing device doesn't match desired configuration - delete it and recreate.
			logrus.Warningf("%q exists with incompatible configuration: %v; recreating device", m.tunnelDevice, incompat)
			if err = m.nlHandle.LinkDel(link); err != nil {
				return fmt.Errorf("failed to delete interface: %v", err)
			}
			if err = m.nlHandle.LinkAdd(newLink); err != nil {
				if err == syscall.EEXIST {
					logrus.Warnf("Failed to create VXLAN device. Another device with this VNI may already exist")
				}
				return fmt.Errorf("failed to create vxlan interface: %v", err)
			}
			link, err = m.nlHandle.LinkByName(m.tunnelDevice)
			if err != nil {
				return err
			}
		}
	}

	// Make sure the MTU is set correctly.
	attrs := link.Attrs()
	oldMTU := attrs.MTU
	if oldMTU != mtu {
		m.logCtx.WithFields(logrus.Fields{"old": oldMTU, "new": mtu}).Info("VXLAN device MTU needs to be updated")
		if err := m.nlHandle.LinkSetMTU(link, mtu); err != nil {
			m.logCtx.WithError(err).Warn("Failed to set vxlan tunnel device MTU")
		} else {
			m.logCtx.Info("Updated vxlan tunnel MTU")
		}
	}

	// Make sure the IP address is configured.
	if err := m.ensureAddressOnLink(addr, link); err != nil {
		return fmt.Errorf("failed to ensure address of interface: %s", err)
	}

	// If required, disable checksum offload.
	if xsumBroken {
		if err := ethtool.EthtoolTXOff(m.tunnelDevice); err != nil {
			return fmt.Errorf("failed to disable checksum offload: %s", err)
		}
	}

	// And the device is up.
	if err := m.nlHandle.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set interface up: %w", err)
	}

	return nil
}

// ensureAddressOnLink ensures that the provided IP address is configured on the provided Link. If there are other addresses,
// this function will remove them, ensuring that the desired IP address is the _only_ address on the Link.
func (m *routeManager) ensureAddressOnLink(ipStr string, link netlink.Link) error {
	suffix := "/32"
	family := netlink.FAMILY_V4
	if m.ipVersion == 6 {
		suffix = "/128"
		family = netlink.FAMILY_V6
	}
	_, net, err := net.ParseCIDR(ipStr + suffix)
	if err != nil {
		return err
	}
	addr := netlink.Addr{IPNet: net}
	existingAddrs, err := m.nlHandle.AddrList(link, family)
	if err != nil {
		return err
	}

	// Remove any addresses which we don't want.
	addrPresent := false
	for _, existing := range existingAddrs {
		if reflect.DeepEqual(existing.IPNet, addr.IPNet) {
			addrPresent = true
			continue
		}
		m.logCtx.WithFields(logrus.Fields{
			"address": existing,
			"link":    link.Attrs().Name,
		}).Warn("Removing unwanted IP from VXLAN device")
		if err := m.nlHandle.AddrDel(link, &existing); err != nil {
			return fmt.Errorf("failed to remove IP address %s", existing)
		}
	}

	// Actually add the desired address to the interface if needed.
	if !addrPresent {
		m.logCtx.WithFields(logrus.Fields{"address": addr}).Info("Assigning address to VXLAN device")
		if err := m.nlHandle.AddrAdd(link, &addr); err != nil {
			return fmt.Errorf("failed to add IP address")
		}
	}
	return nil
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

	if v1.VtepDevIndex > 0 && v2.VtepDevIndex > 0 && v1.VtepDevIndex != v2.VtepDevIndex {
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
