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
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
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

type vxlanManager struct {
	// Our dependencies.
	hostname        string
	routeTable      routetable.Interface
	parentIfaceName string
	fdb             VXLANFDB

	// Hold pending updates.
	routesByDest    map[string]*proto.RouteUpdate
	localIPAMBlocks map[string]*proto.RouteUpdate
	vtepsByNode     map[string]*proto.VXLANTunnelEndpointUpdate

	// Holds this node's VTEP information.
	myVTEPLock     sync.Mutex
	myVTEPChangedC chan struct{}
	myVTEP         *proto.VXLANTunnelEndpointUpdate

	// VXLAN configuration.
	vxlanDevice string
	vxlanID     int
	vxlanPort   int
	ipVersion   uint8
	mtu         int

	// Indicates if configuration has changed since the last apply.
	routesDirty       bool
	ipsetsDataplane   dpsets.IPSetsDataplane
	ipSetMetadata     ipsets.IPSetMetadata
	externalNodeCIDRs []string
	vtepsDirty        bool
	nlHandle          netlinkHandle
	dpConfig          Config
	noEncapProtocol   netlink.RouteProtocol

	// Log context
	logCtx     *logrus.Entry
	opRecorder logutils.OpRecorder
}

type VXLANFDB interface {
	SetVTEPs(vteps []vxlanfdb.VTEP)
}

func newVXLANManager(
	ipsetsDataplane dpsets.IPSetsDataplane,
	mainRouteTable routetable.Interface,
	fdb VXLANFDB,
	deviceName string,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	ipVersion uint8,
	mtu int,
) *vxlanManager {
	nlHandle, _ := netlinkshim.NewRealNetlink()
	return newVXLANManagerWithShims(
		ipsetsDataplane,
		mainRouteTable,
		fdb,
		deviceName,
		dpConfig,
		opRecorder,
		nlHandle,
		ipVersion,
		mtu,
	)
}

func newVXLANManagerWithShims(
	ipsetsDataplane dpsets.IPSetsDataplane,
	mainRouteTable routetable.Interface,
	fdb VXLANFDB,
	deviceName string,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	nlHandle netlinkHandle,
	ipVersion uint8,
	mtu int,
) *vxlanManager {
	logCtx := logrus.WithField("ipVersion", ipVersion)
	return &vxlanManager{
		ipsetsDataplane: ipsetsDataplane,
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: dpConfig.MaxIPSetSize,
			SetID:   rules.IPSetIDAllVXLANSourceNets,
			Type:    ipsets.IPSetTypeHashNet,
		},
		hostname:          dpConfig.Hostname,
		routeTable:        mainRouteTable,
		fdb:               fdb,
		routesByDest:      map[string]*proto.RouteUpdate{},
		localIPAMBlocks:   map[string]*proto.RouteUpdate{},
		vtepsByNode:       map[string]*proto.VXLANTunnelEndpointUpdate{},
		myVTEPChangedC:    make(chan struct{}, 1),
		vxlanDevice:       deviceName,
		vxlanID:           dpConfig.RulesConfig.VXLANVNI,
		vxlanPort:         dpConfig.RulesConfig.VXLANPort,
		ipVersion:         ipVersion,
		mtu:               mtu,
		externalNodeCIDRs: dpConfig.ExternalNodesCidrs,
		routesDirty:       true,
		vtepsDirty:        true,
		dpConfig:          dpConfig,
		nlHandle:          nlHandle,
		noEncapProtocol:   calculateNonEncapRouteProtocol(dpConfig),
		logCtx:            logCtx,
		opRecorder:        opRecorder,
	}
}

func calculateNonEncapRouteProtocol(dpConfig Config) netlink.RouteProtocol {
	// For same-subnet and blackhole routes, we need a unique protocol
	// to attach to the routes.  If the global DeviceRouteProtocol is set to
	// a usable value, use that; otherwise, pick a safer default.  (For back
	// compatibility, our DeviceRouteProtocol defaults to RTPROT_BOOT, which
	// can also be used by other processes.)
	//
	// Routes to the VXLAN tunnel device itself are identified by their target
	// interface.  We don't need to worry about their protocol.
	noEncapProtocol := dataplanedefs.VXLANDefaultProto
	if dpConfig.DeviceRouteProtocol != syscall.RTPROT_BOOT {
		noEncapProtocol = dpConfig.DeviceRouteProtocol
	}
	return noEncapProtocol
}

func isType(msg *proto.RouteUpdate, t proto.RouteType) bool {
	return msg.Types&t == t
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

func (m *vxlanManager) OnUpdate(protoBufMsg interface{}) {
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
		if isType(msg, proto.RouteType_REMOTE_WORKLOAD) && msg.IpPoolType == proto.IPPoolType_VXLAN {
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
		if routeIsLocalVXLANBlock(msg) {
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
		m.logCtx.WithField("msg", msg).Debug("VXLAN data plane received VTEP remove")
		if msg.Node == m.hostname {
			m.setLocalVTEP(nil)
		} else {
			delete(m.vtepsByNode, msg.Node)
		}
		m.routesDirty = true
		m.vtepsDirty = true
	}
}

func routeIsLocalVXLANBlock(msg *proto.RouteUpdate) bool {
	// RouteType_LOCAL_WORKLOAD means "local IPAM block _or_ /32 of workload" in IPv4.
	// It means "local IPAM block _or_ /128 of workload" in IPv6.
	if !isType(msg, proto.RouteType_LOCAL_WORKLOAD) {
		return false
	}
	// Only care about VXLAN blocks.
	if msg.IpPoolType != proto.IPPoolType_VXLAN {
		return false
	}
	// Ignore routes that we know are from local workload endpoints.
	if msg.LocalWorkload {
		return false
	}

	// Check the valid suffix depending on IP version.
	cidr, err := ip.CIDRFromString(msg.Dst)
	if err != nil {
		logrus.WithError(err).WithField("msg", msg).Warning("Unable to parse destination into a CIDR. Treating block as external.")
	}
	if cidr.Version() == 4 {
		// This is an IPv4 route.
		// Ignore /32 routes in any case for two reasons:
		// * If we have a /32 block then our blackhole route would stop the CNI plugin from programming its /32 for a
		//   newly added workload.
		// * If this isn't a /32 block then it must be a borrowed /32 from another block.  In that case, we know we're
		//   racing with CNI, adding a new workload.  We've received the borrowed IP but not the workload endpoint yet.
		if strings.HasSuffix(msg.Dst, "/32") {
			return false
		}
	} else {
		// This is an IPv6 route.
		// Ignore /128 routes in any case for two reasons:
		// * If we have a /128 block then our blackhole route would stop the CNI plugin from programming its /128 for a
		//   newly added workload.
		// * If this isn't a /128 block then it must be a borrowed /128 from another block.  In that case, we know we're
		//   racing with CNI, adding a new workload.  We've received the borrowed IP but not the workload endpoint yet.
		if strings.HasSuffix(msg.Dst, "/128") {
			return false
		}
	}
	return true
}

func (m *vxlanManager) deleteRoute(dst string) {
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

func (m *vxlanManager) setLocalVTEP(vtep *proto.VXLANTunnelEndpointUpdate) {
	m.myVTEPLock.Lock()
	defer m.myVTEPLock.Unlock()
	m.myVTEP = vtep
	select {
	case m.myVTEPChangedC <- struct{}{}:
	default:
	}
}

func (m *vxlanManager) getLocalVTEP() *proto.VXLANTunnelEndpointUpdate {
	m.myVTEPLock.Lock()
	defer m.myVTEPLock.Unlock()
	return m.myVTEP
}

func (m *vxlanManager) getLocalVTEPParent() (netlink.Link, error) {
	return m.getParentInterface(m.getLocalVTEP())
}

func (m *vxlanManager) blackholeRoutes() []routetable.Target {
	var rtt []routetable.Target
	for dst := range m.localIPAMBlocks {
		cidr, err := ip.CIDRFromString(dst)
		if err != nil {
			m.logCtx.WithError(err).Warning(
				"Error processing IPAM block CIDR: ", dst,
			)
			continue
		}
		rtt = append(rtt, routetable.Target{
			Type:     routetable.TargetTypeBlackhole,
			CIDR:     cidr,
			Protocol: m.noEncapProtocol,
		})
	}
	m.logCtx.Debug("calculated blackholes ", rtt)
	return rtt
}

func (m *vxlanManager) CompleteDeferredWork() error {
	if m.parentIfaceName == "" {
		// Background goroutine hasn't sent us the parent interface name yet,
		// but we can look it up synchronously.  OnParentNameUpdate will handle
		// any duplicate update when it arrives.
		parent, err := m.getLocalVTEPParent()
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
			m.parentIfaceName = parent.Attrs().Name
			m.routesDirty = true
		}
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

func (m *vxlanManager) updateRoutes() {
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

		if noEncapRoute := m.noEncapRoute(cidr, r); noEncapRoute != nil {
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

	m.logCtx.WithField("vxlanRoutes", vxlanRoutes).Debug("VXLAN manager setting VXLAN tunneled routes")
	m.routeTable.SetRoutes(routetable.RouteClassVXLANTunnel, m.vxlanDevice, vxlanRoutes)
	m.routeTable.SetRoutes(routetable.RouteClassIPAMBlockDrop, routetable.InterfaceNone, m.blackholeRoutes())

	if m.parentIfaceName != "" {
		m.logCtx.WithFields(logrus.Fields{
			"noEncapDevice": m.parentIfaceName,
			"routes":        noEncapRoutes,
		}).Debug("VXLAN manager sending unencapsulated L3 updates")
		m.routeTable.SetRoutes(routetable.RouteClassVXLANSameSubnet, m.parentIfaceName, noEncapRoutes)
	} else {
		m.logCtx.Debug("VXLAN manager not sending unencapsulated L3 updates, no parent interface.")
	}
}

func (m *vxlanManager) noEncapRoute(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
	if !r.GetSameSubnet() {
		return nil
	}
	if m.parentIfaceName == "" {
		return nil
	}
	if r.DstNodeIp == "" {
		return nil
	}
	noEncapRoute := routetable.Target{
		Type:     routetable.TargetTypeNoEncap,
		CIDR:     cidr,
		GW:       ip.FromString(r.DstNodeIp),
		Protocol: m.noEncapProtocol,
	}
	return &noEncapRoute
}

func (m *vxlanManager) tunneledRoute(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
	if isRemoteTunnelRoute(r) {
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

func (m *vxlanManager) OnParentNameUpdate(name string) {
	if name == "" {
		m.logCtx.Warn("Empty parent interface name? Ignoring.")
		return
	}
	if name == m.parentIfaceName {
		return
	}
	if m.parentIfaceName != "" {
		// We're changing parent interface, remove the old routes.
		m.routeTable.SetRoutes(routetable.RouteClassVXLANSameSubnet, m.parentIfaceName, nil)
	}
	m.parentIfaceName = name
	m.routesDirty = true
}

// KeepVXLANDeviceInSync is a goroutine that configures the VXLAN tunnel device, then periodically
// checks that it is still correctly configured.
func (m *vxlanManager) KeepVXLANDeviceInSync(
	ctx context.Context,
	mtu int,
	xsumBroken bool,
	wait time.Duration,
	parentNameC chan string,
) {
	m.logCtx.WithFields(logrus.Fields{
		"mtu":        mtu,
		"xsumBroken": xsumBroken,
		"wait":       wait,
	}).Info("VXLAN tunnel device thread started.")
	logNextSuccess := true
	parentName := ""

	sleepMonitoringChans := func(maxDuration time.Duration) {
		timer := time.NewTimer(maxDuration)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			logrus.Debug("Sleep returning early: context finished.")
		case <-m.myVTEPChangedC:
			logrus.Debug("Sleep returning early: VTEP changed.")
		}
	}

	for ctx.Err() == nil {
		localVTEP := m.getLocalVTEP()
		if localVTEP == nil {
			m.logCtx.Debug("Missing local VTEP information, retrying...")
			sleepMonitoringChans(10 * time.Second)
			continue
		}

		parent, err := m.getLocalVTEPParent()
		if err != nil {
			m.logCtx.WithError(err).Warn("Failed to find VXLAN tunnel device parent, retrying...")
			sleepMonitoringChans(1 * time.Second)
			continue
		}

		m.logCtx.WithField("localVTEP", localVTEP).Debug("Configuring VXLAN device")
		err = m.configureVXLANDevice(mtu, localVTEP, xsumBroken)
		if err != nil {
			m.logCtx.WithError(err).Warn("Failed to configure VXLAN tunnel device, retrying...")
			logNextSuccess = true
			sleepMonitoringChans(1 * time.Second)
			continue
		}

		newParentName := parent.Attrs().Name
		if newParentName != parentName {
			// Send a message back to the main loop to tell it to update the
			// routing tables.
			m.logCtx.Infof("VXLAN device parent changed from %q to %q", parentName, newParentName)
			select {
			case parentNameC <- newParentName:
				parentName = newParentName
			case <-m.myVTEPChangedC:
				m.logCtx.Info("My VTEP changed; restarting configuration.")
				continue
			case <-ctx.Done():
				continue
			}
		}

		if logNextSuccess {
			m.logCtx.Info("VXLAN tunnel device configured")
			logNextSuccess = false
		}
		sleepMonitoringChans(wait)
	}
	m.logCtx.Info("KeepVXLANDeviceInSync exiting due to context.")
}

// getParentInterface returns the parent interface for the given local VTEP based on IP address. This link returned is nil
// if, and only if, an error occurred
func (m *vxlanManager) getParentInterface(localVTEP *proto.VXLANTunnelEndpointUpdate) (netlink.Link, error) {
	if localVTEP == nil {
		return nil, fmt.Errorf("local VTEP not yet known")
	}
	m.logCtx.WithField("localVTEP", localVTEP).Debug("Getting parent interface")
	links, err := m.nlHandle.LinkList()
	if err != nil {
		return nil, err
	}

	family := netlink.FAMILY_V4
	parentDeviceIP := localVTEP.ParentDeviceIp
	if m.ipVersion == 6 {
		family = netlink.FAMILY_V6
		parentDeviceIP = localVTEP.ParentDeviceIpv6
	}
	for _, link := range links {
		addrs, err := m.nlHandle.AddrList(link, family)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if addr.IPNet.IP.String() == parentDeviceIP {
				m.logCtx.Debugf("Found parent interface: %+v", link)
				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("unable to find parent interface with address %s", parentDeviceIP)
}

// configureVXLANDevice ensures the VXLAN tunnel device is up and configured correctly.
func (m *vxlanManager) configureVXLANDevice(
	mtu int,
	localVTEP *proto.VXLANTunnelEndpointUpdate,
	xsumBroken bool,
) error {
	logCtx := m.logCtx.WithFields(logrus.Fields{"device": m.vxlanDevice})
	logCtx.Debug("Configuring VXLAN tunnel device")
	parent, err := m.getParentInterface(localVTEP)
	if err != nil {
		return err
	}
	mac, err := parseMacForIPVersion(localVTEP, m.ipVersion)
	if err != nil {
		return err
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
		LinkAttrs:    la,
		VxlanId:      m.vxlanID,
		Port:         m.vxlanPort,
		VtepDevIndex: parent.Attrs().Index,
		SrcAddr:      ip.FromString(parentDeviceIP).AsNetIP(),
	}

	// Try to get the device.
	link, err := m.nlHandle.LinkByName(m.vxlanDevice)
	if err != nil {
		m.logCtx.WithError(err).Info("Failed to get VXLAN tunnel device, assuming it isn't present")
		if err := m.nlHandle.LinkAdd(vxlan); err == syscall.EEXIST {
			// Device already exists - likely a race.
			m.logCtx.Debug("VXLAN device already exists, likely created by someone else.")
		} else if err != nil {
			// Error other than "device exists" - return it.
			return err
		}

		// The device now exists - requery it to check that the link exists and is a vxlan device.
		link, err = m.nlHandle.LinkByName(m.vxlanDevice)
		if err != nil {
			return fmt.Errorf("can't locate created vxlan device %v", m.vxlanDevice)
		}
	}

	// At this point, we have successfully queried the existing device, or made sure it exists if it didn't
	// already. Check for mismatched configuration. If they don't match, recreate the device.
	if incompat := vxlanLinksIncompat(vxlan, link); incompat != "" {
		// Existing device doesn't match desired configuration - delete it and recreate.
		logrus.Warningf("%q exists with incompatible configuration: %v; recreating device", vxlan.Name, incompat)
		if err = m.nlHandle.LinkDel(link); err != nil {
			return fmt.Errorf("failed to delete interface: %v", err)
		}
		if err = m.nlHandle.LinkAdd(vxlan); err != nil {
			if err == syscall.EEXIST {
				logrus.Warnf("Failed to create VXLAN device. Another device with this VNI may already exist")
			}
			return fmt.Errorf("failed to create vxlan interface: %v", err)
		}
		link, err = m.nlHandle.LinkByName(vxlan.Name)
		if err != nil {
			return err
		}
	}

	// Make sure the MTU is set correctly.
	attrs := link.Attrs()
	oldMTU := attrs.MTU
	if oldMTU != mtu {
		logCtx.WithFields(logrus.Fields{"old": oldMTU, "new": mtu}).Info("VXLAN device MTU needs to be updated")
		if err := m.nlHandle.LinkSetMTU(link, mtu); err != nil {
			m.logCtx.WithError(err).Warn("Failed to set vxlan tunnel device MTU")
		} else {
			logCtx.Info("Updated vxlan tunnel MTU")
		}
	}

	// Make sure the IP address is configured.
	if err := m.ensureAddressOnLink(addr, link); err != nil {
		return fmt.Errorf("failed to ensure address of interface: %s", err)
	}

	// If required, disable checksum offload.
	if xsumBroken {
		if err := ethtool.EthtoolTXOff(m.vxlanDevice); err != nil {
			return fmt.Errorf("failed to disable checksum offload: %s", err)
		}
	}

	// And the device is up.
	if err := m.nlHandle.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set interface up: %s", err)
	}

	return nil
}

// ensureAddressOnLink ensures that the provided IP address is configured on the provided Link. If there are other addresses,
// this function will remove them, ensuring that the desired IP address is the _only_ address on the Link.
func (m *vxlanManager) ensureAddressOnLink(ipStr string, link netlink.Link) error {
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
