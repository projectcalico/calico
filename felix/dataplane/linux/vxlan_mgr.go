// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.
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
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/ethtool"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
)

// added so that we can shim netlink for tests
type netlinkHandle interface {
	LinkByName(name string) (netlink.Link, error)
	LinkSetMTU(link netlink.Link, mtu int) error
	LinkSetUp(link netlink.Link) error
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
	AddrAdd(link netlink.Link, addr *netlink.Addr) error
	AddrDel(link netlink.Link, addr *netlink.Addr) error
	LinkList() ([]netlink.Link, error)
	LinkAdd(netlink.Link) error
	LinkDel(netlink.Link) error
}

type vxlanManager struct {
	sync.Mutex

	// Our dependencies.
	hostname            string
	routeTable          routeTable
	blackholeRouteTable routeTable
	noEncapRouteTable   routeTable

	// Hold pending updates.
	routesByDest    map[string]*proto.RouteUpdate
	localIPAMBlocks map[string]*proto.RouteUpdate
	vtepsByNode     map[string]*proto.VXLANTunnelEndpointUpdate

	// Holds this node's VTEP information.
	myVTEP *proto.VXLANTunnelEndpointUpdate

	// VXLAN configuration.
	vxlanDevice string
	vxlanID     int
	vxlanPort   int
	ipVersion   uint8

	// Indicates if configuration has changed since the last apply.
	routesDirty       bool
	ipsetsDataplane   common.IPSetsDataplane
	ipSetMetadata     ipsets.IPSetMetadata
	externalNodeCIDRs []string
	vtepsDirty        bool
	nlHandle          netlinkHandle
	dpConfig          Config
	noEncapProtocol   netlink.RouteProtocol
	// Used so that we can shim the no encap route table for the tests
	noEncapRTConstruct func(interfacePrefixes []string, ipVersion uint8, vxlan bool, netlinkTimeout time.Duration,
		deviceRouteSourceAddress net.IP, deviceRouteProtocol netlink.RouteProtocol, removeExternalRoutes bool) routeTable

	// Log context
	logCtx *logrus.Entry
}

const (
	defaultVXLANProto netlink.RouteProtocol = 80
)

func newVXLANManager(
	ipsetsDataplane common.IPSetsDataplane,
	rt routeTable,
	deviceName string,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	ipVersion uint8,
) *vxlanManager {
	nlHandle, _ := netlink.NewHandle()

	blackHoleProto := defaultVXLANProto
	if dpConfig.DeviceRouteProtocol != syscall.RTPROT_BOOT {
		blackHoleProto = dpConfig.DeviceRouteProtocol
	}

	var brt routeTable
	if !dpConfig.RouteSyncDisabled {
		logrus.Debug("RouteSyncDisabled is false.")
		brt = routetable.New(
			[]string{routetable.InterfaceNone},
			4,
			false,
			dpConfig.NetlinkTimeout,
			dpConfig.DeviceRouteSourceAddress,
			blackHoleProto,
			false,
			0,
			opRecorder,
		)
		if ipVersion == 6 {
			brt = routetable.New(
				[]string{routetable.InterfaceNone},
				ipVersion,
				false,
				dpConfig.NetlinkTimeout,
				dpConfig.DeviceRouteSourceAddressIPv6,
				blackHoleProto,
				false,
				0,
				opRecorder,
			)
		} else if ipVersion != 4 {
			logrus.WithField("ipVersion", ipVersion).Panic("Unknown IP version")
		}
	} else {
		logrus.Info("RouteSyncDisabled is true, using DummyTable.")
		brt = &routetable.DummyTable{}
	}

	return newVXLANManagerWithShims(
		ipsetsDataplane,
		rt, brt,
		deviceName,
		dpConfig,
		nlHandle,
		ipVersion,
		func(interfaceRegexes []string, ipVersion uint8, vxlan bool, netlinkTimeout time.Duration,
			deviceRouteSourceAddress net.IP, deviceRouteProtocol netlink.RouteProtocol, removeExternalRoutes bool) routeTable {
			return routetable.New(interfaceRegexes, ipVersion, vxlan, netlinkTimeout,
				deviceRouteSourceAddress, deviceRouteProtocol, removeExternalRoutes, 0,
				opRecorder,
			)
		},
	)
}

func newVXLANManagerWithShims(
	ipsetsDataplane common.IPSetsDataplane,
	rt, brt routeTable,
	deviceName string,
	dpConfig Config,
	nlHandle netlinkHandle,
	ipVersion uint8,
	noEncapRTConstruct func(interfacePrefixes []string, ipVersion uint8, vxlan bool, netlinkTimeout time.Duration,
		deviceRouteSourceAddress net.IP, deviceRouteProtocol netlink.RouteProtocol, removeExternalRoutes bool) routeTable,
) *vxlanManager {
	noEncapProtocol := defaultVXLANProto
	if dpConfig.DeviceRouteProtocol != syscall.RTPROT_BOOT {
		noEncapProtocol = dpConfig.DeviceRouteProtocol
	}

	logCtx := logrus.WithField("ipVersion", ipVersion)
	return &vxlanManager{
		ipsetsDataplane: ipsetsDataplane,
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: dpConfig.MaxIPSetSize,
			SetID:   rules.IPSetIDAllVXLANSourceNets,
			Type:    ipsets.IPSetTypeHashNet,
		},
		hostname:            dpConfig.Hostname,
		routeTable:          rt,
		blackholeRouteTable: brt,
		routesByDest:        map[string]*proto.RouteUpdate{},
		localIPAMBlocks:     map[string]*proto.RouteUpdate{},
		vtepsByNode:         map[string]*proto.VXLANTunnelEndpointUpdate{},
		vxlanDevice:         deviceName,
		vxlanID:             dpConfig.RulesConfig.VXLANVNI,
		vxlanPort:           dpConfig.RulesConfig.VXLANPort,
		ipVersion:           ipVersion,
		externalNodeCIDRs:   dpConfig.ExternalNodesCidrs,
		routesDirty:         true,
		vtepsDirty:          true,
		dpConfig:            dpConfig,
		nlHandle:            nlHandle,
		noEncapProtocol:     noEncapProtocol,
		noEncapRTConstruct:  noEncapRTConstruct,
		logCtx:              logCtx,
	}
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

		if msg.Type == proto.RouteType_REMOTE_WORKLOAD && msg.IpPoolType == proto.IPPoolType_VXLAN {
			m.logCtx.WithField("msg", msg).Debug("VXLAN data plane received route update")
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
	if msg.Type != proto.RouteType_LOCAL_WORKLOAD {
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
	m.Lock()
	defer m.Unlock()
	m.myVTEP = vtep
}

func (m *vxlanManager) getLocalVTEP() *proto.VXLANTunnelEndpointUpdate {
	m.Lock()
	defer m.Unlock()
	return m.myVTEP
}

func (m *vxlanManager) getLocalVTEPParent() (netlink.Link, error) {
	return m.getParentInterface(m.getLocalVTEP())
}

func (m *vxlanManager) getNoEncapRouteTable() routeTable {
	m.Lock()
	defer m.Unlock()

	return m.noEncapRouteTable
}

func (m *vxlanManager) setNoEncapRouteTable(rt routeTable) {
	m.Lock()
	defer m.Unlock()

	m.noEncapRouteTable = rt
}

func (m *vxlanManager) GetRouteTableSyncers() []routeTableSyncer {
	rts := []routeTableSyncer{m.routeTable, m.blackholeRouteTable}

	noEncapRouteTable := m.getNoEncapRouteTable()
	if noEncapRouteTable != nil {
		rts = append(rts, noEncapRouteTable)
	}

	return rts
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
			Type: routetable.TargetTypeBlackhole,
			CIDR: cidr,
		})
	}
	m.logCtx.Debug("calculated blackholes ", rtt)
	return rtt
}

func (m *vxlanManager) CompleteDeferredWork() error {
	if !m.routesDirty {
		m.logCtx.Debug("No change since last application, nothing to do")
		return nil
	}

	if m.vtepsDirty {
		var allowedVXLANSources []string
		if m.vtepsDirty {
			m.logCtx.Debug("VTEPs are dirty, collecting the allowed VXLAN source set")
			allowedVXLANSources = append(allowedVXLANSources, m.externalNodeCIDRs...)
		}

		// The route table accepts the desired state. Start by setting the desired L2 "routes" by iterating
		// known VTEPs.
		var l2routes []routetable.L2Target
		for _, u := range m.vtepsByNode {
			mac, err := m.parseMacForIPVersion(u)
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
			l2routes = append(l2routes, routetable.L2Target{
				VTEPMAC: mac,
				GW:      ip.FromString(addr),
				IP:      ip.FromString(parentDeviceIP),
			})
			allowedVXLANSources = append(allowedVXLANSources, parentDeviceIP)
		}
		m.logCtx.WithField("l2routes", l2routes).Debug("VXLAN manager sending L2 updates")
		m.routeTable.SetL2Routes(m.vxlanDevice, l2routes)
		m.ipsetsDataplane.AddOrReplaceIPSet(m.ipSetMetadata, allowedVXLANSources)
		m.vtepsDirty = false
	}

	if m.routesDirty {
		// Iterate through all of our L3 routes and send them through to the route table.
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

			if r.GetSameSubnet() {
				if r.DstNodeIp == "" {
					logCtx.Debug("Can't program non-encap route since host IP is not known.")
					continue
				}

				defaultRoute := routetable.Target{
					Type: routetable.TargetTypeNoEncap,
					CIDR: cidr,
					GW:   ip.FromString(r.DstNodeIp),
				}

				noEncapRoutes = append(noEncapRoutes, defaultRoute)
				logCtx.WithField("route", r).Debug("adding no encap route to list for addition")
			} else {
				// Extract the gateway addr for this route based on its remote VTEP.
				vtep, ok := m.vtepsByNode[r.DstNodeName]
				if !ok {
					// When the VTEP arrives, it'll set routesDirty=true so this loop will execute again.
					logCtx.Debug("Dataplane has route with no corresponding VTEP")
					continue
				}

				vtepAddr := vtep.Ipv4Addr
				if m.ipVersion == 6 {
					vtepAddr = vtep.Ipv6Addr
				}
				vxlanRoute := routetable.Target{
					Type: routetable.TargetTypeVXLAN,
					CIDR: cidr,
					GW:   ip.FromString(vtepAddr),
				}

				vxlanRoutes = append(vxlanRoutes, vxlanRoute)
				logCtx.WithField("route", vxlanRoute).Debug("adding vxlan route to list for addition")
			}
		}

		m.logCtx.WithField("vxlanroutes", vxlanRoutes).Debug("VXLAN manager sending VXLAN L3 updates")
		m.routeTable.SetRoutes(m.vxlanDevice, vxlanRoutes)

		m.blackholeRouteTable.SetRoutes(routetable.InterfaceNone, m.blackholeRoutes())

		noEncapRouteTable := m.getNoEncapRouteTable()
		// only set the noEncapRouteTable table if it's nil, as you will lose the routes that are being managed already
		// and the new table will probably delete routes that were put in there by the previous table
		if noEncapRouteTable != nil {
			if parentDevice, err := m.getLocalVTEPParent(); err == nil {
				ifName := parentDevice.Attrs().Name
				m.logCtx.WithField("link", parentDevice).WithField("routes", noEncapRoutes).Debug("VXLAN manager sending unencapsulated L3 updates")
				noEncapRouteTable.SetRoutes(ifName, noEncapRoutes)
			} else {
				return err
			}
		} else {
			return errors.New("no encap route table not set, will defer adding routes")
		}

		m.logCtx.Info("VXLAN Manager completed deferred work")

		m.routesDirty = false
	}

	return nil
}

// KeepVXLANDeviceInSync is a goroutine that configures the VXLAN tunnel device, then periodically
// checks that it is still correctly configured.
func (m *vxlanManager) KeepVXLANDeviceInSync(mtu int, xsumBroken bool, wait time.Duration) {
	m.logCtx.WithFields(logrus.Fields{
		"mtu":        mtu,
		"xsumBroken": xsumBroken,
		"wait":       wait,
	}).Info("VXLAN tunnel device thread started.")
	logNextSuccess := true
	for {
		localVTEP := m.getLocalVTEP()
		if localVTEP == nil {
			m.logCtx.Debug("Missing local VTEP information, retrying...")
			time.Sleep(1 * time.Second)
			continue
		}

		if parent, err := m.getLocalVTEPParent(); err != nil {
			m.logCtx.WithError(err).Warn("Failed to configure VXLAN tunnel device, retrying...")
			time.Sleep(1 * time.Second)
			continue
		} else {
			if m.getNoEncapRouteTable() == nil {
				devRouteSrcAddr := m.dpConfig.DeviceRouteSourceAddress
				if m.ipVersion == 6 {
					devRouteSrcAddr = m.dpConfig.DeviceRouteSourceAddressIPv6
				}
				noEncapRouteTable := m.noEncapRTConstruct([]string{"^" + parent.Attrs().Name + "$"}, m.ipVersion, false, m.dpConfig.NetlinkTimeout, devRouteSrcAddr,
					m.noEncapProtocol, false)
				m.setNoEncapRouteTable(noEncapRouteTable)
			}
		}

		m.logCtx.WithField("localVTEP", localVTEP).Debug("Configuring VXLAN device")
		err := m.configureVXLANDevice(mtu, localVTEP, xsumBroken)
		if err != nil {
			m.logCtx.WithError(err).Warn("Failed to configure VXLAN tunnel device, retrying...")
			logNextSuccess = true
			time.Sleep(1 * time.Second)
			continue
		}

		if logNextSuccess {
			m.logCtx.Info("VXLAN tunnel device configured")
			logNextSuccess = false
		}
		time.Sleep(wait)
	}
}

// getParentInterface returns the parent interface for the given local VTEP based on IP address. This link returned is nil
// if, and only if, an error occurred
func (m *vxlanManager) getParentInterface(localVTEP *proto.VXLANTunnelEndpointUpdate) (netlink.Link, error) {
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
				m.logCtx.Debugf("Found parent interface: %s", link)
				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("Unable to find parent interface with address %s", parentDeviceIP)
}

func (m *vxlanManager) parseMacForIPVersion(vtep *proto.VXLANTunnelEndpointUpdate) (net.HardwareAddr, error) {
	switch m.ipVersion {
	case 4:
		return net.ParseMAC(vtep.Mac)
	case 6:
		return net.ParseMAC(vtep.MacV6)
	default:
		return nil, fmt.Errorf("Invalid IP version")
	}
}

// configureVXLANDevice ensures the VXLAN tunnel device is up and configured correctly.
func (m *vxlanManager) configureVXLANDevice(mtu int, localVTEP *proto.VXLANTunnelEndpointUpdate, xsumBroken bool) error {
	logCtx := m.logCtx.WithFields(logrus.Fields{"device": m.vxlanDevice})
	logCtx.Debug("Configuring VXLAN tunnel device")
	parent, err := m.getParentInterface(localVTEP)
	if err != nil {
		return err
	}
	mac, err := m.parseMacForIPVersion(localVTEP)
	if err != nil {
		return err
	}
	addr := localVTEP.Ipv4Addr
	parentDeviceIP := localVTEP.ParentDeviceIp
	if m.ipVersion == 6 {
		addr = localVTEP.Ipv6Addr
		parentDeviceIP = localVTEP.ParentDeviceIpv6
	}
	vxlan := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:         m.vxlanDevice,
			HardwareAddr: mac,
		},
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
		m.logCtx.WithFields(logrus.Fields{"address": existing, "link": link.Attrs().Name}).Warn("Removing unwanted IP from VXLAN device")
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
// this function will return a mesasge indicating which configuration is mismatched.
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

	return ""
}
