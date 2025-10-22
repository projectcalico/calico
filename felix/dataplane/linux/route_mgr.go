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

	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/ethtool"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
)

type routeManager struct {
	// Our dependencies.
	routeTable           routetable.Interface
	routeClassTunnel     routetable.RouteClass
	routeClassSameSubnet routetable.RouteClass
	ipVersion            uint8
	ippoolType           proto.IPPoolType

	// Device information
	parentDevice     string
	parentDeviceLock sync.Mutex
	parentDeviceAddr string

	tunnelDevice    string
	tunnelDeviceMTU int
	tunnelRouteFn   func(ip.CIDR, *proto.RouteUpdate) *routetable.Target

	// Hold pending updates.
	routesByDest    map[string]*proto.RouteUpdate
	localIPAMBlocks map[string]*proto.RouteUpdate

	// Local host information
	hostname       string
	tunnelChangedC chan struct{}

	// Indicates if configuration has changed since the last apply.
	routesDirty   bool
	nlHandle      netlinkHandle
	dpConfig      Config
	routeProtocol netlink.RouteProtocol

	// Log context
	logCtx     *logrus.Entry
	opRecorder logutils.OpRecorder

	// In dual-stack setup in ebpf mode, for the sake of simplicity, we still
	// run 2 instance of the vxlan manager, one for each ip version - like in
	// the *tables mode. However, they share the same device. The device is
	// created and maintained by the V4 manager and the V6 manager is
	// responsible only for assigning the right V6 IP to the device.
	maintainIPOnly bool
}

func newRouteManager(
	mainRouteTable routetable.Interface,
	routeClassTunnel routetable.RouteClass,
	routeClassSameSubnet routetable.RouteClass,
	ippoolType proto.IPPoolType,
	tunnelDevice string,
	ipVersion uint8,
	mtu int,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	nlHandle netlinkHandle,
) *routeManager {
	return &routeManager{
		hostname:             dpConfig.Hostname,
		routeTable:           mainRouteTable,
		routeClassTunnel:     routeClassTunnel,
		routeClassSameSubnet: routeClassSameSubnet,
		routesByDest:         map[string]*proto.RouteUpdate{},
		localIPAMBlocks:      map[string]*proto.RouteUpdate{},
		tunnelChangedC:       make(chan struct{}, 1),
		tunnelDevice:         tunnelDevice,
		tunnelDeviceMTU:      mtu,
		ipVersion:            ipVersion,
		ippoolType:           ippoolType,
		dpConfig:             dpConfig,
		nlHandle:             nlHandle,
		routeProtocol:        calculateRouteProtocol(dpConfig),
		opRecorder:           opRecorder,
		logCtx: logrus.WithFields(logrus.Fields{
			"ipVersion":    ipVersion,
			"tunnelDevice": tunnelDevice,
		}),
	}
}

func calculateRouteProtocol(dpConfig Config) netlink.RouteProtocol {
	// For same-subnet, blackhole and ipip routes, we need a unique protocol
	// to attach to the routes.  If the global DeviceRouteProtocol is set to
	// a usable value, use that; otherwise, pick a safer default.  (For back
	// compatibility, our DeviceRouteProtocol defaults to RTPROT_BOOT, which
	// can also be used by other processes.)
	//
	// Routes to the VXLAN tunnel device itself are identified by their target
	// interface.  We don't need to worry about their protocol.
	routeProtocol := dataplanedefs.DefaultRouteProto
	if dpConfig.DeviceRouteProtocol != syscall.RTPROT_BOOT {
		routeProtocol = dpConfig.DeviceRouteProtocol
	}
	return routeProtocol
}

// isRemoteTunnelRoute returns true if the route update signifies a need to program
// a directly connected route on the VXLAN/IPIP device for a remote tunnel endpoint. This is needed
// in a few cases in order to ensure host <-> pod connectivity over the tunnel.
func isRemoteTunnelRoute(msg *proto.RouteUpdate, ippoolType proto.IPPoolType) bool {
	if msg.IpPoolType != ippoolType {
		// Not relevant IP pool - can skip this update.
		return false
	}

	var isRemoteTunnel bool
	var isBlock bool
	isRemoteTunnel = isType(msg, proto.RouteType_REMOTE_TUNNEL)
	isBlock = isType(msg, proto.RouteType_REMOTE_WORKLOAD)

	if isRemoteTunnel && msg.Borrowed {
		// If we receive a route for a borrowed tunnel IP, we need to make sure to program a route for it as it
		// won't be covered by the block route.
		return true
	}
	if isRemoteTunnel && isBlock {
		// This happens when tunnel addresses are selected from an IP pool with blocks of a single address.
		// These also need routes of the form "<IP> dev vxlan.calico" rather than "<block> via <TunnelEndpoint>".
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
			m.logCtx.WithError(err).WithField("msg", msg).
				Warning("Unable to parse route update destination. Skipping update.")
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
			m.logCtx.WithField("msg", msg).Debug("Route manager received route update")
			m.routesByDest[msg.Dst] = msg
			m.routesDirty = true
		}

		if isRemoteTunnelRoute(msg, m.ippoolType) {
			m.logCtx.WithField("msg", msg).Debug("Route manager received route update for remote tunnel endpoint")
			m.routesByDest[msg.Dst] = msg
			m.routesDirty = true
		}

		// Process IPAM blocks that aren't associated to a single or /32 local workload
		if m.routeIsLocalBlock(msg) {
			m.logCtx.WithField("msg", msg).Debug("Route manager received route update for IPAM block")
			m.localIPAMBlocks[msg.Dst] = msg
			m.routesDirty = true
		} else if _, ok := m.localIPAMBlocks[msg.Dst]; ok {
			m.logCtx.WithField("msg", msg).Debug("Route manager IPAM block changed to something else")
			delete(m.localIPAMBlocks, msg.Dst)
			m.routesDirty = true
		}

	case *proto.RouteRemove:
		// Check to make sure that we are dealing with messages of the correct IP version.
		cidr, err := ip.CIDRFromString(msg.Dst)
		if err != nil {
			m.logCtx.WithError(err).WithField("msg", msg).
				Warning("Unable to parse route removal destination. Skipping update.")
			return
		}
		if m.ipVersion != cidr.Version() {
			// Skip since the update is for a mismatched IP version
			return
		}
		m.deleteRoute(msg.Dst)
	}
}

func (m *routeManager) triggerRouteUpdate() {
	m.routesDirty = true
}

func (m *routeManager) updateParentIfaceAddr(addr string) {
	m.parentDeviceLock.Lock()
	defer m.parentDeviceLock.Unlock()
	m.parentDeviceAddr = addr
	m.tunnelChangedC <- struct{}{}
}

func (m *routeManager) parentIfaceAddr() string {
	m.parentDeviceLock.Lock()
	defer m.parentDeviceLock.Unlock()
	return m.parentDeviceAddr
}

func (m *routeManager) vxlanEnabled() bool {
	return m.ippoolType == proto.IPPoolType_VXLAN
}

func isType(msg *proto.RouteUpdate, t proto.RouteType) bool {
	return msg.Types&t == t
}

func (m *routeManager) routeIsLocalBlock(msg *proto.RouteUpdate) bool {
	// RouteType_LOCAL_WORKLOAD means "local IPAM block _or_ /32 of workload" in IPv4.
	// It means "local IPAM block _or_ /128 of workload" in IPv6.
	if !isType(msg, proto.RouteType_LOCAL_WORKLOAD) {
		return false
	}
	// Only care about IPPools which match the encap type of the manager.
	if msg.IpPoolType != m.ippoolType {
		return false
	}
	// Ignore routes that we know are from local workload endpoints.
	if msg.LocalWorkload {
		return false
	}

	// Check the valid suffix depending on IP version.
	cidr, err := ip.CIDRFromString(msg.Dst)
	if err != nil {
		logrus.WithError(err).WithField("msg", msg).
			Warning("Unable to parse destination into a CIDR. Treating block as external.")
	}
	// Ignore exact routes, i.e. /32 (ipv4) or /128 (ipv6) routes in any case for two reasons:
	// * If we have a /32 or /128 block then our blackhole route would stop the CNI plugin from
	// programming its /32 or /128 for a newly added workload.
	// * If this isn't a /32 or /128 block then it must be a borrowed /32 or /128 from another
	// block. In that case, we know we're racing with CNI, adding a new workload.
	// We've received the borrowed IP but not the workload endpoint yet.
	exactRoute := "/32"
	if cidr.Version() == 6 {
		exactRoute = "/128"
	}
	return !strings.HasSuffix(msg.Dst, exactRoute)
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

func (m *routeManager) CompleteDeferredWork() error {
	if m.parentDevice == "" {
		// Background goroutine hasn't sent us the parent interface name yet,
		// but we can look it up synchronously.  OnParentDeviceUpdate will handle
		// any duplicate update when it arrives.
		parentIface, err := m.detectParentIface()
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
			m.logCtx.WithError(err).Error(
				"Failed to find parent device. Missing/conflicting local information?" +
					"route programming is likely to fail.")
		} else {
			m.OnParentDeviceUpdate(parentIface.Attrs().Name)
			m.routesDirty = true
		}
	}

	if m.routesDirty {
		m.updateRoutes()
		m.routesDirty = false
	}
	return nil
}

func (m *routeManager) OnParentDeviceUpdate(name string) {
	if name == "" {
		m.logCtx.Warn("Empty parent interface name? Ignoring.")
	}
	if name == m.parentDevice {
		return
	}
	if m.parentDevice != "" {
		// We're changing parent interface, remove the old routes.
		m.routeTable.SetRoutes(m.routeClassSameSubnet, m.parentDevice, nil)
	}
	m.parentDevice = name
	m.routesDirty = true
}

func (m *routeManager) updateRoutes() {
	// Iterate through all of our L3 routes and send them through to the
	// RouteTable.  It's a little wasteful to recalculate everything but the
	// RouteTable will avoid making dataplane changes for routes that haven't
	// changed.
	m.opRecorder.RecordOperation("update-routes")
	var tunnelRoutes []routetable.Target
	var noEncapRoutes []routetable.Target
	for _, r := range m.routesByDest {
		logCtx := m.logCtx.WithField("route", r)
		cidr, err := ip.CIDRFromString(r.Dst)
		if err != nil {
			// Don't block programming of other routes if somehow we receive one with a bad dst.
			logCtx.WithError(err).Warn("Failed to parse route destination")
			continue
		}

		if noEncapRoute := m.noEncapRoute(cidr, r); noEncapRoute != nil {
			// We've got everything we need to program this route as a no-encap route.
			noEncapRoutes = append(noEncapRoutes, *noEncapRoute)
			logCtx.WithField("route", r).Debug("Destination in same subnet, using no-encap route.")
		} else if tunnelRoute := m.tunnelRouteFn(cidr, r); tunnelRoute != nil {
			tunnelRoutes = append(tunnelRoutes, *tunnelRoute)
			logCtx.WithField("route", tunnelRoute).Debug("adding tunnel route to list for addition")
		} else {
			logCtx.Debug("Not enough information to program route; missing local information?")
		}
	}

	m.logCtx.WithField("routes", tunnelRoutes).Debug("Route manager setting tunneled routes")
	m.routeTable.SetRoutes(m.routeClassTunnel, m.tunnelDevice, tunnelRoutes)

	bhRoutes := blackholeRoutes(m.localIPAMBlocks, m.routeProtocol)
	m.logCtx.WithField("routes", bhRoutes).Debug("Route manager setting blackhole routes")
	m.routeTable.SetRoutes(routetable.RouteClassIPAMBlockDrop, routetable.InterfaceNone, bhRoutes)

	if m.parentDevice != "" {
		m.logCtx.WithFields(logrus.Fields{
			"parentDevice": m.parentDevice,
			"routes":       noEncapRoutes,
		}).Debug("Route manager sending unencapsulated L3 updates")
		m.routeTable.SetRoutes(m.routeClassSameSubnet, m.parentDevice, noEncapRoutes)
	} else {
		m.logCtx.Debug("Route manager not sending unencapsulated L3 updates, no parent interface.")
	}
}

func (m *routeManager) setTunnelRouteFunc(fn func(ip.CIDR, *proto.RouteUpdate) *routetable.Target) {
	m.tunnelRouteFn = fn
}

func blackholeRoutes(localIPAMBlocks map[string]*proto.RouteUpdate, proto netlink.RouteProtocol) []routetable.Target {
	var rtt []routetable.Target
	for dst := range localIPAMBlocks {
		cidr, err := ip.CIDRFromString(dst)
		if err != nil {
			logrus.WithError(err).Warning(
				"Error processing IPAM block CIDR: ", dst,
			)
			continue
		}
		rtt = append(rtt, routetable.Target{
			Type:     routetable.TargetTypeBlackhole,
			CIDR:     cidr,
			Protocol: proto,
		})
	}
	return rtt
}

func (m *routeManager) noEncapRoute(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
	if m.parentDevice == "" {
		return nil
	}
	if m.ippoolType != proto.IPPoolType_NO_ENCAP && !r.GetSameSubnet() {
		return nil
	}
	if r.DstNodeIp == "" {
		return nil
	}
	noEncapRoute := routetable.Target{
		Type:     routetable.TargetTypeNoEncap,
		CIDR:     cidr,
		GW:       ip.FromString(r.DstNodeIp),
		Protocol: m.routeProtocol,
	}
	return &noEncapRoute
}

func (m *routeManager) detectParentIface() (netlink.Link, error) {
	parentAddr := m.parentIfaceAddr()
	if parentAddr == "" {
		return nil, fmt.Errorf("parent interface not yet known")
	}

	m.logCtx.WithField("address", parentAddr).Debug("Getting parent interface")
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
			// Match address with or without subnet mask
			if addr.IP.String() == parentAddr || addr.IPNet.String() == parentAddr {
				m.logCtx.Debugf("Found parent interface: %s", link)
				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("unable to find parent interface with address %s", parentAddr)
}

// KeepDeviceInSync runs in a loop and checks that the device is still correctly configured, and updates it if necessary.
func (m *routeManager) keepDeviceInSync(
	ctx context.Context,
	mtu int,
	xsumBroken bool,
	wait time.Duration,
	parentIfaceC chan string,
	getDevice func(netlink.Link) (netlink.Link, string, error),
) {
	m.logCtx.WithFields(logrus.Fields{
		"device":     m.tunnelDevice,
		"mtu":        mtu,
		"xsumBroken": xsumBroken,
		"wait":       wait,
	}).Info("Tunnel device thread started.")
	logNextSuccess := true
	parentIface := ""

	sleepMonitoringChans := func(maxDuration time.Duration) {
		timer := time.NewTimer(maxDuration)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			logrus.Debug("Sleep returning early: context finished.")
		case <-m.tunnelChangedC:
			logrus.Debug("Sleep returning early: tunnel changed.")
		}
	}

	for ctx.Err() == nil {
		if m.parentIfaceAddr() == "" {
			m.logCtx.Debug("Missing local information, retrying...")
			sleepMonitoringChans(10 * time.Second)
			continue
		}

		parentDevice, err := m.detectParentIface()
		if err != nil {
			m.logCtx.WithError(err).Warn("Failed to find parent device, retrying...")
			sleepMonitoringChans(1 * time.Second)
			continue
		}

		link, addr, err := getDevice(parentDevice)
		if err != nil {
			m.logCtx.WithError(err).Warn("Failed to get tunnel device, retrying...")
			sleepMonitoringChans(1 * time.Second)
			continue
		}

		if link != nil {
			m.logCtx.Debug("Configuring tunnel device")
			err = m.configureTunnelDevice(link, addr, mtu, xsumBroken)
			if err != nil {
				m.logCtx.WithError(err).Warn("Failed to configure tunnel device, retrying...")
				logNextSuccess = true
				sleepMonitoringChans(1 * time.Second)
				continue
			}
		}

		newParentIface := parentDevice.Attrs().Name
		if newParentIface != parentIface {
			// Send a message back to the main loop to tell it to update the
			// routing tables.
			m.logCtx.Infof("parent device changed from %q to %q", parentIface, newParentIface)
			select {
			case parentIfaceC <- newParentIface:
				parentIface = newParentIface
			case <-m.tunnelChangedC:
				m.logCtx.Info("Tunnel changed; restarting configuration.")
				continue
			case <-ctx.Done():
				continue
			}
		}

		if logNextSuccess {
			m.logCtx.Info("Tunnel device configured")
			logNextSuccess = false
		}
		sleepMonitoringChans(wait)
	}
}

func (m *routeManager) configureTunnelDevice(
	newLink netlink.Link,
	addr string,
	mtu int, xsumBroken bool) error {
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
		m.logCtx.WithError(err).Info("Failed to get tunnel device, assuming it isn't present")
		if m.maintainIPOnly {
			return err
		}
		if err := m.nlHandle.LinkAdd(newLink); err == syscall.EEXIST {
			// Device already exists - likely a race.
			m.logCtx.Debug("Tunnel device already exists, likely created by someone else.")
		} else if err != nil {
			// Error other than "device exists" - return it.
			return err
		}

		// The device now exists - requery it to check that the link exists and is our tunnel device.
		link, err = m.nlHandle.LinkByName(m.tunnelDevice)
		if err != nil {
			return fmt.Errorf("can't locate created tunnel device %v", m.tunnelDevice)
		}
	}

	if m.maintainIPOnly {
		if err := m.ensureAddressOnLink(addr, link); err != nil {
			return fmt.Errorf("failed to ensure address of interface: %s", err)
		}
		return nil
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
	if mtu != 0 && oldMTU != mtu {
		m.logCtx.WithFields(logrus.Fields{"old": oldMTU, "new": mtu}).Info("Tunnel device MTU needs to be updated")
		if err := m.nlHandle.LinkSetMTU(link, mtu); err != nil {
			m.logCtx.WithError(err).Warn("Failed to set tunnel device MTU")
		} else {
			m.logCtx.Info("Updated tunnel MTU")
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

	// And set the device state to up if needed.
	if attrs.Flags&net.FlagUp == 0 {
		logCtx.WithField("flags", attrs.Flags).Info("Tunnel wasn't admin up, enabling it")
		if err := m.nlHandle.LinkSetUp(link); err != nil {
			m.logCtx.WithError(err).Warn("Failed to set tunnel device up")
			return err
		}
		logCtx.Info("Set tunnel admin up")
	}

	return nil
}

// ensureAddressOnLink ensures that the provided IP address is configured on the provided Link. If there are other
// addresses, this function will remove them, ensuring that the desired IP address is the _only_ address on the Link.
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
		}).Warn("Removing unwanted IP from tunnel device")
		if err := m.nlHandle.AddrDel(link, &existing); err != nil {
			return fmt.Errorf("failed to remove IP address %s", existing)
		}
	}

	// Actually add the desired address to the interface if needed.
	if !addrPresent {
		m.logCtx.WithFields(logrus.Fields{"address": addr}).Info("Assigning address to tunnel device")
		if err := m.nlHandle.AddrAdd(link, &addr); err != nil {
			return fmt.Errorf("failed to add IP address")
		}
	}
	return nil
}
