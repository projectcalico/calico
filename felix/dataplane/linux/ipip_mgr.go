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
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ethtool"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
)

// ipipManager manages the all-hosts IP set, which is used by some rules in our static chains
// when IPIP is enabled. It doesn't actually program the rules, because they are part of the
// top-level static chains.
//
// ipipManager also takes care of the configuration of the IPIP tunnel device, and programming IPIP routes.
type ipipManager struct {
	routeTable routetable.Interface

	// activeHostnameToIP maps hostname to string IP address. We don't bother to parse into
	// net.IPs because we're going to pass them directly to the IPSet API.
	activeHostnameToIP map[string]string
	ipSetDirty         bool
	ipsetsDataplane    dpsets.IPSetsDataplane

	// Hold pending updates.
	routesByDest    map[string]*proto.RouteUpdate
	localIPAMBlocks map[string]*proto.RouteUpdate

	//  configuration.
	ipipDevice    string
	noEncapDevice string
	ipVersion     uint8

	// Local information
	hostname       string
	hostAddr       string
	myAddrLock     sync.Mutex
	myAddrChangedC chan struct{}

	// Indicates if configuration has changed since the last apply.
	routesDirty bool

	// Config for creating/refreshing the IP set.
	ipSetMetadata ipsets.IPSetMetadata

	// Configured list of external node ip cidr's to be added to the ipset.
	externalNodeCIDRs []string
	nlHandle          netlinkHandle
	dpConfig          Config
	routeProtocol     netlink.RouteProtocol

	// Log context
	logCtx     *logrus.Entry
	opRecorder logutils.OpRecorder
}

func newIPIPManager(
	ipsetsDataplane dpsets.IPSetsDataplane,
	mainRouteTable routetable.Interface,
	deviceName string,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	ipVersion uint8,
	featureDetector environment.FeatureDetectorIface,
) *ipipManager {
	nlHandle, _ := netlinkshim.NewRealNetlink()
	return newIPIPManagerWithShim(
		ipsetsDataplane,
		mainRouteTable,
		deviceName,
		dpConfig,
		opRecorder,
		nlHandle,
		ipVersion,
	)
}

func newIPIPManagerWithShim(
	ipsetsDataplane dpsets.IPSetsDataplane,
	mainRouteTable routetable.Interface,
	deviceName string,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	nlHandle netlinkHandle,
	ipVersion uint8,
) *ipipManager {
	if ipVersion != 4 {
		logrus.Errorf("IPIP manager only supports IPv4")
		return nil
	}
	return &ipipManager{
		ipsetsDataplane:    ipsetsDataplane,
		activeHostnameToIP: map[string]string{},
		myAddrChangedC:     make(chan struct{}, 1),
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: dpConfig.MaxIPSetSize,
			SetID:   rules.IPSetIDAllHostNets,
			Type:    ipsets.IPSetTypeHashNet,
		},
		hostname:          dpConfig.Hostname,
		routeTable:        mainRouteTable,
		routesByDest:      map[string]*proto.RouteUpdate{},
		localIPAMBlocks:   map[string]*proto.RouteUpdate{},
		ipipDevice:        deviceName,
		ipVersion:         ipVersion,
		externalNodeCIDRs: dpConfig.ExternalNodesCidrs,
		routesDirty:       true,
		ipSetDirty:        true,
		dpConfig:          dpConfig,
		nlHandle:          nlHandle,
		routeProtocol:     calculateRouteProtocol(dpConfig),
		logCtx:            logrus.WithField("ipVersion", ipVersion),
		opRecorder:        opRecorder,
	}
}

func (m *ipipManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.RouteUpdate:
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
		if isType(msg, proto.RouteType_REMOTE_WORKLOAD) && msg.IpPoolType == proto.IPPoolType_IPIP {
			m.logCtx.WithField("msg", msg).Debug("IPIP data plane received route update")
			m.routesByDest[msg.Dst] = msg
			m.routesDirty = true
		}

		// Process IPAM blocks that aren't associated to a single or /32 local workload
		if routeIsLocalBlock(msg, proto.IPPoolType_IPIP) {
			m.logCtx.WithField("msg", msg).Debug("IPIP data plane received route update for IPAM block")
			m.localIPAMBlocks[msg.Dst] = msg
			m.routesDirty = true
		} else if _, ok := m.localIPAMBlocks[msg.Dst]; ok {
			m.logCtx.WithField("msg", msg).Debug("IPIP data plane IPAM block changed to something else")
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
	case *proto.HostMetadataUpdate:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host update/create")
		if msg.Hostname == m.hostname {
			m.setLocalHostAddr(msg.Ipv4Addr)
		}
		m.activeHostnameToIP[msg.Hostname] = msg.Ipv4Addr
		m.ipSetDirty = true
		m.routesDirty = true
	case *proto.HostMetadataRemove:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host removed")
		if msg.Hostname == m.hostname {
			m.setLocalHostAddr("")
		}
		delete(m.activeHostnameToIP, msg.Hostname)
		m.ipSetDirty = true
		m.routesDirty = true
	}
}

func (m *ipipManager) deleteRoute(dst string) {
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

func (m *ipipManager) setLocalHostAddr(address string) {
	m.myAddrLock.Lock()
	defer m.myAddrLock.Unlock()
	m.hostAddr = address
	select {
	case m.myAddrChangedC <- struct{}{}:
	default:
	}
}

func (m *ipipManager) getLocalHostAddr() string {
	m.myAddrLock.Lock()
	defer m.myAddrLock.Unlock()
	return m.hostAddr
}

func (m *ipipManager) CompleteDeferredWork() error {
	if m.ipSetDirty {
		m.updateAllHostsIPSet()
		m.ipSetDirty = false
	}
	// Program routes, only if Felix is responsible for programming IPIP routes.
	if !m.dpConfig.ProgramRoutes {
		m.routesDirty = false
		return nil
	}
	if m.noEncapDevice == "" {
		// Background goroutine hasn't sent us the noEncap interface name yet,
		// but we can look it up synchronously. OnNoEncapDeviceUpdate will handle
		// any duplicate update when it arrives.
		noEncapDevice, err := m.getNoEncapInterface()
		if err != nil {
			// If we can't look up the noEncap interface then we're in trouble.
			// It likely means that our local address is missing or conflicting.  We
			// won't be able to program same-subnet routes at all, so we'll
			// fall back to programming all tunnel routes.  However, unless the
			// ipip device happens to already exist, we won't be able to
			// program tunnel routes either.  The RouteTable will be the
			// component that spots that the interface is missing.
			//
			// Note: this behaviour changed when we unified all the main
			// RouteTale instances into one.  Before that change, we chose to
			// defer creation of our "no encap" RouteTable, so that the
			// dataplane would stay untouched until the conflict was resolved.
			// With only a single RouteTable, we need a different fallback.
			m.logCtx.WithError(err).WithField("local address", m.getLocalHostAddr()).Error(
				"Failed to find noEncap interface. Missing/conflicting local address? ipip route " +
					"programming is likely to fail.")
		} else {
			m.noEncapDevice = noEncapDevice.Attrs().Name
			m.routesDirty = true
		}
	}
	if m.routesDirty {
		err := m.updateRoutes()
		if err != nil {
			return err
		}
		m.routesDirty = false
	}
	m.logCtx.Info("Route Manager completed deferred work")
	return nil
}

func (m *ipipManager) updateAllHostsIPSet() {
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

func (m *ipipManager) updateRoutes() error {
	// Iterate through all of our L3 routes and send them through to the
	// RouteTable.  It's a little wasteful to recalculate everything but the
	// RouteTable will avoid making dataplane changes for routes that haven't
	// changed.
	m.opRecorder.RecordOperation("update-ipip-routes")

	var ipipRoutes []routetable.Target
	var noEncapRoutes []routetable.Target
	for _, r := range m.routesByDest {
		logCtx := m.logCtx.WithField("route", r)
		cidr, err := ip.CIDRFromString(r.Dst)
		if err != nil {
			// Don't block programming of other routes if somehow we receive one with a bad dst.
			logCtx.WithError(err).Warn("Failed to parse IPIP route destination")
			continue
		}

		if noEncapRoute := noEncapRoute(m.noEncapDevice, cidr, r, m.routeProtocol); noEncapRoute != nil {
			// We've got everything we need to program this route as a no-encap route.
			noEncapRoutes = append(noEncapRoutes, *noEncapRoute)
			logCtx.WithField("route", r).Debug("Destination in same subnet, using no-encap route.")
		} else if ipipRoute := m.tunneledRoute(cidr, r); ipipRoute != nil {
			ipipRoutes = append(ipipRoutes, *ipipRoute)
			logCtx.WithField("route", ipipRoute).Debug("adding ipip route to list for addition")
		} else {
			logCtx.Debug("Not enough information to program route; missing target host address?")
		}
	}

	m.logCtx.WithField("routes", ipipRoutes).Debug("IPIP manager setting IPIP tunneled routes")
	m.routeTable.SetRoutes(routetable.RouteClassIPIPTunnel, m.ipipDevice, ipipRoutes)

	bhRoutes := blackholeRoutes(m.localIPAMBlocks, m.routeProtocol)
	m.logCtx.WithField("routes", bhRoutes).Debug("IPIP manager setting blackhole routes")
	m.routeTable.SetRoutes(routetable.RouteClassIPAMBlockDrop, routetable.InterfaceNone, bhRoutes)

	if m.noEncapDevice != "" {
		m.logCtx.WithFields(logrus.Fields{
			"noEncapDevice": m.noEncapDevice,
			"routes":        noEncapRoutes,
		}).Debug("IPIP manager sending unencapsulated L3 updates")
		m.routeTable.SetRoutes(routetable.RouteClassIPIPSameSubnet, m.noEncapDevice, noEncapRoutes)
	} else {
		m.logCtx.Debug("IPIP manager not sending unencapsulated L3 updates, noEncap interface not found.")
	}

	return nil
}

func (m *ipipManager) tunneledRoute(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
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

func (m *ipipManager) OnNoEncapDeviceUpdate(name string) {
	if name == "" {
		m.logCtx.Warn("Empty noEncap interface name? Ignoring.")
		return
	}
	if name == m.noEncapDevice {
		return
	}
	if m.noEncapDevice != "" {
		// We're changing noEncap interface, remove the old routes.
		m.routeTable.SetRoutes(routetable.RouteClassIPIPSameSubnet, m.noEncapDevice, nil)
	}
	m.noEncapDevice = name
	m.routesDirty = true
}

// KeepBIRDIPIPDeviceInSync is a goroutine that configures the IPIP tunnel device for BIRD, then periodically
// checks that it is still correctly configured.
func (m *ipipManager) KeepBIRDIPIPDeviceInSync(xsumBroken bool) {
	for {
		err := m.configureIPIPDevice(m.dpConfig.IPIPMTU, m.dpConfig.RulesConfig.IPIPTunnelAddress, xsumBroken)
		if err != nil {
			logrus.WithError(err).Warn("Failed configure IPIP tunnel device, retrying...")
			time.Sleep(1 * time.Second)
			continue
		}
		time.Sleep(10 * time.Second)
	}
}

// KeepIPIPDeviceInSync is a goroutine that configures the IPIP tunnel device, then periodically
// checks that it is still correctly configured.
func (m *ipipManager) KeepIPIPDeviceInSync(xsumBroken bool, wait time.Duration, noEncapNameC chan string) {
	usedBy := "BIRD"
	if m.dpConfig.ProgramRoutes {
		usedBy = "Felix"
	}
	ctx := context.Background()
	mtu := m.dpConfig.IPIPMTU
	address := m.dpConfig.RulesConfig.IPIPTunnelAddress
	m.logCtx.WithFields(logrus.Fields{
		"device":     m.ipipDevice,
		"mtu":        mtu,
		"xsumBroken": xsumBroken,
		"wait":       wait,
		"used by":    usedBy,
	}).Info("IPIP device thread started.")

	if !m.dpConfig.ProgramRoutes {
		m.KeepBIRDIPIPDeviceInSync(xsumBroken)
	}

	logNextSuccess := true
	noEncapDevName := ""

	sleepMonitoringChans := func(maxDuration time.Duration) {
		timer := time.NewTimer(maxDuration)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			logrus.Debug("Sleep returning early: context finished.")
		case <-m.myAddrChangedC:
			logrus.Debug("Sleep returning early: local address changed.")
		}
	}

	for ctx.Err() == nil {
		localAddr := m.getLocalHostAddr()
		if localAddr == "" {
			m.logCtx.Debug("Missing local address information, retrying...")
			sleepMonitoringChans(10 * time.Second)
			continue
		}

		noEncapDev, err := m.getNoEncapInterface()
		if err != nil {
			m.logCtx.WithError(err).Warn("Failed to find noEncap device, retrying...")
			sleepMonitoringChans(1 * time.Second)
			continue
		}

		m.logCtx.WithField("localAddr", address).Debug("Configuring IPIP device")
		err = m.configureIPIPDevice(mtu, address, xsumBroken)
		if err != nil {
			m.logCtx.WithError(err).Warn("Failed to configure IPIP tunnel device, retrying...")
			logNextSuccess = true
			sleepMonitoringChans(1 * time.Second)
			continue
		}

		newNoEncapDevName := noEncapDev.Attrs().Name
		if newNoEncapDevName != noEncapDevName {
			// Send a message back to the main loop to tell it to update the
			// routing tables.
			m.logCtx.Infof("NoEncap device changed from %q to %q", noEncapDevName, newNoEncapDevName)
			select {
			case noEncapNameC <- newNoEncapDevName:
				noEncapDevName = newNoEncapDevName
			case <-m.myAddrChangedC:
				m.logCtx.Info("My address changed; restarting configuration.")
				continue
			case <-ctx.Done():
				continue
			}
		}

		if logNextSuccess {
			m.logCtx.Info("IPIP tunnel device configured")
			logNextSuccess = false
		}
		sleepMonitoringChans(wait)
	}
	m.logCtx.Info("KeepIPIPDeviceInSync exiting due to context.")
}

// getNoEncapInterface returns the noEncap interface for the given local address. This link returned is nil
// if, and only if, an error occurred
func (m *ipipManager) getNoEncapInterface() (netlink.Link, error) {
	localAddr := m.getLocalHostAddr()
	if localAddr == "" {
		return nil, fmt.Errorf("local address not found")
	}

	m.logCtx.WithField("local address", localAddr).Debug("Getting noEncap interface")
	links, err := m.nlHandle.LinkList()
	if err != nil {
		return nil, err
	}

	for _, link := range links {
		addrs, err := m.nlHandle.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if addr.IPNet.IP.String() == localAddr {
				m.logCtx.Debugf("Found noEncap interface: %s", link)
				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("Unable to find noEncap interface with address %s", localAddr)
}

// configureIPIPDevice ensures the IPIP tunnel device is up and configures correctly.
func (m *ipipManager) configureIPIPDevice(mtu int, address net.IP, xsumBroken bool) error {
	logCtx := logrus.WithFields(logrus.Fields{
		"mtu":        mtu,
		"tunnelAddr": address,
		"device":     m.ipipDevice,
	})
	logCtx.Debug("Configuring IPIP tunnel")

	la := netlink.NewLinkAttrs()
	la.Name = m.ipipDevice
	ipip := &netlink.Iptun{
		LinkAttrs: la,
	}

	link, err := m.nlHandle.LinkByName(m.ipipDevice)
	if err != nil {
		m.logCtx.WithError(err).Info("Failed to get IPIP tunnel device, assuming it isn't present")

		// We call out to "ip tunnel", which takes care of loading the kernel module if
		// needed.  The tunl0 device is actually created automatically by the kernel
		// module.
		if err := m.nlHandle.LinkAdd(ipip); err == syscall.EEXIST {
			// Device already exists - likely a race.
			m.logCtx.Debug("IPIP device already exists, likely created by someone else.")
		} else if err != nil {
			// Error other than "device exists" - return it.
			return err
		}

		link, err = m.nlHandle.LinkByName(m.ipipDevice)
		if err != nil {
			m.logCtx.WithError(err).Warning("Failed to get tunnel device")
			return err
		}
	}

	attrs := link.Attrs()
	oldMTU := attrs.MTU
	if oldMTU != mtu {
		logCtx.WithField("oldMTU", oldMTU).Info("Tunnel device MTU needs to be updated")
		if err := m.nlHandle.LinkSetMTU(link, mtu); err != nil {
			m.logCtx.WithError(err).Warn("Failed to set tunnel device MTU")
			return err
		}
		logCtx.Info("Updated tunnel MTU")
	}

	if err := m.ensureAddressOnLink(m.ipipDevice, address); err != nil {
		m.logCtx.WithError(err).Warn("Failed to set tunnel device IP")
		return err
	}

	// If required, disable checksum offload.
	if xsumBroken {
		if err := ethtool.EthtoolTXOff(m.ipipDevice); err != nil {
			return fmt.Errorf("failed to disable checksum offload: %s", err)
		}
	}

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

// ensureAddressOnLink updates the given link to set its local IP address. It removes any other addresses.
func (m *ipipManager) ensureAddressOnLink(linkName string, address net.IP) error {
	logCxt := m.logCtx.WithFields(logrus.Fields{
		"link": linkName,
		"addr": address,
	})
	logCxt.Debug("Setting local IPv4 address on link.")
	link, err := m.nlHandle.LinkByName(linkName)
	if err != nil {
		m.logCtx.WithError(err).WithField("name", linkName).Warning("Failed to get device")
		return err
	}

	addrs, err := m.nlHandle.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		m.logCtx.WithError(err).Warn("Failed to list interface addresses")
		return err
	}

	found := false
	for _, oldAddr := range addrs {
		if address != nil && oldAddr.IP.Equal(address) {
			logCxt.Debug("Address already present.")
			found = true
			continue
		}
		logCxt.WithField("oldAddr", oldAddr).Info("Removing old address")
		if err := m.nlHandle.AddrDel(link, &oldAddr); err != nil {
			m.logCtx.WithError(err).Warn("Failed to delete address")
			return err
		}
	}

	if !found && address != nil {
		logCxt.Info("Address wasn't present, adding it.")
		mask := net.CIDRMask(32, 32)
		ipNet := net.IPNet{
			IP:   address.Mask(mask), // Mask the IP to match ParseCIDR()'s behaviour.
			Mask: mask,
		}
		addr := &netlink.Addr{
			IPNet: &ipNet,
		}
		if err := m.nlHandle.AddrAdd(link, addr); err != nil {
			m.logCtx.WithError(err).WithField("addr", address).Warn("Failed to add address")
			return err
		}
	}
	logCxt.Debug("Address set.")

	return nil
}
