// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
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
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ethtool"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// ipipManager manages the all-hosts IP set, which is used by some rules in our static chains
// when IPIP is enabled.  It doesn't actually program the rules, because they are part of the
// top-level static chains.
//
// ipipManager also takes care of the configuration of the IPIP tunnel device.
type ipipManager struct {
	// Our dependencies.
	routeTable                routetable.RouteTableInterface
	blackholeRouteTable       routetable.RouteTableInterface
	noEncapRouteTable         routetable.RouteTableInterface
	parentIfaceName           string
	lastParentDevUpdate       time.Time
	previouslyUsedParentNames set.Set[string]

	// activeHostnameToIP maps hostname to string IP address. We don't bother to parse into
	// net.IPs because we're going to pass them directly to the IPSet API.
	activeHostnameToIP map[string]string
	ipSetDirty         bool
	ipsetsDataplane    dpsets.IPSetsDataplane

	// Hold pending updates.
	routesByDest    map[string]*proto.RouteUpdate
	localIPAMBlocks map[string]*proto.RouteUpdate

	// IPIP configuration.
	ipipDevice string
	ipVersion  uint8

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
	noEncapProtocol   netlink.RouteProtocol

	// Used so that we can shim the no encap route table for the tests
	noEncapRTConstruct func(
		interfacePrefixes []string, ipVersion uint8, netlinkTimeout time.Duration,
		deviceRouteSourceAddress net.IP, deviceRouteProtocol netlink.RouteProtocol,
		removeExternalRoutes bool,
	) routetable.RouteTableInterface

	// Log context
	logCtx *logrus.Entry
}

func newIPIPManager(
	ipsetsDataplane dpsets.IPSetsDataplane,
	rt routetable.RouteTableInterface,
	deviceName string,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	ipVersion uint8,
	featureDetector environment.FeatureDetectorIface,
) *ipipManager {
	if ipVersion != 4 {
		logrus.Errorf("IPIP manager only supports IPv4")
		return nil
	}
	nlHandle, _ := netlink.NewHandle(syscall.NETLINK_ROUTE)
	blackHoleProto := calculateRouteProtocol(dpConfig)

	var brt routetable.RouteTableInterface
	if !dpConfig.RouteSyncDisabled {
		logrus.Debug("RouteSyncDisabled is false.")
		brt = routetable.New(
			[]string{routetable.InterfaceNone},
			4,
			dpConfig.NetlinkTimeout,
			dpConfig.DeviceRouteSourceAddress,
			blackHoleProto,
			false,
			unix.RT_TABLE_MAIN,
			opRecorder,
			featureDetector,
		)
	} else {
		logrus.Info("RouteSyncDisabled is true, using DummyTable.")
		brt = &routetable.DummyTable{}
	}
	return newIPIPManagerWithShim(
		ipsetsDataplane,
		rt, brt,
		deviceName,
		dpConfig,
		nlHandle,
		ipVersion,
		func(interfaceRegexes []string, ipVersion uint8, netlinkTimeout time.Duration,
			deviceRouteSourceAddress net.IP, deviceRouteProtocol netlink.RouteProtocol,
			removeExternalRoutes bool,
		) routetable.RouteTableInterface {
			return routetable.New(interfaceRegexes, ipVersion, netlinkTimeout,
				deviceRouteSourceAddress, deviceRouteProtocol, removeExternalRoutes, unix.RT_TABLE_MAIN,
				opRecorder, featureDetector,
			)
		},
	)
}

func newIPIPManagerWithShim(
	ipsetsDataplane dpsets.IPSetsDataplane,
	rt, brt routetable.RouteTableInterface,
	deviceName string,
	dpConfig Config,
	nlHandle netlinkHandle,
	ipVersion uint8,
	noEncapRTConstruct func(
		interfacePrefixes []string, ipVersion uint8, netlinkTimeout time.Duration,
		deviceRouteSourceAddress net.IP, deviceRouteProtocol netlink.RouteProtocol,
		removeExternalRoutes bool,
	) routetable.RouteTableInterface,
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
		hostname:                  dpConfig.Hostname,
		routeTable:                rt,
		blackholeRouteTable:       brt,
		previouslyUsedParentNames: set.New[string](),
		routesByDest:              map[string]*proto.RouteUpdate{},
		localIPAMBlocks:           map[string]*proto.RouteUpdate{},
		ipipDevice:                deviceName,
		ipVersion:                 ipVersion,
		externalNodeCIDRs:         dpConfig.ExternalNodesCidrs,
		routesDirty:               true,
		ipSetDirty:                true,
		dpConfig:                  dpConfig,
		nlHandle:                  nlHandle,
		noEncapProtocol:           calculateRouteProtocol(dpConfig),
		noEncapRTConstruct:        noEncapRTConstruct,
		logCtx:                    logrus.WithField("ipVersion", ipVersion),
	}
}

func (m *ipipManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.RouteUpdate:
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
		if msg.Type == proto.RouteType_REMOTE_WORKLOAD && msg.IpPoolType == proto.IPPoolType_IPIP {
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
			m.logCtx.WithError(err).WithField("msg", msg).Warning("Unable to parse route removal destination. Skipping update.")
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

func (m *ipipManager) GetRouteTableSyncers() []routetable.RouteTableSyncer {
	rts := []routetable.RouteTableSyncer{m.routeTable, m.blackholeRouteTable}

	if time.Since(m.lastParentDevUpdate) > 5*time.Minute && m.previouslyUsedParentNames.Len() > 1 {
		// Make sure the set of names doesn't grow forever.
		m.previouslyUsedParentNames.Clear()
	}

	if m.noEncapRouteTable != nil {
		m.previouslyUsedParentNames.Add(m.parentIfaceName)
		rts = append(rts, m.noEncapRouteTable)
	}
	return rts
}

func (m *ipipManager) CompleteDeferredWork() error {
	if !m.ipSetDirty && !m.routesDirty {
		return nil
	}
	if m.ipSetDirty {
		m.updateAllHostsIPSet()
		m.ipSetDirty = false
	}
	if m.routesDirty {
		err := m.updateRoutes()
		if err != nil {
			return err
		}
		m.routesDirty = false
	}
	m.logCtx.Info("IPIP Manager completed deferred work")
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
	// Iterate through all of our L3 routes and send them through to the route table.
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

		if noEncapRoute := noEncapRoute(cidr, r); noEncapRoute != nil {
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

	m.logCtx.WithField("ipipRoutes", ipipRoutes).Debug("IPIP manager setting IPIP tunnled routes")
	m.routeTable.SetRoutes(m.ipipDevice, ipipRoutes)

	bhRoutes := blackholeRoutes(m.localIPAMBlocks)
	m.logCtx.WithField("balckhole routes", bhRoutes).Debug("IPIP manager setting blackhole routes")
	m.blackholeRouteTable.SetRoutes(routetable.InterfaceNone, bhRoutes)

	if m.noEncapRouteTable != nil {
		m.logCtx.WithField("link", m.parentIfaceName).WithField("routes", noEncapRoutes).Debug(
			"IPIP manager sending unencapsulated L3 updates")
		m.noEncapRouteTable.SetRoutes(m.parentIfaceName, noEncapRoutes)
	} else {
		return errors.New("no encap route table not set, will defer adding routes")
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

	ipipRoute := routetable.Target{
		Type: routetable.TargetTypeOnLink,
		CIDR: cidr,
		GW:   ip.FromString(remoteAddr),
	}
	return &ipipRoute
}

func (m *ipipManager) OnParentNameUpdate(name string) {
	if name == "" {
		m.logCtx.Warn("Empty parent interface name? Ignoring.")
		return
	}
	m.logCtx.WithField("parent", name).Info("Parent interface updated, creating new routing table.")
	devRouteSrcAddr := m.dpConfig.DeviceRouteSourceAddress
	m.parentIfaceName = name
	m.lastParentDevUpdate = time.Now()

	// If we're changing the name, we need to make sure the new RouteTable will
	// clean up the routes on the old interface.  Add previously-used names to
	// the regexp.
	names := m.previouslyUsedParentNames.Slice()
	if !m.previouslyUsedParentNames.Contains(m.parentIfaceName) {
		names = append(names, m.parentIfaceName)
	}
	sort.Strings(names)
	for i, name := range names {
		names[i] = regexp.QuoteMeta(name)
	}

	m.noEncapRouteTable = m.noEncapRTConstruct(
		[]string{"^" + strings.Join(names, "|") + "$"},
		m.ipVersion,
		m.dpConfig.NetlinkTimeout,
		devRouteSrcAddr,
		m.noEncapProtocol,
		false,
	)
	m.routesDirty = true
}

// KeepIPIPDeviceInSync is a goroutine that configures the IPIP tunnel device, then periodically
// checks that it is still correctly configured.
func (m *ipipManager) KeepIPIPDeviceInSync(ctx context.Context, mtu int, address net.IP, xsumBroken bool, wait time.Duration, parentNameC chan string) {
	m.logCtx.WithFields(logrus.Fields{
		"mtu":        mtu,
		"xsumBroken": xsumBroken,
		"wait":       wait,
	}).Info("IPIP tunnel device thread started.")
	logNextSuccess := true
	parentName := ""

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

		parent, err := m.getParentInterface()
		if err != nil {
			m.logCtx.WithError(err).Warn("Failed to find IPIP tunnel device parent, retrying...")
			sleepMonitoringChans(1 * time.Second)
			continue
		}

		// TODO: we are sending passed in address here
		m.logCtx.WithField("localAddr", address).Debug("Configuring IPIP device")
		err = m.configureIPIPDevice(mtu, address, xsumBroken)
		if err != nil {
			m.logCtx.WithError(err).Warn("Failed to configure IPIP tunnel device, retrying...")
			logNextSuccess = true
			sleepMonitoringChans(1 * time.Second)
			continue
		}

		newParentName := parent.Attrs().Name
		if newParentName != parentName {
			// Send a message back to the main loop to tell it to update the
			// routing tables.
			m.logCtx.Infof("IPIP device parent changed from %q to %q", parentName, newParentName)
			select {
			case parentNameC <- newParentName:
				parentName = newParentName
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

// getParentInterface returns the parent interface for the given local address. This link returned is nil
// if, and only if, an error occurred
func (m *ipipManager) getParentInterface() (netlink.Link, error) {
	m.logCtx.WithField("local hostname", m.hostname).Debug("Getting parent interface")
	address := m.getLocalHostAddr()
	if address == "" {
		return nil, fmt.Errorf("local address not found, will defer adding routes")
	}
	m.logCtx.Debugf("Found parent's address: %v", address)

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
			if addr.IPNet.IP.String() == address {
				m.logCtx.Debugf("Found parent interface: %s", link)
				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("Unable to find parent interface with address %s", address)
}

// configureIPIPDevice ensures the IPIP tunnel device is up and configures correctly.
func (m *ipipManager) configureIPIPDevice(mtu int, address net.IP, xsumBroken bool) error {
	logCxt := log.WithFields(log.Fields{
		"mtu":        mtu,
		"tunnelAddr": address,
		"device":     m.ipipDevice,
	})
	logCxt.Debug("Configuring IPIP tunnel")

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
		logCxt.WithField("oldMTU", oldMTU).Info("Tunnel device MTU needs to be updated")
		if err := m.nlHandle.LinkSetMTU(link, mtu); err != nil {
			m.logCtx.WithError(err).Warn("Failed to set tunnel device MTU")
			return err
		}
		logCxt.Info("Updated tunnel MTU")
	}

	// If required, disable checksum offload.
	if xsumBroken {
		if err := ethtool.EthtoolTXOff(m.ipipDevice); err != nil {
			return fmt.Errorf("failed to disable checksum offload: %s", err)
		}
	}

	if attrs.Flags&net.FlagUp == 0 {
		logCxt.WithField("flags", attrs.Flags).Info("Tunnel wasn't admin up, enabling it")
		if err := m.nlHandle.LinkSetUp(link); err != nil {
			m.logCtx.WithError(err).Warn("Failed to set tunnel device up")
			return err
		}
		logCxt.Info("Set tunnel admin up")
	}

	if err := m.setLinkAddressV4(m.ipipDevice, address); err != nil {
		m.logCtx.WithError(err).Warn("Failed to set tunnel device IP")
		return err
	}
	return nil
}

// setLinkAddressV4 updates the given link to set its local IP address.  It removes any other
// addresses.
func (m *ipipManager) setLinkAddressV4(linkName string, address net.IP) error {
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
