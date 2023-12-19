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
	"net"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
)

// ipipManager manages the all-hosts IP set, which is used by some rules in our static chains
// when IPIP is enabled.  It doesn't actually program the rules, because they are part of the
// top-level static chains.
//
// ipipManager also takes care of the configuration of the IPIP tunnel device.
type ipipManager struct {
	// Our dependencies.
	hostname            string
	routeTable          routetable.RouteTableInterface
	blackholeRouteTable routetable.RouteTableInterface
	//noEncapRouteTable   routetable.RouteTableInterface

	// activeHostnameToIP maps hostname to string IP address. We don't bother to parse into
	// net.IPs because we're going to pass them directly to the IPSet API.
	activeHostnameToIP map[string]string
	ipSetDirty         bool

	// Dataplane shim.
	dataplane ipipDataplane

	// Hold pending updates.
	routesByDest    map[string]*proto.RouteUpdate
	localIPAMBlocks map[string]*proto.RouteUpdate

	// IPIP configuration.
	ipipDevice string
	ipVersion  uint8

	// Indicates if configuration has changed since the last apply.
	routesDirty     bool
	ipsetsDataplane common.IPSetsDataplane
	// Config for creating/refreshing the IP set.
	ipSetMetadata ipsets.IPSetMetadata
	// Configured list of external node ip cidr's to be added to the ipset.
	externalNodeCIDRs []string
	nlHandle          netlinkHandle
	dpConfig          Config

	// Log context
	logCtx *logrus.Entry
}

func newIPIPManager(
	ipsetsDataplane common.IPSetsDataplane,
	deviceName string,
	rt routetable.RouteTableInterface,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	ipVersion uint8,
	featureDetector environment.FeatureDetectorIface,
) *ipipManager {
	if ipVersion != 4 {
		logrus.Infof("IPIP manager only supports IPv4")
		return nil
	}
	nlHandle, _ := netlink.NewHandle()

	blackHoleProto := defaultVXLANProto
	if dpConfig.DeviceRouteProtocol != syscall.RTPROT_BOOT {
		blackHoleProto = dpConfig.DeviceRouteProtocol
	}

	var brt routetable.RouteTableInterface
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
		realIPIPNetlink{})
}

func newIPIPManagerWithShim(
	ipsetsDataplane common.IPSetsDataplane,
	rt, brt routetable.RouteTableInterface,
	deviceName string,
	dpConfig Config,
	nlHandle netlinkHandle,
	ipVersion uint8,
	dataplane ipipDataplane,
) *ipipManager {
	if ipVersion != 4 {
		logrus.Infof("IPIP manager only supports IPv4")
		return nil
	}
	ipipMgr := &ipipManager{
		ipsetsDataplane:    ipsetsDataplane,
		activeHostnameToIP: map[string]string{},
		dataplane:          dataplane,
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: dpConfig.MaxIPSetSize,
			SetID:   rules.IPSetIDAllHostNets,
			Type:    ipsets.IPSetTypeHashNet,
		},
		hostname:            dpConfig.Hostname,
		routeTable:          rt,
		blackholeRouteTable: brt,
		routesByDest:        map[string]*proto.RouteUpdate{},
		localIPAMBlocks:     map[string]*proto.RouteUpdate{},
		ipipDevice:          deviceName,
		ipVersion:           ipVersion,
		externalNodeCIDRs:   dpConfig.ExternalNodesCidrs,
		routesDirty:         true,
		ipSetDirty:          true,
		dpConfig:            dpConfig,
		nlHandle:            nlHandle,
		logCtx:              logrus.WithField("ipVersion", ipVersion),
	}
	return ipipMgr
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
		m.activeHostnameToIP[msg.Hostname] = msg.Ipv4Addr
		m.ipSetDirty = true
		m.routesDirty = true
	case *proto.HostMetadataRemove:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host removed")
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

func (m *ipipManager) CompleteDeferredWork() error {
	if !m.routesDirty {
		m.logCtx.Debug("No change since last application, nothing to do")
		return nil
	}
	if m.ipSetDirty {
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
		m.ipSetDirty = false
	}
	if m.routesDirty {
		// Iterate through all of our L3 routes and send them through to the route table.
		var ipipRoutes []routetable.Target
		//var noEncapRoutes []routetable.Target
		for _, r := range m.routesByDest {
			logCtx := m.logCtx.WithField("route", r)
			cidr, err := ip.CIDRFromString(r.Dst)
			if err != nil {
				// Don't block programming of other routes if somehow we receive one with a bad dst.
				logCtx.WithError(err).Warn("Failed to parse IPIP route destination")
				continue
			}

			if r.GetSameSubnet() {
				if r.DstNodeIp == "" {
					logCtx.Debug("Can't program non-encap route since host IP is not known.")
					continue
				}

				/*defaultRoute := routetable.Target{
					Type: routetable.TargetTypeNoEncap,
					CIDR: cidr,
					GW:   ip.FromString(r.DstNodeIp),
				}

				noEncapRoutes = append(noEncapRoutes, defaultRoute)*/
				logCtx.WithField("route", r).Debug("adding no encap route to list for addition")
			} else {
				// Extract the gateway addr for this route based on its remote VTEP.
				remoteAddr, ok := m.activeHostnameToIP[r.DstNodeName]
				if !ok {
					// When the VTEP arrives, it'll set routesDirty=true so this loop will execute again.
					logCtx.Debug("Dataplane has route with no corresponding VTEP")
					continue
				}

				ipipRoute := routetable.Target{
					Type: routetable.TargetTypeVXLAN,
					CIDR: cidr,
					GW:   ip.FromString(remoteAddr),
				}

				ipipRoutes = append(ipipRoutes, ipipRoute)
				logCtx.WithField("route", ipipRoute).Debug("adding ipip route to list for addition")
			}
		}

		m.logCtx.WithField("ipip routes", ipipRoutes).Debug("IPIP manager sending IPIP L3 updates")
		m.routeTable.SetRoutes(m.ipipDevice, ipipRoutes)

		m.blackholeRouteTable.SetRoutes(routetable.InterfaceNone, m.blackholeRoutes())

		m.logCtx.Info("IPIP Manager completed deferred work")
		m.routesDirty = false
	}

	return nil
}

func (m *ipipManager) blackholeRoutes() []routetable.Target {
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

// KeepIPIPDeviceInSync is a goroutine that configures the IPIP tunnel device, then periodically
// checks that it is still correctly configured.
func (m *ipipManager) KeepIPIPDeviceInSync(mtu int, address net.IP) {
	m.logCtx.Info("IPIP thread started.")
	for {
		err := m.configureIPIPDevice(mtu, address)
		if err != nil {
			m.logCtx.WithError(err).Warn("Failed configure IPIP tunnel device, retrying...")
			time.Sleep(1 * time.Second)
			continue
		}
		time.Sleep(10 * time.Second)
	}
}

// configureIPIPDevice ensures the IPIP tunnel device is up and configures correctly.
func (m *ipipManager) configureIPIPDevice(mtu int, address net.IP) error {
	logCxt := m.logCtx.WithFields(logrus.Fields{
		"mtu":        mtu,
		"tunnelAddr": address,
		"device":     m.ipipDevice,
	})
	logCxt.Debug("Configuring IPIP tunnel")
	link, err := m.dataplane.LinkByName("tunl0")
	if err != nil {
		m.logCtx.WithError(err).Info("Failed to get IPIP tunnel device, assuming it isn't present")
		// We call out to "ip tunnel", which takes care of loading the kernel module if
		// needed.  The tunl0 device is actually created automatically by the kernel
		// module.
		// TODO: fix this:
		err := m.dataplane.RunCmd("ip", "tunnel", "add", "tunl0", "mode", "ipip")
		if err != nil {
			m.logCtx.WithError(err).Warning("Failed to add IPIP tunnel device")
			return err
		}
		link, err = m.dataplane.LinkByName("tunl0")
		if err != nil {
			m.logCtx.WithError(err).Warning("Failed to get tunnel device")
			return err
		}
	}

	attrs := link.Attrs()
	oldMTU := attrs.MTU
	if oldMTU != mtu {
		logCxt.WithField("oldMTU", oldMTU).Info("Tunnel device MTU needs to be updated")
		if err := m.dataplane.LinkSetMTU(link, mtu); err != nil {
			m.logCtx.WithError(err).Warn("Failed to set tunnel device MTU")
			return err
		}
		logCxt.Info("Updated tunnel MTU")
	}
	if attrs.Flags&net.FlagUp == 0 {
		logCxt.WithField("flags", attrs.Flags).Info("Tunnel wasn't admin up, enabling it")
		if err := m.dataplane.LinkSetUp(link); err != nil {
			m.logCtx.WithError(err).Warn("Failed to set tunnel device up")
			return err
		}
		logCxt.Info("Set tunnel admin up")
	}

	if err := m.setLinkAddressV4("tunl0", address); err != nil {
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
	link, err := m.dataplane.LinkByName(linkName)
	if err != nil {
		m.logCtx.WithError(err).WithField("name", linkName).Warning("Failed to get device")
		return err
	}

	addrs, err := m.dataplane.AddrList(link, netlink.FAMILY_V4)
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
		if err := m.dataplane.AddrDel(link, &oldAddr); err != nil {
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
		if err := m.dataplane.AddrAdd(link, addr); err != nil {
			m.logCtx.WithError(err).WithField("addr", address).Warn("Failed to add address")
			return err
		}
	}
	logCxt.Debug("Address set.")

	return nil
}
