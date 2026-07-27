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

package intdataplane

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
)

// ipipManager takes care of the configuration of the IPIP tunnel device, and programming IPIP routes by using
// route manager. Route updates are only sent to the route manager when Felix is reponsible for programming routes.
// If BIRD is in charge of IPIP routes, ipipManager is only responsible for configuration of the IPIP tunnel device.
type ipipManager struct {
	// Our dependencies.
	hostname      string
	ipVersion     uint8
	routeProtocol netlink.RouteProtocol
	routeMgr      *routeManager
	dpConfig      Config

	// Device information
	tunnelDevice    string
	tunnelDeviceMTU int

	// activeHostnameToIP maps hostname to string IP address. We don't bother to parse into
	// net.IPs because we're going to pass them directly to the IPSet API.
	activeHostnameToIP map[string]string

	// Log context
	logCtx     *logrus.Entry
	opRecorder logutils.OpRecorder
}

func newIPIPManager(
	mainRouteTable routetable.Interface,
	tunnelDevice string,
	ipVersion uint8,
	mtu int,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
) *ipipManager {
	nlHandle, _ := netlinkshim.NewRealNetlink()
	return newIPIPManagerWithShims(
		mainRouteTable,
		tunnelDevice,
		ipVersion,
		mtu,
		dpConfig,
		opRecorder,
		nlHandle,
	)
}

func newIPIPManagerWithShims(
	mainRouteTable routetable.Interface,
	tunnelDevice string,
	ipVersion uint8,
	mtu int,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	nlHandle netlinkshim.Interface,
) *ipipManager {
	if ipVersion != 4 {
		logrus.Errorf("IPIP manager only supports IPv4")
		return nil
	}

	m := &ipipManager{
		activeHostnameToIP: map[string]string{},
		hostname:           dpConfig.Hostname,
		tunnelDevice:       tunnelDevice,
		tunnelDeviceMTU:    mtu,
		ipVersion:          ipVersion,
		dpConfig:           dpConfig,
		routeProtocol:      calculateRouteProtocol(dpConfig),
		logCtx: logrus.WithFields(logrus.Fields{
			"ipVersion":    ipVersion,
			"tunnelDevice": tunnelDevice,
		}),
		opRecorder: opRecorder,
		routeMgr: newRouteManager(
			mainRouteTable,
			routetable.RouteClassIPIPTunnel,
			routetable.RouteClassIPIPSameSubnet,
			proto.IPPoolType_IPIP,
			tunnelDevice,
			ipVersion,
			mtu,
			dpConfig,
			opRecorder,
			nlHandle,
		),
	}

	m.routeMgr.setTunnelRouteFunc(m.tunnelRoute)
	m.maybeUpdateRoutes()
	return m
}

func (m *ipipManager) OnUpdate(protoBufMsg any) {
	switch msg := protoBufMsg.(type) {
	case *proto.HostMetadataUpdate:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host update/create")
		if msg.Hostname == m.hostname {
			m.routeMgr.updateParentIfaceAddr(msg.Ipv4Addr)
		}
		// An empty Ipv4Addr means the host has no v4 BGP/host IP (e.g. its BGP
		// spec was cleared). Drop the map entry so tunnelRoute won't try to
		// install onlink routes via a nil gateway.
		if msg.Ipv4Addr == "" {
			delete(m.activeHostnameToIP, msg.Hostname)
		} else {
			m.activeHostnameToIP[msg.Hostname] = msg.Ipv4Addr
		}
		m.maybeUpdateRoutes()
	case *proto.HostMetadataRemove:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host removed")
		if msg.Hostname == m.hostname {
			m.routeMgr.updateParentIfaceAddr("")
		}
		delete(m.activeHostnameToIP, msg.Hostname)
		m.maybeUpdateRoutes()
	default:
		if m.dpConfig.ProgramClusterRoutes {
			m.routeMgr.OnUpdate(msg)
		}
	}
}

func (m *ipipManager) maybeUpdateRoutes() {
	// Only update routes if only Felix is responsible for programming IPIP routes.
	if m.dpConfig.ProgramClusterRoutes {
		m.routeMgr.triggerRouteUpdate()
	}
}

func (m *ipipManager) CompleteDeferredWork() error {
	if m.dpConfig.ProgramClusterRoutes {
		return m.routeMgr.CompleteDeferredWork()
	}
	return nil
}

func (m *ipipManager) tunnelRoute(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
	// Extract the gateway addr for this route based on its remote address.
	remoteAddr, ok := m.activeHostnameToIP[r.DstNodeName]
	if !ok {
		// When the local address arrives, it'll mark routes as dirty so this loop will execute again.
		return nil
	}

	return &routetable.Target{
		Type: routetable.TargetTypeOnLink,
		RouteKey: routetable.RouteKey{
			CIDR: cidr,
		},
		GW:       ip.FromIPOrCIDRString(remoteAddr),
		Protocol: m.routeProtocol,
		MTU:      m.dpConfig.IPIPMTU,
	}
}

func (m *ipipManager) keepIPIPDeviceInSync(
	ctx context.Context,
	mtu int,
	xsumBroken bool,
	wait time.Duration,
	parentIfaceC chan string,
) {
	m.routeMgr.keepDeviceInSync(ctx, mtu, xsumBroken, wait, parentIfaceC, m.device)
}

func (m *ipipManager) device(_ netlink.Link) (netlink.Link, string, error) {
	la := netlink.NewLinkAttrs()
	la.Name = m.tunnelDevice
	ipip := &netlink.Iptun{
		LinkAttrs: la,
	}

	if m.dpConfig.BPFEnabled && !m.dpConfig.BPFOverlayIPOnDevice {
		// BPF dataplane handles encap/decap and source IP selection itself,
		// so it doesn't need an IP assigned to the tunnel device.
		return ipip, "", nil
	}

	address := m.dpConfig.RulesConfig.IPIPTunnelAddress
	if len(address) == 0 {
		return nil, "", fmt.Errorf("address is not set")
	}
	return ipip, address.String(), nil
}

func cleanUpIPIPAddrs() {
	// If IPIP is not enabled, check to see if there is are addresses in the IPIP device and delete them if there are.
	logrus.Debug("Checking if we need to clean up the IPIP device")

	var errFound bool

cleanupRetry:
	for i := 0; i <= maxCleanupRetries; i++ {
		errFound = false
		if i > 0 {
			logrus.Debugf("Retrying %v/%v times", i, maxCleanupRetries)
		}
		link, err := netlink.LinkByName(dataplanedefs.IPIPIfaceName)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); ok {
				logrus.Debug("IPIP disabled and no IPIP device found")
				return
			}
			logrus.WithError(err).Warn("IPIP disabled and failed to query IPIP device.")
			errFound = true

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			continue
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			logrus.WithError(err).Warn("IPIP disabled and failed to list addresses, will be unable to remove any old addresses from the device should they exist.")
			errFound = true

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			continue
		}

		for _, oldAddr := range addrs {
			if err := netlink.AddrDel(link, &oldAddr); err != nil {
				logrus.WithError(err).Errorf("IPIP disabled and failed to delete unwanted IPIP address %s.", oldAddr.IPNet)
				errFound = true

				// Sleep for 1 second before retrying
				time.Sleep(1 * time.Second)
				continue cleanupRetry
			}
		}
	}
	if errFound {
		logrus.Warnf("Giving up trying to clean up IPIP addresses after retrying %v times", maxCleanupRetries)
	}
}
