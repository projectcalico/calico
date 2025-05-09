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
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
)

type ipipManager struct {
	// Our dependencies.
	hostname      string
	ipVersion     uint8
	routeProtocol netlink.RouteProtocol

	// Device information
	tunnelDevice    string
	tunnelDeviceMTU int

	// activeHostnameToIP maps hostname to string IP address. We don't bother to parse into
	// net.IPs because we're going to pass them directly to the IPSet API.
	activeHostnameToIP map[string]string
	ipsetsDataplane    dpsets.IPSetsDataplane
	ipSetMetadata      ipsets.IPSetMetadata

	// Local host information
	myHostAddr string
	myInfoLock sync.Mutex

	// Indicates if configuration has changed since the last apply.
	triggerRouteUpdate func(bool)
	routesDirty        bool
	ipSetDirty         bool
	externalNodeCIDRs  []string
	dpConfig           Config

	// Log context
	logCtx     *logrus.Entry
	opRecorder logutils.OpRecorder
}

func newIPIPManager(
	ipsetsDataplane dpsets.IPSetsDataplane,
	tunnelDevice string,
	ipVersion uint8,
	mtu int,
	dpConfig Config,
	triggerRouteUpdate func(bool),
	opRecorder logutils.OpRecorder,
) *ipipManager {
	return newIPIPManagerWithShims(
		ipsetsDataplane,
		tunnelDevice,
		ipVersion,
		mtu,
		dpConfig,
		triggerRouteUpdate,
		opRecorder,
	)
}

func newIPIPManagerWithShims(
	ipsetsDataplane dpsets.IPSetsDataplane,
	tunnelDevice string,
	ipVersion uint8,
	mtu int,
	dpConfig Config,
	triggerRouteUpdate func(bool),
	opRecorder logutils.OpRecorder,
) *ipipManager {

	if ipVersion != 4 {
		logrus.Errorf("IPIP manager is only supports in IPv4")
		return nil
	}

	return &ipipManager{
		ipsetsDataplane: ipsetsDataplane,
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: dpConfig.MaxIPSetSize,
			SetID:   rules.IPSetIDAllHostNets,
			Type:    ipsets.IPSetTypeHashNet,
		},
		activeHostnameToIP: map[string]string{},
		hostname:           dpConfig.Hostname,
		tunnelDevice:       tunnelDevice,
		tunnelDeviceMTU:    mtu,
		ipVersion:          ipVersion,
		externalNodeCIDRs:  dpConfig.ExternalNodesCidrs,
		triggerRouteUpdate: triggerRouteUpdate,
		ipSetDirty:         true,
		dpConfig:           dpConfig,
		routeProtocol:      calculateRouteProtocol(dpConfig),
		logCtx: logrus.WithFields(logrus.Fields{
			"ipVersion":     ipVersion,
			"tunnel device": tunnelDevice,
		}),
		opRecorder: opRecorder,
	}
}

func (m *ipipManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.HostMetadataUpdate:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host update/create")
		if msg.Hostname == m.hostname {
			m.setLocalHostAddr(msg.Ipv4Addr)
		}
		m.activeHostnameToIP[msg.Hostname] = msg.Ipv4Addr
		m.ipSetDirty = true
		m.mayUpdateRoutes()
	case *proto.HostMetadataRemove:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host removed")
		if msg.Hostname == m.hostname {
			m.setLocalHostAddr("")
		}
		delete(m.activeHostnameToIP, msg.Hostname)
		m.ipSetDirty = true
		m.mayUpdateRoutes()
	}
}

func (m *ipipManager) mayUpdateRoutes() {
	// Only update routes if only Felix is responsible for programming routes.
	if m.dpConfig.ProgramRoutes {
		m.triggerRouteUpdate(false)
	}
}

func (m *ipipManager) setLocalHostAddr(address string) {
	m.myInfoLock.Lock()
	defer m.myInfoLock.Unlock()
	m.myHostAddr = address
	m.triggerRouteUpdate(true)
}

func (m *ipipManager) getLocalHostAddr() string {
	m.myInfoLock.Lock()
	defer m.myInfoLock.Unlock()
	return m.myHostAddr
}

func (m *ipipManager) CompleteDeferredWork() error {
	if m.ipSetDirty {
		m.updateAllHostsIPSet()
		m.ipSetDirty = false
	}
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

func (m *ipipManager) route(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
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

func (m *ipipManager) updateDataDevice(_ netlink.Link) {
	return
}

func (m *ipipManager) dataDeviceAddr() string {
	return m.getLocalHostAddr()
}

// configureIPIPDevice ensures the IPIP tunnel device is up and configures correctly.
func (m *ipipManager) Device() (netlink.Link, string, error) {
	la := netlink.NewLinkAttrs()
	la.Name = m.tunnelDevice
	ipip := &netlink.Iptun{
		LinkAttrs: la,
	}
	address := m.dpConfig.RulesConfig.IPIPTunnelAddress

	if len(address) == 0 {
		return nil, "", fmt.Errorf("Address is not set")
	}
	return ipip, address.String(), nil
}
