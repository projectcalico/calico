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
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
)

type noEncapManager struct {
	// Our dependencies.
	hostname      string
	ipVersion     uint8
	routeProtocol netlink.RouteProtocol
	routeMgr      *routeManager

	// Device information
	mtu int

	// activeHostnameToIP maps hostname to string IP address. We don't bother to parse into
	// net.IPs because we're going to pass them directly to the IPSet API.
	activeHostnameToIP map[string]string
	ipsetsDataplane    dpsets.IPSetsDataplane
	ipSetMetadata      ipsets.IPSetMetadata

	// Indicates if configuration has changed since the last apply.
	ipSetDirty        bool
	externalNodeCIDRs []string
	dpConfig          Config

	// Log context
	logCtx     *logrus.Entry
	opRecorder logutils.OpRecorder
}

func newNoEncapManager(
	ipsetsDataplane dpsets.IPSetsDataplane,
	mainRouteTable routetable.Interface,
	ipVersion uint8,
	mtu int,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
) *noEncapManager {
	nlHandle, _ := netlinkshim.NewRealNetlink()
	return newNoEncapManagerWithSims(
		ipsetsDataplane,
		mainRouteTable,
		ipVersion,
		mtu,
		dpConfig,
		opRecorder,
		nlHandle,
	)
}

func newNoEncapManagerWithSims(
	ipsetsDataplane dpsets.IPSetsDataplane,
	mainRouteTable routetable.Interface,
	ipVersion uint8,
	mtu int,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	nlHandle netlinkHandle,
) *noEncapManager {

	if ipVersion != 4 {
		logrus.Errorf("NoEncap manager only supports IPv4")
		return nil
	}

	m := &noEncapManager{
		ipsetsDataplane: ipsetsDataplane,
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: dpConfig.MaxIPSetSize,
			SetID:   rules.IPSetIDAllHostNets,
			Type:    ipsets.IPSetTypeHashNet,
		},
		activeHostnameToIP: map[string]string{},
		hostname:           dpConfig.Hostname,
		mtu:                mtu,
		ipVersion:          ipVersion,
		externalNodeCIDRs:  dpConfig.ExternalNodesCidrs,
		ipSetDirty:         true,
		dpConfig:           dpConfig,
		routeProtocol:      calculateRouteProtocol(dpConfig),
		logCtx: logrus.WithFields(logrus.Fields{
			"ipVersion": ipVersion,
		}),
		opRecorder: opRecorder,
		routeMgr: newRouteManager(
			mainRouteTable,
			proto.IPPoolType_NO_ENCAP,
			"",
			ipVersion,
			mtu,
			dpConfig,
			opRecorder,
			nlHandle,
		),
	}

	m.routeMgr.routeClassTunnel = routetable.RouteClassNoEncap
	m.routeMgr.routeClassSameSubnet = routetable.RouteClassNoEncap
	m.routeMgr.setTunnelRouteFunc(m.route)

	m.routeMgr.triggerRouteUpdate()
	return m
}

func (m *noEncapManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.HostMetadataUpdate:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host update/create")
		if msg.Hostname == m.hostname {
			m.routeMgr.updateParentIfaceAddr(msg.Ipv4Addr)
		}
		m.activeHostnameToIP[msg.Hostname] = msg.Ipv4Addr
		m.ipSetDirty = true
		m.routeMgr.triggerRouteUpdate()
	case *proto.HostMetadataRemove:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host removed")
		if msg.Hostname == m.hostname {
			m.routeMgr.updateParentIfaceAddr("")
		}
		delete(m.activeHostnameToIP, msg.Hostname)
		m.ipSetDirty = true
		m.routeMgr.triggerRouteUpdate()
	default:
		if m.dpConfig.ProgramRoutes {
			m.routeMgr.OnUpdate(msg)
		}
	}
}

func (m *noEncapManager) CompleteDeferredWork() error {
	if m.ipSetDirty {
		m.updateAllHostsIPSet()
		m.ipSetDirty = false
	}

	if m.dpConfig.ProgramRoutes {
		return m.routeMgr.CompleteDeferredWork()
	}
	return nil
}

func (m *noEncapManager) updateAllHostsIPSet() {
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

func (m *noEncapManager) route(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
	return nil
}

func (m *noEncapManager) monitorParentDevice(ctx context.Context, wait time.Duration, parentIfaceC chan string) {
	// NoEncap manager does not need to configure any interface. It expects the parent interface to be up and configured.
	// However, it needs to monitor the parent interface to update routes. For this, we can use route manager
	// keepDeviceInSync method without providing any device to configure.
	m.routeMgr.keepDeviceInSync(ctx, m.mtu, false, wait, parentIfaceC, m.device)
}

func (m *noEncapManager) device(_ netlink.Link) (netlink.Link, string, error) {
	return nil, "", nil
}
