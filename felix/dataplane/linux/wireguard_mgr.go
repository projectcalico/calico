// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/wireguard"
)

// wireguardManager manages the dataplane resources that are used for wireguard encrypted traffic. This includes:
// -  Routing rule to route to the wireguard routing table
// -  Route table and rules specifically to handle routing to the wireguard interface, or to return to default routing
//    (depending on whether the remote node supports wireguard)
// -  Wireguard interface lifecycle
// -  Wireguard peer configuration
//
// The wireguard component implements the routetable interface and so dataplane programming is triggered through calls
// to the Apply method, with periodic resyncs occurring after calls to QueueResync. Calls from the main OnUpdate method
// call through to the various update methods on the wireguard module which simply record state without actually
// programming.
type wireguardManager struct {
	// Our dependencies.
	wireguardRouteTable *wireguard.Wireguard
	dpConfig            Config
	ipVersion           uint8
}

type WireguardStatusUpdateCallback func(ipVersion uint8, id interface{}, status string)

func newWireguardManager(
	wireguardRouteTable *wireguard.Wireguard,
	dpConfig Config,
	ipVersion uint8,
) *wireguardManager {
	if ipVersion != 4 && ipVersion != 6 {
		log.Panicf("Unknown IP version: %d", ipVersion)
	}
	return &wireguardManager{
		wireguardRouteTable: wireguardRouteTable,
		dpConfig:            dpConfig,
		ipVersion:           ipVersion,
	}
}

func (m *wireguardManager) OnUpdate(protoBufMsg interface{}) {
	logCtx := log.WithField("ipVersion", m.ipVersion)
	logCtx.WithField("msg", protoBufMsg).Debug("Received message")
	switch msg := protoBufMsg.(type) {
	case *proto.HostMetadataUpdate:
		logCtx.WithField("msg", msg).Debug("HostMetadataUpdate update")
		if m.ipVersion != 4 {
			logCtx.WithField("hostname", msg.Hostname).Debug("ignore update for mismatched IP version")
			return
		}
		m.wireguardRouteTable.EndpointUpdate(msg.Hostname, ip.FromString(msg.Ipv4Addr))
	case *proto.HostMetadataRemove:
		logCtx.WithField("msg", msg).Debug("HostMetadataRemove update")
		if m.ipVersion != 4 {
			logCtx.WithField("hostname", msg.Hostname).Debug("ignore update for mismatched IP version")
			return
		}
		m.wireguardRouteTable.EndpointRemove(msg.Hostname)
	case *proto.HostMetadataV6Update:
		logCtx.WithField("msg", msg).Debug("HostMetadataV6Update update")
		if m.ipVersion != 6 {
			logCtx.WithField("hostname", msg.Hostname).Debug("ignore update for mismatched IP version")
			return
		}
		m.wireguardRouteTable.EndpointUpdate(msg.Hostname, ip.FromString(msg.Ipv6Addr))
	case *proto.HostMetadataV6Remove:
		if m.ipVersion != 6 {
			logCtx.WithField("hostname", msg.Hostname).Debug("ignore update for mismatched IP version")
			return
		}
		logCtx.WithField("msg", msg).Debug("HostMetadataV6Remove update")
		m.wireguardRouteTable.EndpointRemove(msg.Hostname)
	case *proto.RouteUpdate:
		logCtx.WithField("msg", msg).Debug("RouteUpdate update")
		cidr, err := ip.ParseCIDROrIP(msg.Dst)
		if err != nil || cidr == nil {
			logCtx.Errorf("error parsing RouteUpdate CIDR: %s", msg.Dst)
			return
		}
		if cidr.Version() != m.ipVersion {
			logCtx.WithField("CIDR", msg.Dst).Debugf("ignore update for mismatched IP version")
			return
		}
		switch msg.Type {
		case proto.RouteType_REMOTE_HOST:
			logCtx.Debug("RouteUpdate is a remote host update")
			// This can only be done in WorkloadIPs mode, because this breaks networking during upgrade in CalicoIPAM
			// mode.
			if m.dpConfig.Wireguard.EncryptHostTraffic {
				m.wireguardRouteTable.RouteUpdate(msg.DstNodeName, cidr)
			}
		case proto.RouteType_LOCAL_WORKLOAD, proto.RouteType_REMOTE_WORKLOAD:
			// CIDR is for a workload.
			logCtx.Debug("RouteUpdate is a workload update")
			m.wireguardRouteTable.RouteUpdate(msg.DstNodeName, cidr)
		case proto.RouteType_LOCAL_TUNNEL, proto.RouteType_REMOTE_TUNNEL:
			// CIDR is for a tunnel address. We treat tunnel addresses like workloads (in that we route over wireguard
			// to and from these addresses when both nodes support wireguard).
			logCtx.Debug("RouteUpdate is a tunnel update")
			m.wireguardRouteTable.RouteUpdate(msg.DstNodeName, cidr)
		default:
			// It is not a workload CIDR - treat this as a route deletion.
			logCtx.Debug("RouteUpdate is not a workload, remote host or tunnel update, treating as a deletion")
			m.wireguardRouteTable.RouteRemove(cidr)
		}
	case *proto.RouteRemove:
		logCtx.WithField("msg", msg).Debug("RouteRemove update")
		cidr, err := ip.ParseCIDROrIP(msg.Dst)
		if err != nil || cidr == nil {
			logCtx.WithField("CIDR", msg.Dst).Error("error parsing RouteUpdate")
			return
		}
		if cidr.Version() != m.ipVersion {
			logCtx.WithField("CIDR", msg.Dst).Debug("ignore update for mismatched IP version")
			return
		}
		logCtx.Debugf("Route removal for CIDR: %s", cidr)
		m.wireguardRouteTable.RouteRemove(cidr)
	case *proto.WireguardEndpointUpdate:
		logCtx.WithField("msg", msg).Debug("WireguardEndpointUpdate update")
		if m.ipVersion != 4 {
			logCtx.WithField("hostname", msg.Hostname).Debug("ignore update for mismatched IP version")
			return
		}
		key, err := wgtypes.ParseKey(msg.PublicKey)
		if err != nil {
			logCtx.WithError(err).Errorf("error parsing wireguard public key %s for node %s", msg.PublicKey, msg.Hostname)
		}
		var ifaceAddr ip.Addr
		if msg.InterfaceIpv4Addr != "" {
			addr := ip.FromString(msg.InterfaceIpv4Addr)
			if addr == nil {
				// Unable to parse the wireguard interface address. We can still enable wireguard without this, so treat as
				// an update with no interface address.
				logCtx.WithError(err).Errorf("error parsing wireguard interface address %s for node %s", msg.InterfaceIpv4Addr, msg.Hostname)
			} else if addr.Version() == m.ipVersion {
				ifaceAddr = addr
			}
		}
		m.wireguardRouteTable.EndpointWireguardUpdate(msg.Hostname, key, ifaceAddr)
	case *proto.WireguardEndpointRemove:
		logCtx.WithField("msg", msg).Debug("WireguardEndpointRemove update")
		if m.ipVersion != 4 {
			logCtx.WithField("hostname", msg.Hostname).Debug("ignore update for mismatched IP version")
			return
		}
		m.wireguardRouteTable.EndpointWireguardRemove(msg.Hostname)
	case *proto.WireguardEndpointV6Update:
		logCtx.WithField("msg", msg).Debug("WireguardEndpointV6Update update")
		if m.ipVersion != 6 {
			logCtx.WithField("hostname", msg.Hostname).Debug("ignore update for mismatched IP version")
			return
		}
		key, err := wgtypes.ParseKey(msg.PublicKeyV6)
		if err != nil {
			logCtx.WithError(err).Errorf("error parsing wireguard public key %s for node %s", msg.PublicKeyV6, msg.Hostname)
		}
		var ifaceAddr ip.Addr
		if msg.InterfaceIpv6Addr != "" {
			addr := ip.FromString(msg.InterfaceIpv6Addr)
			if addr == nil {
				// Unable to parse the wireguard interface address. We can still enable wireguard without this, so treat as
				// an update with no interface address.
				logCtx.WithError(err).Errorf("error parsing wireguard interface address %s for node %s", msg.InterfaceIpv6Addr, msg.Hostname)
			} else if addr.Version() == m.ipVersion {
				ifaceAddr = addr
			}
		}
		m.wireguardRouteTable.EndpointWireguardUpdate(msg.Hostname, key, ifaceAddr)
	case *proto.WireguardEndpointV6Remove:
		logCtx.WithField("msg", msg).Debug("WireguardEndpointV6Remove update")
		if m.ipVersion != 6 {
			logCtx.WithField("hostname", msg.Hostname).Debug("ignore update for mismatched IP version")
			return
		}
		m.wireguardRouteTable.EndpointWireguardRemove(msg.Hostname)
	}
}

func (m *wireguardManager) CompleteDeferredWork() error {
	// Dataplane programming is handled through the routetable interface.
	return nil
}

func (m *wireguardManager) GetRouteTableSyncers() []routeTableSyncer {
	return []routeTableSyncer{m.wireguardRouteTable}
}
