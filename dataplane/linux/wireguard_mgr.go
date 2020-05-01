// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/wireguard"
)

// wireguardManager manages the dataplane resources that are used for wireguard encrypted traffic. This includes:
// -  Routing rule to route to the wireguard routing table
// -  Route table and rules specifically to handle routing to the wireguard interface, or to return to default routing
//    (depending on whether the remote node supports wireguard)
// -  Wireguard interface lifecycle
// -  Wireguard peer configuration
//
// The wireguard component implements the routetable interface and so dataplane programming is triggered through calls
// to the Apply method, with periodic resyncs occuring after calls to QueueResync. Calls from the main OnUpdate method
// call through to the various update methods on the wireguard module which simply record state without actually
// programming.
type wireguardManager struct {
	// Our dependencies.
	wireguardRouteTable *wireguard.Wireguard
}

type WireguardStatusUpdateCallback func(ipVersion uint8, id interface{}, status string)

func newWireguardManager(
	wireguardRouteTable *wireguard.Wireguard,
) *wireguardManager {
	return &wireguardManager{
		wireguardRouteTable: wireguardRouteTable,
	}
}

func (m *wireguardManager) OnUpdate(protoBufMsg interface{}) {
	log.WithField("msg", protoBufMsg).Debug("Received message")
	switch msg := protoBufMsg.(type) {
	case *proto.HostMetadataUpdate:
		log.WithField("msg", msg).Debug("HostMetadataUpdate update")
		m.wireguardRouteTable.EndpointUpdate(msg.Hostname, ip.FromString(msg.Ipv4Addr))
	case *proto.HostMetadataRemove:
		log.WithField("msg", msg).Debug("HostMetadataRemove update")
		m.wireguardRouteTable.EndpointRemove(msg.Hostname)
	case *proto.RouteUpdate:
		log.WithField("msg", msg).Debug("RouteUpdate update")
		cidr, err := ip.ParseCIDROrIP(msg.Dst)
		if err != nil || cidr == nil {
			log.Errorf("error parsing RouteUpdate CIDR: %s", msg.Dst)
			return
		}
		switch msg.Type {
		case proto.RouteType_LOCAL_WORKLOAD, proto.RouteType_REMOTE_WORKLOAD:
			// CIDR is for a workload.
			log.Debug("RouteUpdate is a workload update")
			m.wireguardRouteTable.RouteUpdate(msg.DstNodeName, cidr)
		default:
			// It is not a workload CIDR - treat this as a route deletion.
			log.Debug("RouteUpdate is not a workload update, treating as a deletion")
			m.wireguardRouteTable.RouteRemove(cidr)
		}
	case *proto.RouteRemove:
		log.WithField("msg", msg).Debug("RouteRemove update")
		cidr, err := ip.ParseCIDROrIP(msg.Dst)
		if err != nil || cidr == nil {
			log.Errorf("error parsing RouteUpdate CIDR: %s", msg.Dst)
			return
		}
		log.Debugf("Route removal for IPv4 CIDR: %s", cidr)
		m.wireguardRouteTable.RouteRemove(cidr)
	case *proto.WireguardEndpointUpdate:
		log.WithField("msg", msg).Debug("WireguardEndpointUpdate update")
		key, err := wgtypes.ParseKey(msg.PublicKey)
		if err != nil {
			log.WithError(err).Errorf("error parsing wireguard public key %s for node %s", msg.PublicKey, msg.Hostname)
		}
		var ifaceAddr ip.Addr
		if msg.InterfaceIpv4Addr != "" {
			addr := ip.FromString(msg.InterfaceIpv4Addr)
			if addr == nil {
				// Unable to parse the wireguard interface address. We can still enable wireguard without this, so treat as
				// an update with no interface address.
				log.WithError(err).Errorf("error parsing wireguard interface address %s for node %s", msg.InterfaceIpv4Addr, msg.Hostname)
			} else if addr.Version() == 4 {
				ifaceAddr = addr
			}
		}
		m.wireguardRouteTable.EndpointWireguardUpdate(msg.Hostname, key, ifaceAddr)
	case *proto.WireguardEndpointRemove:
		log.WithField("msg", msg).Debug("WireguardEndpointRemove update")
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
