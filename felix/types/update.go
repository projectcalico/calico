// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package types

import "github.com/projectcalico/calico/felix/proto"

type VXLANTunnelEndpointUpdate struct {
	Node             string
	Mac              string
	Ipv4Addr         string
	ParentDeviceIp   string
	MacV6            string
	Ipv6Addr         string
	ParentDeviceIpv6 string
}

type WireguardEndpointUpdate struct {
	// The name of the IPv4 wireguard host.
	Hostname string
	// The public key for IPv4 wireguard on this endpoint.
	PublicKey string
	// The IP address of the IPv4 wireguard interface.
	InterfaceIpv4Addr string
}

type WireguardEndpointV6Update struct {
	// The name of the IPv6 wireguard host.
	Hostname string
	// The public key for IPv6 wireguard on this endpoint.
	PublicKeyV6 string
	// The IP address of the IPv6 wireguard interface.
	InterfaceIpv6Addr string
}

type RouteUpdate struct {
	Type          proto.RouteType
	IpPoolType    proto.IPPoolType
	Dst           string
	DstNodeName   string
	DstNodeIp     string
	SameSubnet    bool
	NatOutgoing   bool
	LocalWorkload bool
	TunnelType    *proto.TunnelType
}

func ProtoToVXLANTunnelEndpointUpdate(msg *proto.VXLANTunnelEndpointUpdate) VXLANTunnelEndpointUpdate {
	return VXLANTunnelEndpointUpdate{
		Node:             msg.Node,
		Mac:              msg.Mac,
		Ipv4Addr:         msg.Ipv4Addr,
		ParentDeviceIp:   msg.ParentDeviceIp,
		MacV6:            msg.MacV6,
		Ipv6Addr:         msg.Ipv6Addr,
		ParentDeviceIpv6: msg.ParentDeviceIpv6,
	}
}

func ProtoToWireguardEndpointUpdate(msg *proto.WireguardEndpointUpdate) WireguardEndpointUpdate {
	return WireguardEndpointUpdate{
		Hostname:          msg.Hostname,
		PublicKey:         msg.PublicKey,
		InterfaceIpv4Addr: msg.InterfaceIpv4Addr,
	}
}

func ProtoToWireguardEndpointV6Update(msg *proto.WireguardEndpointV6Update) WireguardEndpointV6Update {
	return WireguardEndpointV6Update{
		Hostname:          msg.Hostname,
		PublicKeyV6:       msg.PublicKeyV6,
		InterfaceIpv6Addr: msg.InterfaceIpv6Addr,
	}
}

func ProtoToRouteUpdate(msg *proto.RouteUpdate) RouteUpdate {
	return RouteUpdate{
		Type:          msg.Type,
		IpPoolType:    msg.IpPoolType,
		Dst:           msg.Dst,
		DstNodeName:   msg.DstNodeName,
		DstNodeIp:     msg.DstNodeIp,
		SameSubnet:    msg.SameSubnet,
		NatOutgoing:   msg.NatOutgoing,
		LocalWorkload: msg.LocalWorkload,
		TunnelType:    msg.TunnelType,
	}
}
