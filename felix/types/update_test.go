package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/felix/proto"
)

func TestProtoToVXLANTunnelEndpointUpdate(t *testing.T) {
	tests := []struct {
		name string
		msg  *proto.VXLANTunnelEndpointUpdate
		want VXLANTunnelEndpointUpdate
	}{
		{"empty", &proto.VXLANTunnelEndpointUpdate{}, VXLANTunnelEndpointUpdate{}},
		{"non-empty",
			&proto.VXLANTunnelEndpointUpdate{
				Node: "node", Mac: "mac", Ipv4Addr: "ipv4", ParentDeviceIp: "parent", MacV6: "macv6", Ipv6Addr: "ipv6", ParentDeviceIpv6: "parentv6"},
			VXLANTunnelEndpointUpdate{
				Node: "node", Mac: "mac", Ipv4Addr: "ipv4", ParentDeviceIp: "parent", MacV6: "macv6", Ipv6Addr: "ipv6", ParentDeviceIpv6: "parentv6"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProtoToVXLANTunnelEndpointUpdate(tt.msg); got != tt.want {
				t.Errorf("ProtoToVXLANTunnelEndpointUpdate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProtoToWireguardEndpointUpdate(t *testing.T) {
	tests := []struct {
		name string
		msg  *proto.WireguardEndpointUpdate
		want WireguardEndpointUpdate
	}{
		{"empty", &proto.WireguardEndpointUpdate{}, WireguardEndpointUpdate{}},
		{"non-empty",
			&proto.WireguardEndpointUpdate{
				Hostname: "hostname", PublicKey: "public", InterfaceIpv4Addr: "ipv4"},
			WireguardEndpointUpdate{
				Hostname: "hostname", PublicKey: "public", InterfaceIpv4Addr: "ipv4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProtoToWireguardEndpointUpdate(tt.msg); got != tt.want {
				t.Errorf("ProtoToWireguardEndpointUpdate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProtoToWireguardEndpointV6Update(t *testing.T) {
	tests := []struct {
		name string
		msg  *proto.WireguardEndpointV6Update
		want WireguardEndpointV6Update
	}{
		{"empty", &proto.WireguardEndpointV6Update{}, WireguardEndpointV6Update{}},
		{"non-empty",
			&proto.WireguardEndpointV6Update{
				Hostname: "hostname", PublicKeyV6: "public", InterfaceIpv6Addr: "ipv6"},
			WireguardEndpointV6Update{
				Hostname: "hostname", PublicKeyV6: "public", InterfaceIpv6Addr: "ipv6"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProtoToWireguardEndpointV6Update(tt.msg); got != tt.want {
				t.Errorf("ProtoToWireguardEndpointV6Update() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProtoToRouteUpdate(t *testing.T) {
	tests := []struct {
		name string
		msg  *proto.RouteUpdate
		want RouteUpdate
	}{
		{"empty", &proto.RouteUpdate{}, RouteUpdate{}},
		{"non-empty",
			&proto.RouteUpdate{
				Type:          proto.RouteType_CIDR_INFO,
				IpPoolType:    proto.IPPoolType_VXLAN,
				Dst:           "dst",
				DstNodeName:   "node",
				DstNodeIp:     "ip",
				SameSubnet:    true,
				NatOutgoing:   true,
				LocalWorkload: true,
				TunnelType:    &proto.TunnelType{Vxlan: true}},
			RouteUpdate{
				Type:          proto.RouteType_CIDR_INFO,
				IpPoolType:    proto.IPPoolType_VXLAN,
				Dst:           "dst",
				DstNodeName:   "node",
				DstNodeIp:     "ip",
				SameSubnet:    true,
				NatOutgoing:   true,
				LocalWorkload: true,
				TunnelType:    &proto.TunnelType{Vxlan: true}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := require.New(t)
			got := ProtoToRouteUpdate(tt.msg)
			assert.Equal(tt.want.Type, got.Type)
			assert.Equal(tt.want.IpPoolType, got.IpPoolType)
			assert.Equal(tt.want.Dst, got.Dst)
			assert.Equal(tt.want.DstNodeName, got.DstNodeName)
			assert.Equal(tt.want.DstNodeIp, got.DstNodeIp)
			assert.Equal(tt.want.SameSubnet, got.SameSubnet)
			assert.Equal(tt.want.NatOutgoing, got.NatOutgoing)
			assert.Equal(tt.want.LocalWorkload, got.LocalWorkload)
			assert.Equal(tt.want.TunnelType, got.TunnelType)
		})
	}
}
