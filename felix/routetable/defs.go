// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package routetable

import (
	"errors"
	"net"
	"reflect"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/ip"
)

//go:generate stringer -type=RouteClass

// RouteClass is a type used to identify the different groups of routes
// that we program.  It is used as a tie-breaker when there are conflicting
// routes for the same CIDR (lowest numeric value wins).
type RouteClass int

const (
	RouteClassLocalWorkload RouteClass = iota
	RouteClassBPFSpecial
	RouteClassWireguard
	RouteClassVXLANSameSubnet
	RouteClassVXLANTunnel
	RouteClassIPAMBlockDrop

	RouteClassMax
)

func (c RouteClass) IsRemote() bool {
	switch c {
	case RouteClassVXLANTunnel, RouteClassVXLANSameSubnet, RouteClassWireguard:
		return true
	default:
		return false
	}
}

const (
	// Use this for targets with no outbound interface.
	InterfaceNone = "*NoOIF*"
)

var (
	ConnectFailed   = errors.New("connect to netlink failed")
	ListFailed      = errors.New("netlink list operation failed")
	UpdateFailed    = errors.New("netlink update operation failed")
	IfaceNotPresent = errors.New("interface not present")
	IfaceDown       = errors.New("interface down")
)

type Target struct {
	Type     TargetType
	CIDR     ip.CIDR
	GW       ip.Addr
	Src      ip.Addr
	DestMAC  net.HardwareAddr
	Protocol netlink.RouteProtocol
}

func (t Target) Equal(t2 Target) bool {
	return reflect.DeepEqual(t, t2)
}

func (t Target) RouteType() int {
	switch t.Type {
	case TargetTypeLocal:
		return unix.RTN_LOCAL
	case TargetTypeThrow:
		return unix.RTN_THROW
	case TargetTypeBlackhole:
		return unix.RTN_BLACKHOLE
	case TargetTypeProhibit:
		return unix.RTN_PROHIBIT
	case TargetTypeUnreachable:
		return unix.RTN_UNREACHABLE
	default:
		return unix.RTN_UNICAST
	}
}

func (t Target) RouteScope() netlink.Scope {
	switch t.Type {
	case TargetTypeLocal:
		return netlink.SCOPE_HOST
	case TargetTypeLinkLocalUnicast:
		return netlink.SCOPE_LINK
	case TargetTypeGlobalUnicast:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeNoEncap:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeVXLAN:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeThrow:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeBlackhole:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeProhibit:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeOnLink:
		return netlink.SCOPE_LINK
	default:
		return netlink.SCOPE_LINK
	}
}

func (t Target) Flags() netlink.NextHopFlag {
	switch t.Type {
	case TargetTypeVXLAN, TargetTypeNoEncap, TargetTypeOnLink:
		return unix.RTNH_F_ONLINK
	default:
		return 0
	}
}

type TargetType string

const (
	TargetTypeLocal            TargetType = "local"
	TargetTypeVXLAN            TargetType = "vxlan"
	TargetTypeNoEncap          TargetType = "noencap"
	TargetTypeOnLink           TargetType = "onlink"
	TargetTypeGlobalUnicast    TargetType = "global-unicast"
	TargetTypeLinkLocalUnicast TargetType = "local-unicast"

	// The following target types should be used with InterfaceNone.

	TargetTypeBlackhole   TargetType = "blackhole"
	TargetTypeProhibit    TargetType = "prohibit"
	TargetTypeThrow       TargetType = "throw"
	TargetTypeUnreachable TargetType = "unreachable"
)
