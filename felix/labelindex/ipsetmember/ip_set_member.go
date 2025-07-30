// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package ipsetmember

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ip"
)

type IPSetMember interface {
	ToProtobufFormat() string
	fmt.Stringer
}

func MakeIPPortProto(addr ip.Addr, port uint16, proto Protocol) IPSetMember {
	if port == 0 && proto == ProtocolNone {
		return MakeCIDROrIPOnly(addr.AsCIDR())
	}

	// By using the address type as a type parameter, we can embed the IP
	// directly in the struct and use a lot less storage.
	switch addr := addr.(type) {
	case ip.V4Addr:
		return ipPortProtoIPSetMember[ip.V4Addr]{
			addr:  addr,
			port:  port,
			proto: proto,
		}
	case ip.V6Addr:
		return ipPortProtoIPSetMember[ip.V6Addr]{
			addr:  addr,
			port:  port,
			proto: proto,
		}
	default:
		logrus.WithField("addr", addr).Panic("Unknown IP type.")
		panic("Unknown IP type.")
	}
}

type ipPortProtoIPSetMember[IPType ip.Addr] struct {
	addr  IPType
	port  uint16
	proto Protocol
}

func (m ipPortProtoIPSetMember[IPType]) ToProtobufFormat() string {
	switch m.Protocol() {
	case ProtocolTCP:
		return fmt.Sprintf("%s,tcp:%d", m.CIDR().Addr(), m.PortNumber())
	case ProtocolUDP:
		return fmt.Sprintf("%s,udp:%d", m.CIDR().Addr(), m.PortNumber())
	case ProtocolSCTP:
		return fmt.Sprintf("%s,sctp:%d", m.CIDR().Addr(), m.PortNumber())
	default:
		logrus.WithField("member", m).Panic("protocol can't be ProtocolNone in a ipPortProtoIPSetMember")
		panic("protocol can't be ProtocolNone in a ipPortProtoIPSetMember")
	}
}

func (m ipPortProtoIPSetMember[IPType]) String() string {
	return fmt.Sprintf("%T(%v,%v,%v)", m, m.addr, m.port, m.proto)
}

func (m ipPortProtoIPSetMember[IPType]) CIDR() ip.CIDR {
	return m.addr.AsCIDR()
}

func (m ipPortProtoIPSetMember[IPType]) Protocol() Protocol {
	return m.proto
}

func (m ipPortProtoIPSetMember[IPType]) PortNumber() uint16 {
	return m.port
}

func MakeCIDROrIPOnly(cidr ip.CIDR) CIDROrIPOnlyIPSetMember {
	if cidr.IsSingleAddress() {
		return MakeSingleIP(cidr.Addr())
	}
	switch cidr := cidr.(type) {
	case ip.V4CIDR:
		return cidrIPSetMember[ip.V4CIDR]{
			cidr: cidr,
		}
	case ip.V6CIDR:
		return cidrIPSetMember[ip.V6CIDR]{
			cidr: cidr,
		}
	default:
		logrus.WithField("cidr", cidr).Panic("Unknown CIDR type.")
		panic("Unknown CIDR type.")
	}
}

type CIDROrIPOnlyIPSetMember interface {
	IPSetMember
	CIDR() ip.CIDR

	CIDROrIPOnlyIPSetMember() // No-op marker method
}

type cidrIPSetMember[CIDRType ip.CIDR] struct {
	cidr CIDRType
}

func (m cidrIPSetMember[CIDRType]) CIDROrIPOnlyIPSetMember() {}

func (m cidrIPSetMember[CIDRType]) ToProtobufFormat() string {
	return m.CIDR().String()
}

func (m cidrIPSetMember[CIDRType]) String() string {
	return fmt.Sprintf("%T(%s)", m, m.ToProtobufFormat())
}

func (m cidrIPSetMember[CIDRType]) CIDR() ip.CIDR {
	return m.cidr
}

func MakeSingleIP(addr ip.Addr) CIDROrIPOnlyIPSetMember {
	switch addr := addr.(type) {
	case ip.V4Addr:
		return ipAddrIPSetMember[ip.V4Addr]{
			addr: addr,
		}
	case ip.V6Addr:
		return ipAddrIPSetMember[ip.V6Addr]{
			addr: addr,
		}
	default:
		logrus.WithField("cidr", addr).Panic("Unknown CIDR type.")
		panic("Unknown CIDR type.")
	}
}

type ipAddrIPSetMember[AddrType ip.Addr] struct {
	addr AddrType
}

func (m ipAddrIPSetMember[AddrType]) CIDROrIPOnlyIPSetMember() {}

func (m ipAddrIPSetMember[AddrType]) ToProtobufFormat() string {
	return m.CIDR().String()
}

func (m ipAddrIPSetMember[AddrType]) String() string {
	return fmt.Sprintf("%T(%s)", m, m.ToProtobufFormat())
}

func (m ipAddrIPSetMember[AddrType]) CIDR() ip.CIDR {
	return m.addr.AsCIDR()
}
