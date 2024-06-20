// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package generictables

import (
	"github.com/projectcalico/calico/felix/proto"
)

type MatchCriteria interface {
	Render() string
	String() string
	MarkClear(mark uint32) MatchCriteria
	MarkNotClear(mark uint32) MatchCriteria
	MarkSingleBitSet(mark uint32) MatchCriteria
	MarkMatchesWithMask(mark, mask uint32) MatchCriteria
	NotMarkMatchesWithMask(mark, mask uint32) MatchCriteria
	InInterface(ifaceMatch string) MatchCriteria
	OutInterface(ifaceMatch string) MatchCriteria
	RPFCheckFailed() MatchCriteria
	IPVSConnection() MatchCriteria
	NotIPVSConnection() MatchCriteria
	NotSrcAddrType(addrType AddrType, limitIfaceOut bool) MatchCriteria
	SrcAddrType(addrType AddrType, limitIfaceOut bool) MatchCriteria
	DestAddrType(addrType AddrType) MatchCriteria
	NotDestAddrType(addrType AddrType) MatchCriteria
	ConntrackState(stateNames string) MatchCriteria
	NotConntrackState(stateNames string) MatchCriteria
	Protocol(name string) MatchCriteria
	NotProtocol(name string) MatchCriteria
	ProtocolNum(num uint8) MatchCriteria
	NotProtocolNum(num uint8) MatchCriteria
	SourceNet(net string) MatchCriteria
	NotSourceNet(net string) MatchCriteria
	DestNet(net string) MatchCriteria
	NotDestNet(net string) MatchCriteria
	SourceIPSet(name string) MatchCriteria
	NotSourceIPSet(name string) MatchCriteria
	SourceIPPortSet(name string) MatchCriteria
	NotSourceIPPortSet(name string) MatchCriteria
	DestIPSet(name string) MatchCriteria
	NotDestIPSet(name string) MatchCriteria
	DestIPPortSet(name string) MatchCriteria
	NotDestIPPortSet(name string) MatchCriteria
	IPSetNames() (ipSetNames []string)
	SourcePorts(ports ...uint16) MatchCriteria
	NotSourcePorts(ports ...uint16) MatchCriteria
	DestPorts(ports ...uint16) MatchCriteria
	NotDestPorts(ports ...uint16) MatchCriteria
	SourcePortRanges(ports []*proto.PortRange) MatchCriteria
	NotSourcePortRanges(ports []*proto.PortRange) MatchCriteria
	DestPortRanges(ports []*proto.PortRange) MatchCriteria
	NotDestPortRanges(ports []*proto.PortRange) MatchCriteria
	ICMPType(t uint8) MatchCriteria
	NotICMPType(t uint8) MatchCriteria
	ICMPTypeAndCode(t, c uint8) MatchCriteria
	NotICMPTypeAndCode(t, c uint8) MatchCriteria
	ICMPV6Type(t uint8) MatchCriteria
	NotICMPV6Type(t uint8) MatchCriteria
	ICMPV6TypeAndCode(t, c uint8) MatchCriteria
	NotICMPV6TypeAndCode(t, c uint8) MatchCriteria
}

type AddrType string

const (
	AddrTypeLocal AddrType = "LOCAL"
)
