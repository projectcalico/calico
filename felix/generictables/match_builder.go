// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
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

// MatchCapabilities says how much one rule's match can hold on a given backend. The
// policy renderer splits anything larger across extra rules, using mark bits to combine them.
type MatchCapabilities struct {
	// CIDRsPerRule is how many source CIDRs, positive and negated together, one rule
	// can match. It limits destination CIDRs separately, so a rule can hold this many
	// of each.
	CIDRsPerRule int

	// PortsPerRule is how many ports one source or destination port match can hold.
	// A port range counts as two ports, as in an iptables multiport match.
	PortsPerRule int
}

type MatchCriteria interface {
	Render() string
	String() string
	MarkClear(mark uint32) MatchCriteria
	MarkNotClear(mark uint32) MatchCriteria
	MarkSingleBitSet(mark uint32) MatchCriteria
	MarkMatchesWithMask(mark, mask uint32) MatchCriteria
	NotMarkMatchesWithMask(mark, mask uint32) MatchCriteria
	ConnMarkMatchesWithMask(mark, mask uint32) MatchCriteria
	TCPFlagsSet(flags string) MatchCriteria
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

	// SourceNets, NotSourceNets, DestNets and NotDestNets match any (or, negated, none)
	// of the given CIDRs. Callers must keep the list within the backend's MatchCapabilities.
	SourceNets(nets []string) MatchCriteria
	NotSourceNets(nets []string) MatchCriteria
	DestNets(nets []string) MatchCriteria
	NotDestNets(nets []string) MatchCriteria

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
	DestPort(port uint16) MatchCriteria
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
	Limit(r string, b uint16) MatchCriteria

	// Only supported in nftables.
	InInterfaceVMAP(mapname string) MatchCriteria
	OutInterfaceVMAP(mapname string) MatchCriteria

	// ARP family matches (only supported in nftables ARP table).
	ARPOperation(op string) MatchCriteria
	ARPSrcIP(ip string) MatchCriteria
}

type AddrType string

const (
	AddrTypeLocal AddrType = "LOCAL"
)
