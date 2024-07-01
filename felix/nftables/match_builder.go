// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
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

package nftables

import (
	"fmt"
	"math/bits"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var Wildcard = "*"

var (
	_ generictables.MatchCriteria = nftMatch{}
	_ NFTMatchCriteria            = nftMatch{}

	// ipSetMatch matches clauses that contain an IP set reference.
	ipSetMatch = regexp.MustCompile("<IPV>.*@(.*)")
)

const (
	ProtoIPIP   = 4
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
	ProtoSCTP   = 132
)

// NFTMatchCriteria extends the generictables.MatchCriteria interface with nftables-specific methods.
type NFTMatchCriteria interface {
	generictables.MatchCriteria

	IPVersion(version uint8) generictables.MatchCriteria

	ConntrackStatus(statusNames string) generictables.MatchCriteria
	NotConntrackStatus(statusNames string) generictables.MatchCriteria
}

// nftMatch implements the MatchCriteria interface for nftables.
type nftMatch struct {
	clauses []string

	ipVersion uint8

	proto    string
	protoNum uint8
}

// protocol is a convenience function that looks at both the string and numeric protocol fields
// to determine which l4proto to use for the match.
func (m nftMatch) protocol() string {
	if m.proto != "" {
		return m.proto
	}
	if m.protoNum != 0 {
		return fmt.Sprintf("%d", m.protoNum)
	}
	logrus.Panicf("Probably bug: No protocol set: %s", m.clauses)
	return ""
}

// transportProto returns the transport header protocol in string form, necessary for
// matching on source and destination ports. If the protocol is not a valid
// protocol utilizing transport header ports (i.e., TCP/UDP/SCTP), this function will panic.
func (m nftMatch) transportProto() string {
	switch m.protoNum {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoSCTP:
		return "sctp"
	}
	switch m.proto {
	case "tcp", "udp", "sctp":
		return m.proto
	}
	logrus.WithFields(logrus.Fields{
		"proto": m.proto,
		"num":   m.protoNum,
	}).Panicf("Probably bug: protocol is not one of TCP/UDP/SCTP: %s", m.clauses)
	return ""
}

func Match() generictables.MatchCriteria {
	return new(nftMatch)
}

func (m nftMatch) IPVersion(ipVersion uint8) generictables.MatchCriteria {
	m.ipVersion = ipVersion
	return m
}

func (m nftMatch) Render() string {
	joined := strings.Join(m.clauses, " ")
	// Replace instances of IPV with the correct IP version.
	if m.ipVersion == 6 {
		joined = strings.ReplaceAll(joined, "<IPV>", "ip6")
	} else {
		joined = strings.ReplaceAll(joined, "<IPV>", "ip")
	}
	return joined
}

func (m nftMatch) String() string {
	return fmt.Sprintf("MatchCriteria[%s]", m.Render())
}

func (m nftMatch) MarkClear(mark uint32) generictables.MatchCriteria {
	if mark == 0 {
		logrus.Panic("Probably bug: zero mark")
	}
	m.clauses = append(m.clauses, fmt.Sprintf("meta mark & %#x == 0", mark))
	return m
}

func (m nftMatch) MarkNotClear(mark uint32) generictables.MatchCriteria {
	if mark == 0 {
		logrus.Panic("Probably bug: zero mark")
	}
	m.clauses = append(m.clauses, fmt.Sprintf("meta mark & %#x != 0", mark))
	return m
}

func (m nftMatch) MarkSingleBitSet(mark uint32) generictables.MatchCriteria {
	if bits.OnesCount32(mark) != 1 {
		// Disallow multi-bit matches to force user to think about the mask they should use.
		// For example, if you are storing a number in the mark then you likely want to match on its
		// 0-bits too
		logrus.WithField("mark", mark).Panic("MarkSingleBitSet() should only be used with a single mark bit")
	}
	return m.MarkMatchesWithMask(mark, mark)
}

func (m nftMatch) MarkMatchesWithMask(mark, mask uint32) generictables.MatchCriteria {
	logCxt := logrus.WithFields(logrus.Fields{
		"mark": mark,
		"mask": mask,
	})
	if mask == 0 {
		logCxt.Panic("Bug: mask is 0.")
	}
	if mark&mask != mark {
		logCxt.Panic("Bug: mark is not contained in mask")
	}
	m.clauses = append(m.clauses, fmt.Sprintf("meta mark & %#x == %#x", mask, mark))
	return m
}

func (m nftMatch) NotMarkMatchesWithMask(mark, mask uint32) generictables.MatchCriteria {
	logCxt := logrus.WithFields(logrus.Fields{
		"mark": mark,
		"mask": mask,
	})
	if mask == 0 {
		logCxt.Panic("Bug: mask is 0.")
	}
	if mark&mask != mark {
		logCxt.Panic("Bug: mark is not contained in mask")
	}
	m.clauses = append(m.clauses, fmt.Sprintf("meta mark & %#x != %#x", mask, mark))
	return m
}

func (m nftMatch) InInterface(ifaceMatch string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("iifname %s", ifaceMatch))
	return m
}

func (m nftMatch) OutInterface(ifaceMatch string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("oifname %s", ifaceMatch))
	return m
}

func (m nftMatch) RPFCheckFailed() generictables.MatchCriteria {
	m.clauses = append(m.clauses, "fib saddr . mark . iif oif 0")
	return m
}

func (m nftMatch) IPVSConnection() generictables.MatchCriteria {
	panic("IPVS not supported in nftables mode")
}

func (m nftMatch) NotIPVSConnection() generictables.MatchCriteria {
	panic("IPVS not supported in nftables mode")
}

func (m nftMatch) NotSrcAddrType(addrType generictables.AddrType, limitIfaceOut bool) generictables.MatchCriteria {
	if limitIfaceOut {
		m.clauses = append(m.clauses, fmt.Sprintf("fib saddr . oif type != %s", strings.ToLower(string(addrType))))
	} else {
		m.clauses = append(m.clauses, fmt.Sprintf("fib saddr type != %s", strings.ToLower(string(addrType))))
	}
	return m
}

func (m nftMatch) SrcAddrType(addrType generictables.AddrType, limitIfaceOut bool) generictables.MatchCriteria {
	if limitIfaceOut {
		m.clauses = append(m.clauses, fmt.Sprintf("fib saddr . oif type %s", strings.ToLower(string(addrType))))
	} else {
		m.clauses = append(m.clauses, fmt.Sprintf("fib saddr type %s", strings.ToLower(string(addrType))))
	}
	return m
}

func (m nftMatch) DestAddrType(addrType generictables.AddrType) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("fib daddr type %s", strings.ToLower(string(addrType))))
	return m
}

func (m nftMatch) NotDestAddrType(addrType generictables.AddrType) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("fib daddr type != %s", strings.ToLower(string(addrType))))
	return m
}

func (m nftMatch) ConntrackStatus(statusNames string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ct status %s", strings.ToLower(statusNames)))
	return m
}

func (m nftMatch) NotConntrackStatus(statusNames string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ct status != %s", strings.ToLower(statusNames)))
	return m
}

func (m nftMatch) ConntrackState(stateNames string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ct state %s", strings.ToLower(stateNames)))
	return m
}

func (m nftMatch) NotConntrackState(stateNames string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ct state != %s", strings.ToLower(stateNames)))
	return m
}

func (m nftMatch) Protocol(name string) generictables.MatchCriteria {
	if m.proto != "" {
		logrus.WithField("protocol", m.proto).Fatal("Protocol already set")
	} else if m.protoNum != 0 {
		logrus.WithField("protocol", m.protoNum).Fatal("Protocol already set")
	}
	m.proto = name

	// The "meta l4proto" matches on nftables metadata about the packet, which allows this
	// match to work for both IPv4 and IPv6 packets.  The "ip protocol" match only works for
	// IPv4 packets.
	m.clauses = append(m.clauses, fmt.Sprintf("meta l4proto %s", name))
	return m
}

func (m nftMatch) NotProtocol(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("meta l4proto != %s", name))
	return m
}

func (m nftMatch) ProtocolNum(num uint8) generictables.MatchCriteria {
	if m.proto != "" {
		logrus.WithField("protocol", m.proto).Fatal("Protocol already set")
	} else if m.protoNum != 0 {
		logrus.WithField("protocol", m.protoNum).Fatal("Protocol already set")
	}
	m.protoNum = num

	// The "meta l4proto" matches on nftables metadata about the packet, which allows this
	// match to work for both IPv4 and IPv6 packets.  The "ip protocol" match only works for
	// IPv4 packets.
	m.clauses = append(m.clauses, fmt.Sprintf("meta l4proto %s", m.protocol()))
	return m
}

func (m nftMatch) NotProtocolNum(num uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("meta l4proto != %d", num))
	return m
}

func (m nftMatch) SourceNet(net string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("<IPV> saddr %s", net))
	return m
}

func (m nftMatch) NotSourceNet(net string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("<IPV> saddr != %s", net))
	return m
}

func (m nftMatch) DestNet(net string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("<IPV> daddr %s", net))
	return m
}

func (m nftMatch) NotDestNet(net string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("<IPV> daddr != %s", net))
	return m
}

func (m nftMatch) SourceIPSet(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("<IPV> saddr @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) NotSourceIPSet(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("<IPV> saddr != @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) SourceIPPortSet(name string) generictables.MatchCriteria {
	// IPPort sets include the IP, protocol, and port, in that order.
	// Note that "th sport" is only compatible with protocols that have their destination port in
	// the same location within the header, i.e., TCP, UDP, and SCTP.
	m.clauses = append(m.clauses, fmt.Sprintf("<IPV> saddr . meta l4proto . th sport @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) NotSourceIPPortSet(name string) generictables.MatchCriteria {
	// IPPort sets include the IP, protocol, and port, in that order.
	// Note that "th sport" is only compatible with protocols that have their destination port in
	// the same location within the header, i.e., TCP, UDP, and SCTP.
	m.clauses = append(m.clauses, fmt.Sprintf("<IPV> saddr . meta l4proto . th sport != @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) DestIPSet(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("<IPV> daddr @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) NotDestIPSet(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("<IPV> daddr != @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) DestIPPortSet(name string) generictables.MatchCriteria {
	// IPPort sets include the IP, protocol, and port, in that order.
	// Note that "th dport" is only compatible with protocols that have their destination port in
	// the same location within the header, i.e., TCP, UDP, and SCTP.
	m.clauses = append(m.clauses, fmt.Sprintf("<IPV> daddr . meta l4proto . th dport @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) NotDestIPPortSet(name string) generictables.MatchCriteria {
	// IPPort sets include the IP, protocol, and port, in that order.
	// Note that "th dport" is only compatible with protocols that have their destination port in
	// the same location within the header, i.e., TCP, UDP, and SCTP.
	m.clauses = append(m.clauses, fmt.Sprintf("<IPV> daddr . meta l4proto . th dport != @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) IPSetNames() []string {
	// Uset a set to deduplicate the names.
	ipSetNames := set.New[string]()
	for _, clause := range []string(m.clauses) {
		match := ipSetMatch.FindStringSubmatch(clause)
		if len(match) > 2 {
			logrus.WithField("clause", clause).Panic("Probably bug: multiple IP set names found")
		} else if len(match) == 2 {
			// Found a match.
			ipSetNames.Add(match[1])
		}
	}
	return ipSetNames.Slice()
}

func (m nftMatch) SourcePorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s sport %s", m.transportProto(), portsString))
	return m
}

func (m nftMatch) NotSourcePorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s sport != %s", m.transportProto(), portsString))
	return m
}

func (m nftMatch) DestPorts(ports ...uint16) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("%s dport %s", m.transportProto(), PortsToMultiport(ports)))
	return m
}

func (m nftMatch) NotDestPorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s dport != %s", m.transportProto(), portsString))
	return m
}

func (m nftMatch) SourcePortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s sport %s", m.transportProto(), portsString))
	return m
}

func (m nftMatch) NotSourcePortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s sport != %s", m.transportProto(), portsString))
	return m
}

func (m nftMatch) DestPortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s dport %s", m.transportProto(), portsString))
	return m
}

func (m nftMatch) NotDestPortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s dport != %s", m.transportProto(), portsString))
	return m
}

func (m nftMatch) ICMPType(t uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("icmp type %d", t))
	return m
}

func (m nftMatch) NotICMPType(t uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("icmp type != %d", t))
	return m
}

func (m nftMatch) ICMPTypeAndCode(t, c uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("icmp type %d code %d", t, c))
	return m
}

func (m nftMatch) NotICMPTypeAndCode(t, c uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("icmp type != %d code != %d", t, c))
	return m
}

func (m nftMatch) ICMPV6Type(t uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("icmpv6 type %d", t))
	return m
}

func (m nftMatch) NotICMPV6Type(t uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("icmpv6 type != %d", t))
	return m
}

func (m nftMatch) ICMPV6TypeAndCode(t, c uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("icmpv6 type %d code %d", t, c))
	return m
}

func (m nftMatch) NotICMPV6TypeAndCode(t, c uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("icmpv6 type != %d code != %d", t, c))
	return m
}

// PortsToMultiport converts a list of ports to a multiport set suitable for inline use in nftables rules.
func PortsToMultiport(ports []uint16) string {
	portFragments := make([]string, len(ports))
	for i, port := range ports {
		portFragments[i] = fmt.Sprintf("%d", port)
	}
	portsString := strings.Join(portFragments, ", ")
	return fmt.Sprintf("{ %s }", portsString)
}

func PortRangesToMultiport(ports []*proto.PortRange) string {
	portFragments := make([]string, len(ports))
	for i, port := range ports {
		if port.First == port.Last {
			portFragments[i] = fmt.Sprintf("%d", port.First)
		} else {
			portFragments[i] = fmt.Sprintf("%d-%d", port.First, port.Last)
		}
	}
	portsString := strings.Join(portFragments, ", ")
	return fmt.Sprintf("{ %s }", portsString)
}
