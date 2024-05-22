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
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/proto"
)

var Wildcard = "*"

var (
	_ generictables.MatchCriteria    = nftMatch{}
	_ generictables.NFTMatchCriteria = nftMatch{}
)

const (
	ProtoIPIP   = 4
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

// nftMatch implements the MatchCriteria interface for nftables.
type nftMatch struct {
	clauses []string

	ipVersion uint8

	proto    string
	protoNum uint8
}

func (m nftMatch) protocol() string {
	if m.proto != "" {
		return m.proto
	}
	if m.protoNum != 0 {
		return protoNumToName(m.protoNum)
	}
	logrus.Panicf("Probably bug: No protocol set: %s", m.clauses)
	return ""
}

func protoNumToName(protoNum uint8) string {
	switch protoNum {
	case ProtoIPIP:
		return "ipip"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMPv6:
		return "icmp"
	}
	return fmt.Sprintf("%d", protoNum)
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
		joined = strings.ReplaceAll(joined, "IPV", "ip6")
	} else {
		joined = strings.ReplaceAll(joined, "IPV", "ip")
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

func (m nftMatch) RPFCheckPassed(acceptLocal bool) generictables.MatchCriteria {
	// TODO: acceptLocal is not supported in nftables mode.
	m.clauses = append(m.clauses, "fib saddr . mark . iif oif != 0")
	return m
}

func (m nftMatch) RPFCheckFailed(acceptLocal bool) generictables.MatchCriteria {
	// TODO: acceptLocal is not supported in nftables mode.
	// https://wiki.nftables.org/wiki-nftables/index.php/Matching_routing_information
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
	m.clauses = append(m.clauses, fmt.Sprintf("meta l4proto %s", protoNumToName(num)))
	return m
}

func (m nftMatch) NotProtocolNum(num uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("meta l4proto != %s", protoNumToName(num)))
	return m
}

func (m nftMatch) SourceNet(net string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("IPV saddr %s", net))
	return m
}

func (m nftMatch) NotSourceNet(net string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("IPV saddr != %s", net))
	return m
}

func (m nftMatch) DestNet(net string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("IPV daddr %s", net))
	return m
}

func (m nftMatch) NotDestNet(net string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("IPV daddr != %s", net))
	return m
}

func (m nftMatch) SourceIPSet(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("IPV saddr @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) NotSourceIPSet(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("IPV saddr != @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) SourceIPPortSet(name string) generictables.MatchCriteria {
	// IPPort sets include the IP, protocol, and port, in that order.
	// Note that "th dport" is only compatible with protocols that have their destination port in
	// the same location within the header, i.e., TCP, UDP, and SCTP.
	m.clauses = append(m.clauses, fmt.Sprintf("IPV saddr . meta l4proto . th sport @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) NotSourceIPPortSet(name string) generictables.MatchCriteria {
	// IPPort sets include the IP, protocol, and port, in that order.
	// Note that "th dport" is only compatible with protocols that have their destination port in
	// the same location within the header, i.e., TCP, UDP, and SCTP.
	m.clauses = append(m.clauses, fmt.Sprintf("IPV saddr . meta l4proto . th sport != @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) DestIPSet(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("IPV daddr @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) NotDestIPSet(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("IPV daddr != @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) DestIPPortSet(name string) generictables.MatchCriteria {
	// IPPort sets include the IP, protocol, and port, in that order.
	// Note that "th dport" is only compatible with protocols that have their destination port in
	// the same location within the header, i.e., TCP, UDP, and SCTP.
	m.clauses = append(m.clauses, fmt.Sprintf("IPV daddr . meta l4proto . th dport @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) NotDestIPPortSet(name string) generictables.MatchCriteria {
	// IPPort sets include the IP, protocol, and port, in that order.
	// Note that "th dport" is only compatible with protocols that have their destination port in
	// the same location within the header, i.e., TCP, UDP, and SCTP.
	m.clauses = append(m.clauses, fmt.Sprintf("IPV daddr . meta l4proto . th dport != @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) IPSetNames() (ipSetNames []string) {
	for _, matchString := range []string(m.clauses) {
		if strings.Contains(matchString, "IPV saddr @") {
			ipSetNames = append(ipSetNames, strings.TrimPrefix(strings.Split(matchString, " ")[2], "@"))
		}
		if strings.Contains(matchString, "IPV daddr @") {
			ipSetNames = append(ipSetNames, strings.TrimPrefix(strings.Split(matchString, " ")[2], "@"))
		}
		if strings.Contains(matchString, "IPV saddr != @") {
			ipSetNames = append(ipSetNames, strings.TrimPrefix(strings.Split(matchString, " ")[3], "@"))
		}
		if strings.Contains(matchString, "IPV daddr != @") {
			ipSetNames = append(ipSetNames, strings.TrimPrefix(strings.Split(matchString, " ")[3], "@"))
		}
	}
	return
}

func (m nftMatch) SourcePorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s sport %s", m.protocol(), portsString))
	return m
}

func (m nftMatch) NotSourcePorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s sport != %s", m.protocol(), portsString))
	return m
}

func (m nftMatch) DestPorts(ports ...uint16) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("%s dport %s", m.protocol(), PortsToMultiport(ports)))
	return m
}

func (m nftMatch) NotDestPorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s dport != %s", m.protocol(), portsString))
	return m
}

func (m nftMatch) SourcePortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s sport %s", m.protocol(), portsString))
	return m
}

func (m nftMatch) NotSourcePortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s sport != %s", m.protocol(), portsString))
	return m
}

func (m nftMatch) DestPortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s dport %s", m.protocol(), portsString))
	return m
}

func (m nftMatch) NotDestPortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s dport != %s", m.protocol(), portsString))
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
	m.clauses = append(m.clauses, fmt.Sprintf("icmp type %d", t))
	return m
}

func (m nftMatch) NotICMPV6Type(t uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("icmp type != %d", t))
	return m
}

func (m nftMatch) ICMPV6TypeAndCode(t, c uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("icmp type %d code %d", t, c))
	return m
}

func (m nftMatch) NotICMPV6TypeAndCode(t, c uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("icmp type != %d code != %d", t, c))
	return m
}

// VXLANVNI matches on the VNI contained within the VXLAN header.  It assumes that this is indeed a VXLAN
// packet; i.e. it should be used with a protocol==UDP and port==VXLAN port match.
//
// Note: the -m u32 option is not supported on iptables in NFT mode.
// https://wiki.nftables.org/wiki-nftables/index.php/Supported_features_compared_to_xtables#u32
func (m nftMatch) VXLANVNI(vni uint32) generictables.MatchCriteria {
	// TODO: Not supported in nftables mode.
	return m
}

// Converts a list of ports to a multiport set suitable for inline use in nftables rules.
func PortsToMultiport(ports []uint16) string {
	if len(ports) == 1 {
		return fmt.Sprintf("%d", ports[0])
	}
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
