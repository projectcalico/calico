// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.
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
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/proto"
)

var Wildcard = "*"

var _ generictables.MatchCriteria = nftMatch{}

// nftMatch implements the MatchCriteria interface for nftables.
type nftMatch struct {
	clauses []string
	proto   string
}

func Match() generictables.MatchCriteria {
	return new(nftMatch)
}

func (m nftMatch) Render() string {
	return strings.Join([]string(m.clauses), " ")
}

func (m nftMatch) String() string {
	return fmt.Sprintf("MatchCriteria[%s]", m.Render())
}

func (m nftMatch) MarkClear(mark uint32) generictables.MatchCriteria {
	if mark == 0 {
		log.Panic("Probably bug: zero mark")
	}
	m.clauses = append(m.clauses, fmt.Sprintf("meta mark & %#x == 0", mark))
	return m
}

func (m nftMatch) MarkNotClear(mark uint32) generictables.MatchCriteria {
	if mark == 0 {
		log.Panic("Probably bug: zero mark")
	}
	m.clauses = append(m.clauses, fmt.Sprintf("meta mark & %#x != 0", mark))
	return m
}

func (m nftMatch) MarkSingleBitSet(mark uint32) generictables.MatchCriteria {
	if bits.OnesCount32(mark) != 1 {
		// Disallow multi-bit matches to force user to think about the mask they should use.
		// For example, if you are storing a number in the mark then you likely want to match on its
		// 0-bits too
		log.WithField("mark", mark).Panic("MarkSingleBitSet() should only be used with a single mark bit")
	}
	return m.MarkMatchesWithMask(mark, mark)
}

func (m nftMatch) MarkMatchesWithMask(mark, mask uint32) generictables.MatchCriteria {
	logCxt := log.WithFields(log.Fields{
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
	logCxt := log.WithFields(log.Fields{
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
	}
	m.proto = name
	m.clauses = append(m.clauses, fmt.Sprintf("ip protocol %s", name))
	return m
}

func (m nftMatch) NotProtocol(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ip protocol != %s", name))
	return m
}

func (m nftMatch) ProtocolNum(num uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ip protocol %d", num))
	return m
}

func (m nftMatch) NotProtocolNum(num uint8) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ip protocol != %d", num))
	return m
}

func (m nftMatch) SourceNet(net string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ip saddr %s", net))
	return m
}

func (m nftMatch) NotSourceNet(net string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ip saddr != %s", net))
	return m
}

func (m nftMatch) DestNet(net string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ip daddr %s", net))
	return m
}

func (m nftMatch) NotDestNet(net string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ip daddr != %s", net))
	return m
}

func (m nftMatch) SourceIPSet(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ip saddr @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) NotSourceIPSet(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ip saddr != @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) SourceIPPortSet(name string) generictables.MatchCriteria {
	m.removeProtocolMatch()
	m.clauses = append(m.clauses, fmt.Sprintf("ip saddr . %s sport @%s", m.proto, LegalizeSetName(name)))
	return m
}

func (m nftMatch) NotSourceIPPortSet(name string) generictables.MatchCriteria {
	m.removeProtocolMatch()
	m.clauses = append(m.clauses, fmt.Sprintf("ip saddr . %s sport != @%s", m.proto, LegalizeSetName(name)))
	return m
}

func (m nftMatch) DestIPSet(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ip daddr @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) NotDestIPSet(name string) generictables.MatchCriteria {
	m.clauses = append(m.clauses, fmt.Sprintf("ip daddr != @%s", LegalizeSetName(name)))
	return m
}

func (m nftMatch) DestIPPortSet(name string) generictables.MatchCriteria {
	m.removeProtocolMatch()
	m.clauses = append(m.clauses, fmt.Sprintf("ip daddr . %s dport @%s", m.proto, LegalizeSetName(name)))
	return m
}

func (m nftMatch) NotDestIPPortSet(name string) generictables.MatchCriteria {
	m.removeProtocolMatch()
	m.clauses = append(m.clauses, fmt.Sprintf("ip daddr . %s dport != @%s", m.proto, LegalizeSetName(name)))
	return m
}

func (m nftMatch) IPSetNames() (ipSetNames []string) {
	for _, matchString := range []string(m.clauses) {
		if strings.Contains(matchString, "ip saddr @") {
			ipSetNames = append(ipSetNames, strings.TrimPrefix(strings.Split(matchString, " ")[2], "@"))
		}
		if strings.Contains(matchString, "ip daddr @") {
			ipSetNames = append(ipSetNames, strings.TrimPrefix(strings.Split(matchString, " ")[2], "@"))
		}
		if strings.Contains(matchString, "ip saddr != @") {
			ipSetNames = append(ipSetNames, strings.TrimPrefix(strings.Split(matchString, " ")[3], "@"))
		}
		if strings.Contains(matchString, "ip daddr != @") {
			ipSetNames = append(ipSetNames, strings.TrimPrefix(strings.Split(matchString, " ")[3], "@"))
		}
	}
	return
}

func (m nftMatch) SourcePorts(ports ...uint16) generictables.MatchCriteria {
	m.removeProtocolMatch()
	portsString := PortsToMultiport(ports)
	logrus.WithField("clauses", m.clauses).WithField("ports", portsString).Warn("Adding source ports")
	m.clauses = append(m.clauses, fmt.Sprintf("%s sport %s", m.proto, portsString))
	return m
}

func (m nftMatch) NotSourcePorts(ports ...uint16) generictables.MatchCriteria {
	m.removeProtocolMatch()
	portsString := PortsToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s sport != %s", m.proto, portsString))
	return m
}

func (m nftMatch) DestPorts(ports ...uint16) generictables.MatchCriteria {
	m.removeProtocolMatch()
	m.clauses = append(m.clauses, fmt.Sprintf("%s dport %s", m.proto, PortsToMultiport(ports)))
	return m
}

func (m nftMatch) UDPDestPorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("udp dport %s", portsString))
	return m
}

func (m nftMatch) NotDestPorts(ports ...uint16) generictables.MatchCriteria {
	m.removeProtocolMatch()
	portsString := PortsToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s dport != %s", m.proto, portsString))
	return m
}

func (m nftMatch) SourcePortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	m.removeProtocolMatch()
	portsString := PortRangesToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s sport %s", m.proto, portsString))
	return m
}

func (m nftMatch) NotSourcePortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	m.removeProtocolMatch()
	portsString := PortRangesToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s sport != %s", m.proto, portsString))
	return m
}

func (m nftMatch) DestPortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	m.removeProtocolMatch()
	portsString := PortRangesToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s dport %s", m.proto, portsString))
	return m
}

func (m nftMatch) NotDestPortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	m.removeProtocolMatch()
	portsString := PortRangesToMultiport(ports)
	m.clauses = append(m.clauses, fmt.Sprintf("%s dport != %s", m.proto, portsString))
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

// removeProtocolMatch removes the "ip protocol" clause from the rule. This is necessary when specifying a port match,
// since port matches already include the protocol in the match string and nftables rejects specifying it twice.
func (m *nftMatch) removeProtocolMatch() {
	if m.proto == "" {
		logrus.Fatal("BUG: removeProtocolMatch called without a protocol match")
	}
	for i := range m.clauses {
		if strings.Contains(m.clauses[i], "ip protocol ") {
			m.clauses = append(m.clauses[:i], m.clauses[i+1:]...)
			return
		}
	}
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
