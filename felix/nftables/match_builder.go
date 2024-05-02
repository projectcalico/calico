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
type nftMatch []string

func Match() generictables.MatchCriteria {
	return new(nftMatch)
}

func (m nftMatch) Render() string {
	return strings.Join([]string(m), " ")
}

func (m nftMatch) String() string {
	return fmt.Sprintf("MatchCriteria[%s]", m.Render())
}

func (m nftMatch) MarkClear(mark uint32) generictables.MatchCriteria {
	if mark == 0 {
		log.Panic("Probably bug: zero mark")
	}
	return append(m, fmt.Sprintf("meta mark & %#x == 0", mark))
}

func (m nftMatch) MarkNotClear(mark uint32) generictables.MatchCriteria {
	if mark == 0 {
		log.Panic("Probably bug: zero mark")
	}
	return append(m, fmt.Sprintf("meta mark & %#x != 0", mark))
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
	return append(m, fmt.Sprintf("meta mark & %#x == %#x", mask, mark))
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
	return append(m, fmt.Sprintf("meta mark & %#x != %#x", mask, mark))
}

func (m nftMatch) InInterface(ifaceMatch string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("iifname %s", ifaceMatch))
}

func (m nftMatch) OutInterface(ifaceMatch string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("oifname %s", ifaceMatch))
}

func (m nftMatch) RPFCheckPassed(acceptLocal bool) generictables.MatchCriteria {
	// TODO: acceptLocal is not supported in nftables mode.
	return append(m, "fib saddr . mark . iif oif != 0")
}

func (m nftMatch) RPFCheckFailed(acceptLocal bool) generictables.MatchCriteria {
	// TODO: acceptLocal is not supported in nftables mode.
	// https://wiki.nftables.org/wiki-nftables/index.php/Matching_routing_information
	return append(m, "fib saddr . mark . iif oif 0")
}

func (m nftMatch) IPVSConnection() generictables.MatchCriteria {
	panic("IPVS not supported in nftables mode")
}

func (m nftMatch) NotIPVSConnection() generictables.MatchCriteria {
	panic("IPVS not supported in nftables mode")
}

func (m nftMatch) NotSrcAddrType(addrType generictables.AddrType, limitIfaceOut bool) generictables.MatchCriteria {
	if limitIfaceOut {
		return append(m, fmt.Sprintf("fib saddr . oif type != %s", strings.ToLower(string(addrType))))
	} else {
		return append(m, fmt.Sprintf("fib saddr type != %s", strings.ToLower(string(addrType))))
	}
}

func (m nftMatch) SrcAddrType(addrType generictables.AddrType, limitIfaceOut bool) generictables.MatchCriteria {
	if limitIfaceOut {
		return append(m, fmt.Sprintf("fib saddr . oif type %s", strings.ToLower(string(addrType))))
	} else {
		return append(m, fmt.Sprintf("fib saddr type %s", strings.ToLower(string(addrType))))
	}
}

func (m nftMatch) DestAddrType(addrType generictables.AddrType) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("fib daddr type %s", strings.ToLower(string(addrType))))
}

func (m nftMatch) NotDestAddrType(addrType generictables.AddrType) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("fib daddr type != %s", strings.ToLower(string(addrType))))
}

func (m nftMatch) ConntrackStatus(statusNames string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ct status %s", strings.ToLower(statusNames)))
}

func (m nftMatch) NotConntrackStatus(statusNames string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ct status != %s", strings.ToLower(statusNames)))
}

func (m nftMatch) ConntrackState(stateNames string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ct state %s", strings.ToLower(stateNames)))
}

func (m nftMatch) NotConntrackState(stateNames string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ct state != %s", strings.ToLower(stateNames)))
}

func (m nftMatch) Protocol(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip protocol %s", name))
}

func (m nftMatch) NotProtocol(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip protocol != %s", name))
}

func (m nftMatch) ProtocolNum(num uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip protocol %d", num))
}

func (m nftMatch) NotProtocolNum(num uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip protocol != %d", num))
}

func (m nftMatch) SourceNet(net string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip saddr %s", net))
}

func (m nftMatch) NotSourceNet(net string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip saddr != %s", net))
}

func (m nftMatch) DestNet(net string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip daddr %s", net))
}

func (m nftMatch) NotDestNet(net string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip daddr != %s", net))
}

func (m nftMatch) SourceIPSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip saddr @%s", CanonicalizeSetName(name)))
}

func (m nftMatch) NotSourceIPSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip saddr != @%s", CanonicalizeSetName(name)))
}

func (m nftMatch) SourceIPPortSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip saddr @%s tcp sport @%s", name, name))
}

func (m nftMatch) NotSourceIPPortSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip saddr != @%s tcp sport != @%s", name, name))
}

func (m nftMatch) DestIPSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip daddr @%s", CanonicalizeSetName(name)))
}

func (m nftMatch) NotDestIPSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip daddr != @%s", CanonicalizeSetName(name)))
}

func (m nftMatch) DestIPPortSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip daddr @%s tcp dport @%s", name, name))
}

func (m nftMatch) NotDestIPPortSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("ip daddr != @%s tcp dport != @%s", name, name))
}

func (m nftMatch) IPSetNames() (ipSetNames []string) {
	for _, matchString := range []string(m) {
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
	portsString := PortsToMultiport(ports)
	return append(m, fmt.Sprintf("tcp sport %s", portsString))
}

func (m nftMatch) NotSourcePorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	return append(m, fmt.Sprintf("tcp sport != %s", portsString))
}

func (m nftMatch) DestPorts(ports ...uint16) generictables.MatchCriteria {
	// Matches on port require a protocol be specified. The MatchCritieria interface exposes these
	// as two separate functions, but the underlying nftables rule syntax varies based on whether or not a port was specified,
	// and what type of match is being made. Extract the protocol and use it to build the port match.
	var protocol string
	for i := range m {
		if strings.Contains(m[i], "ip protocol !=") {
			// Protocol not match is not yet supported.
			logrus.WithField("match", m[i]).Fatal("Not protocol match on ports is not supported")
		} else if strings.Contains(m[i], "ip protocol ") {
			protocol = strings.Split(m[i], " ")[2]

			// Remove the protocol match, and instead include it in the port match. This is because
			// port match includes the protocol in the match string.
			m[i] = fmt.Sprintf("%s dport %s", protocol, PortsToMultiport(ports))
			return m
		}
	}
	logrus.Fatal("Protocol not found in match string, but is required for port match")
	return nil
}

func (m nftMatch) UDPDestPorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	return append(m, fmt.Sprintf("udp dport %s", portsString))
}

func (m nftMatch) NotDestPorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	return append(m, fmt.Sprintf("tcp dport != %s", portsString))
}

func (m nftMatch) SourcePortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("tcp sport %s", portsString))
}

func (m nftMatch) NotSourcePortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("tcp sport != %s", portsString))
}

func (m nftMatch) DestPortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	// Matches on port require a protocol be specified. The MatchCritieria interface exposes these
	// as two separate functions, but the underlying nftables rule syntax varies based on whether or not a port was specified,
	// and what type of match is being made. Extract the protocol and use it to build the port match.
	var protocol string
	for i := range m {
		if strings.Contains(m[i], "ip protocol !=") {
			// Protocol not match is not yet supported.
			logrus.WithField("match", m[i]).Fatal("Not protocol match on port ranges is not supported")
		} else if strings.Contains(m[i], "ip protocol ") {
			protocol = strings.Split(m[i], " ")[2]

			// Remove the protocol match, and instead include it in the port match. This is because
			// port match includes the protocol in the match string.
			m[i] = fmt.Sprintf("%s dport %s", protocol, PortRangesToMultiport(ports))
			return m
		}
	}
	logrus.Fatal("Protocol not found in match string, but is required for port ranges match")
	return nil
}

func (m nftMatch) NotDestPortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("tcp dport != %s", portsString))
}

func (m nftMatch) ICMPType(t uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("icmp type %d", t))
}

func (m nftMatch) NotICMPType(t uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("icmp type != %d", t))
}

func (m nftMatch) ICMPTypeAndCode(t, c uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("icmp type %d code %d", t, c))
}

func (m nftMatch) NotICMPTypeAndCode(t, c uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("icmp type !=%d code !=%d", t, c))
}

func (m nftMatch) ICMPV6Type(t uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("icmp type %d", t))
}

func (m nftMatch) NotICMPV6Type(t uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("icmp type != %d", t))
}

func (m nftMatch) ICMPV6TypeAndCode(t, c uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("icmp type %d code %d", t, c))
}

func (m nftMatch) NotICMPV6TypeAndCode(t, c uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("icmp type != %d code != %d", t, c))
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
