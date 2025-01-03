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

package iptables

import (
	"fmt"
	"math/bits"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/proto"
)

var Wildcard string = "+"

var _ generictables.MatchCriteria = matchCriteria{}

type matchCriteria []string

func Match() generictables.MatchCriteria {
	var m matchCriteria
	return m
}

func (m matchCriteria) Render() string {
	return strings.Join([]string(m), " ")
}

func (m matchCriteria) String() string {
	return fmt.Sprintf("MatchCriteria[%s]", m.Render())
}

func (m matchCriteria) MarkClear(mark uint32) generictables.MatchCriteria {
	if mark == 0 {
		log.Panic("Probably bug: zero mark")
	}
	return append(m, fmt.Sprintf("-m mark --mark 0/%#x", mark))
}

func (m matchCriteria) MarkNotClear(mark uint32) generictables.MatchCriteria {
	if mark == 0 {
		log.Panic("Probably bug: zero mark")
	}
	return append(m, fmt.Sprintf("-m mark ! --mark 0/%#x", mark))
}

func (m matchCriteria) MarkSingleBitSet(mark uint32) generictables.MatchCriteria {
	if bits.OnesCount32(mark) != 1 {
		// Disallow multi-bit matches to force user to think about the mask they should use.
		// For example, if you are storing a number in the mark then you likely want to match on its
		// 0-bits too
		log.WithField("mark", mark).Panic("MarkSingleBitSet() should only be used with a single mark bit")
	}
	return m.MarkMatchesWithMask(mark, mark)
}

func (m matchCriteria) MarkMatchesWithMask(mark, mask uint32) generictables.MatchCriteria {
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
	return append(m, fmt.Sprintf("-m mark --mark %#x/%#x", mark, mask))
}

func (m matchCriteria) NotMarkMatchesWithMask(mark, mask uint32) generictables.MatchCriteria {
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
	return append(m, fmt.Sprintf("-m mark ! --mark %#x/%#x", mark, mask))
}

func (m matchCriteria) InInterface(ifaceMatch string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("--in-interface %s", ifaceMatch))
}

func (m matchCriteria) OutInterface(ifaceMatch string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("--out-interface %s", ifaceMatch))
}

func (m matchCriteria) RPFCheckFailed() generictables.MatchCriteria {
	ret := append(m, "-m rpfilter --invert --validmark")
	return ret
}

func (m matchCriteria) IPVSConnection() generictables.MatchCriteria {
	return append(m, "-m ipvs --ipvs")
}

func (m matchCriteria) NotIPVSConnection() generictables.MatchCriteria {
	return append(m, "-m ipvs ! --ipvs")
}

func (m matchCriteria) NotSrcAddrType(addrType generictables.AddrType, limitIfaceOut bool) generictables.MatchCriteria {
	if limitIfaceOut {
		return append(m, fmt.Sprintf("-m addrtype ! --src-type %s --limit-iface-out", addrType))
	} else {
		return append(m, fmt.Sprintf("-m addrtype ! --src-type %s", addrType))
	}
}

func (m matchCriteria) SrcAddrType(addrType generictables.AddrType, limitIfaceOut bool) generictables.MatchCriteria {
	if limitIfaceOut {
		return append(m, fmt.Sprintf("-m addrtype --src-type %s --limit-iface-out", addrType))
	} else {
		return append(m, fmt.Sprintf("-m addrtype --src-type %s", addrType))
	}
}

func (m matchCriteria) DestAddrType(addrType generictables.AddrType) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m addrtype --dst-type %s", addrType))
}

func (m matchCriteria) NotDestAddrType(addrType generictables.AddrType) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m addrtype ! --dst-type %s", addrType))
}

func (m matchCriteria) ConntrackState(stateNames string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m conntrack --ctstate %s", stateNames))
}

func (m matchCriteria) NotConntrackState(stateNames string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m conntrack ! --ctstate %s", stateNames))
}

func (m matchCriteria) Protocol(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-p %s", name))
}

func (m matchCriteria) NotProtocol(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("! -p %s", name))
}

func (m matchCriteria) ProtocolNum(num uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-p %d", num))
}

func (m matchCriteria) NotProtocolNum(num uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("! -p %d", num))
}

func (m matchCriteria) SourceNet(net string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("--source %s", net))
}

func (m matchCriteria) NotSourceNet(net string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("! --source %s", net))
}

func (m matchCriteria) DestNet(net string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("--destination %s", net))
}

func (m matchCriteria) NotDestNet(net string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("! --destination %s", net))
}

func (m matchCriteria) SourceIPSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m set --match-set %s src", name))
}

func (m matchCriteria) NotSourceIPSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m set ! --match-set %s src", name))
}

func (m matchCriteria) SourceIPPortSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m set --match-set %s src,src", name))
}

func (m matchCriteria) NotSourceIPPortSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m set ! --match-set %s src,src", name))
}

func (m matchCriteria) DestIPSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m set --match-set %s dst", name))
}

func (m matchCriteria) NotDestIPSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m set ! --match-set %s dst", name))
}

func (m matchCriteria) DestIPPortSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m set --match-set %s dst,dst", name))
}

func (m matchCriteria) NotDestIPPortSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m set ! --match-set %s dst,dst", name))
}

func (m matchCriteria) IPSetNames() (ipSetNames []string) {
	for _, matchString := range []string(m) {
		words := strings.Split(matchString, " ")
		for i := range words {
			if words[i] == "--match-set" && (i+1) < len(words) {
				ipSetNames = append(ipSetNames, words[i+1])
			}
		}
	}
	return
}

func (m matchCriteria) SourcePorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	return append(m, fmt.Sprintf("-m multiport --source-ports %s", portsString))
}

func (m matchCriteria) NotSourcePorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	return append(m, fmt.Sprintf("-m multiport ! --source-ports %s", portsString))
}

func (m matchCriteria) DestPort(port uint16) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("--dport %v", port))
}

func (m matchCriteria) DestPorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	return append(m, fmt.Sprintf("-m multiport --destination-ports %s", portsString))
}

func (m matchCriteria) NotDestPorts(ports ...uint16) generictables.MatchCriteria {
	portsString := PortsToMultiport(ports)
	return append(m, fmt.Sprintf("-m multiport ! --destination-ports %s", portsString))
}

func (m matchCriteria) SourcePortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("-m multiport --source-ports %s", portsString))
}

func (m matchCriteria) NotSourcePortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("-m multiport ! --source-ports %s", portsString))
}

func (m matchCriteria) DestPortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("-m multiport --destination-ports %s", portsString))
}

func (m matchCriteria) NotDestPortRanges(ports []*proto.PortRange) generictables.MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("-m multiport ! --destination-ports %s", portsString))
}

func (m matchCriteria) ICMPType(t uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m icmp --icmp-type %d", t))
}

func (m matchCriteria) NotICMPType(t uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m icmp ! --icmp-type %d", t))
}

func (m matchCriteria) ICMPTypeAndCode(t, c uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m icmp --icmp-type %d/%d", t, c))
}

func (m matchCriteria) NotICMPTypeAndCode(t, c uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m icmp ! --icmp-type %d/%d", t, c))
}

func (m matchCriteria) ICMPV6Type(t uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m icmp6 --icmpv6-type %d", t))
}

func (m matchCriteria) NotICMPV6Type(t uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m icmp6 ! --icmpv6-type %d", t))
}

func (m matchCriteria) ICMPV6TypeAndCode(t, c uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m icmp6 --icmpv6-type %d/%d", t, c))
}

func (m matchCriteria) NotICMPV6TypeAndCode(t, c uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m icmp6 ! --icmpv6-type %d/%d", t, c))
}

func (m matchCriteria) InInterfaceVMAP(mapname string) generictables.MatchCriteria {
	log.Panic("InInterfaceVMAP not supported in iptables")
	return m
}

func (m matchCriteria) OutInterfaceVMAP(mapname string) generictables.MatchCriteria {
	log.Panic("OutInterfaceVMAP not supported in iptables")
	return m
}

func PortsToMultiport(ports []uint16) string {
	portFragments := make([]string, len(ports))
	for i, port := range ports {
		portFragments[i] = fmt.Sprintf("%d", port)
	}
	portsString := strings.Join(portFragments, ",")
	return portsString
}

func PortRangesToMultiport(ports []*proto.PortRange) string {
	portFragments := make([]string, len(ports))
	for i, port := range ports {
		if port.First == port.Last {
			portFragments[i] = fmt.Sprintf("%d", port.First)
		} else {
			portFragments[i] = fmt.Sprintf("%d:%d", port.First, port.Last)
		}
	}
	portsString := strings.Join(portFragments, ",")
	return portsString
}
