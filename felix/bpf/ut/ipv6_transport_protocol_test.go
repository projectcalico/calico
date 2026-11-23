// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package ut_test

import (
	"encoding/binary"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/proto"
)

// Policy matches on the protocol the IPv6 parser reads, so these run real packets through the
// whole program rather than building the parsed state by hand. The first transport word is
// chosen so that, read as an extension header, it would name UDP (0x11) or "no next header"
// (0x3b).
func TestIPv6TransportProtocolPolicy(t *testing.T) {
	RegisterTestingT(t)
	defer resetBPFMaps()

	err := rtMapV6.Update(routes.NewKeyV6(srcV6CIDR).AsBytes(),
		routes.NewValueV6WithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes())
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMapV6(rtMapV6)

	name := func(n string) *proto.Protocol { return &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: n}} }
	num := func(n int32) *proto.Protocol { return &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: n}} }

	udpLite := layers.IPProtocolUDPLite
	sctp := layers.IPProtocolSCTP
	vrrp := layers.IPProtocol(112)
	ipv4InIPv6 := layers.IPProtocolIPv4

	for _, tc := range []struct {
		desc      string
		proto     layers.IPProtocol
		firstWord uint16
		hopByHop  bool
		rule      *proto.Rule
		allowed   bool
	}{
		{"UDPLite, allow udplite", udpLite, 12345, false, &proto.Rule{Action: "Allow", Protocol: name("udplite")}, true},
		{"UDPLite, allow 136", udpLite, 12345, false, &proto.Rule{Action: "Allow", Protocol: num(136)}, true},
		{"UDPLite, allow not udplite", udpLite, 12345, false, &proto.Rule{Action: "Allow", NotProtocol: name("udplite")}, false},
		{"UDPLite, allow icmpv6", udpLite, 12345, false, &proto.Rule{Action: "Allow", Protocol: name("icmpv6")}, false},
		{"UDPLite after hop-by-hop, allow udplite", udpLite, 12345, true, &proto.Rule{Action: "Allow", Protocol: name("udplite")}, true},
		{"UDPLite looking like no next header, allow udplite", udpLite, 0x3b00, false, &proto.Rule{Action: "Allow", Protocol: name("udplite")}, true},
		{"UDPLite looking like UDP, allow udp", udpLite, 0x1100, false, &proto.Rule{Action: "Allow", Protocol: name("udp")}, false},
		{"SCTP, allow sctp", sctp, 12345, false, &proto.Rule{Action: "Allow", Protocol: name("sctp")}, true},
		{"SCTP, allow icmpv6", sctp, 12345, false, &proto.Rule{Action: "Allow", Protocol: name("icmpv6")}, false},
		{"VRRP, allow 112", vrrp, 0x3101, false, &proto.Rule{Action: "Allow", Protocol: num(112)}, true},
		{"IPv4 in IPv6, allow 4", ipv4InIPv6, 0x4500, false, &proto.Rule{Action: "Allow", Protocol: num(4)}, true},
		{"UDP after hop-by-hop, allow udp", layers.IPProtocolUDP, 12345, true, &proto.Rule{Action: "Allow", Protocol: name("udp")}, true},
	} {
		resetCTMapV6(ctMapV6)
		skbMark = 0
		rules := makeRulesSingleTier([]*proto.Rule{tc.rule})
		pktBytes := ipv6PacketWithTransport(tc.proto, tc.firstWord, tc.hopByHop)

		runBpfTest(t, "calico_from_workload_ep", &rules, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			if tc.allowed {
				Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT), tc.desc)
			} else {
				Expect(res.Retval).To(Equal(resTC_ACT_SHOT), tc.desc)
			}
		}, withIPv6(), withDescription(tc.desc))
	}
}

func ipv6PacketWithTransport(ipProto layers.IPProtocol, firstWord uint16, hopByHop bool) []byte {
	l4 := make([]byte, 8)
	binary.BigEndian.PutUint16(l4[0:2], firstWord)
	binary.BigEndian.PutUint16(l4[2:4], 5678)
	payload := append(l4, []byte("ABCDEABCDEXXXXXXXXXXXX")...)

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
		DstMAC:       []byte{0, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip := &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: srcIPv6, DstIP: dstIPv6, NextHeader: ipProto}
	ls := []gopacket.SerializableLayer{eth, ip}
	if hopByHop {
		hop := &layers.IPv6HopByHop{}
		hop.NextHeader = ipProto
		hop.Options = append(hop.Options, &layers.IPv6HopByHopOption{OptionType: 0x01, OptionData: []byte{0, 0, 0, 0}})
		ip.NextHeader = layers.IPProtocolIPv6HopByHop
		ls = append(ls, hop)
	}
	ls = append(ls, gopacket.Payload(payload))

	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ls...)
	Expect(err).NotTo(HaveOccurred())
	return buf.Bytes()
}
