// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/bpf/routes"
	"github.com/projectcalico/felix/proto"
)

var rulesAllowUDP = [][][]*proto.Rule{{{{
	Action:   "Allow",
	Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "udp"}},
}}}}

func TestICMPRelatedPlain(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	icmpUNreachable := makeICMPError(ipv4, udp, 3 /* Unreachable */, 1 /*Host unreachable error */)

	runBpfTest(t, "calico_to_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpUNreachable)
		Expect(err).NotTo(HaveOccurred())
		// there is no normal CT record yet, must be denied
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	runBpfTest(t, "calico_from_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	runBpfTest(t, "calico_to_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpUNreachable)
		Expect(err).NotTo(HaveOccurred())
		// we have a normal ct record, it is related, must be allowed
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	// fake icmp echo reply, we do not really care about the payload, just the type and code
	icmpEchoResp := makeICMPError(ipv4, udp, 0 /* Echo reply */, 0)

	runBpfTest(t, "calico_to_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpEchoResp)
		Expect(err).NotTo(HaveOccurred())
		// echo is unrelated, must be denied
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})
}

func makeICMPError(ipInner *layers.IPv4, l4 gopacket.SerializableLayer, icmpType, icmpCode uint8) []byte {
	payloadBuf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(payloadBuf, gopacket.SerializeOptions{}, ipInner, l4)
	Expect(err).NotTo(HaveOccurred())
	payload := payloadBuf.Bytes()

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0xee, 0, 0, 0, 0, 1},
		DstMAC:       []byte{0xfe, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    net.IPv4(11, 22, 33, 44),
		DstIP:    ipInner.SrcIP,
		Protocol: layers.IPProtocolICMPv4,
		Length:   uint16(20 + len(payload)),
	}

	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(icmpType, icmpCode),
	}

	pkt := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
		eth, ipv4, icmp, gopacket.Payload(payload))
	Expect(err).NotTo(HaveOccurred())

	return pkt.Bytes()
}
