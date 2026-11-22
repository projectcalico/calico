// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

package nfnetlink

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// nflogAttrData is raw NFLOG netfilter attribute data (IPv6 TCP packet with
// prefix "DRI", src port 38525, dst port 8000).  This is the payload after
// the NfGenMsg header.
var nflogAttrData = []byte{8, 0, 1, 0, 134, 221, 3, 0, 8, 0, 10, 0, 68, 82, 73, 0, 8, 0, 5, 0, 0, 0, 0, 3, 8, 0, 11, 0, 0, 0, 3, 232, 8, 0, 14, 0, 0, 0, 3, 232, 84, 0, 9, 0, 96, 15, 33, 48, 0, 40, 6, 64, 254, 128, 0, 0, 0, 0, 0, 0, 10, 0, 39, 255, 254, 134, 38, 162, 254, 128, 0, 0, 0, 0, 0, 0, 10, 0, 39, 255, 254, 215, 241, 163, 150, 125, 31, 64, 121, 172, 141, 35, 0, 0, 0, 0, 160, 2, 112, 128, 118, 211, 0, 0, 2, 4, 5, 160, 4, 2, 8, 10, 2, 59, 176, 73, 0, 0, 0, 0, 1, 3, 3, 7}

// makeNflogMessage prepends a 4-byte NfGenMsg header (all zeros) to raw NFLOG
// attribute data, producing a complete message as seen by parseAndAggregateFlowLogs.
func makeNflogMessage() []byte {
	header := []byte{0, 0, 0, 0} // NfGenMsg: family=0, version=0, resId=0
	msg := make([]byte, 0, len(header)+len(nflogAttrData))
	msg = append(msg, header...)
	msg = append(msg, nflogAttrData...)
	return msg
}

var _ = Describe("ParseNflog", func() {
	Describe("Ipv6", func() {
		It("should parse NFLOG packet with IPv6 payload without errors", func() {
			nflogPacket, err := parseNflog(nflogAttrData)
			Expect(err).To(BeNil())
			prefix := string(nflogPacket.Prefix.Prefix[:nflogPacket.Prefix.Len])
			Expect(prefix).To(Equal("DRI"))
			tuple := nflogPacket.Tuple
			Expect(net.IP(tuple.Src[:16]).String()).To(Equal("fe80::a00:27ff:fe86:26a2"))
			Expect(net.IP(tuple.Dst[:16]).String()).To(Equal("fe80::a00:27ff:fed7:f1a3"))
			// TCP
			Expect(tuple.Proto).To(Equal(6))
			// Dst port 8000
			Expect(tuple.L4Src.Port).To(Equal(38525))
			Expect(tuple.L4Dst.Port).To(Equal(8000))
		})
	})
})

var _ = Describe("parseAndAggregateFlowLogs", func() {
	It("should aggregate packets and flush on ticker", func() {
		resChan := make(chan [][]byte, 10)
		ch := make(chan map[NflogPacketTuple]*NflogPacketAggregate, 10)

		parseAndAggregateFlowLogs(0, resChan, ch)

		// Send 3 identical packets as a single batch (as the reader goroutine would).
		msg := makeNflogMessage()
		resChan <- [][]byte{msg, msg, msg}

		// Wait for ticker flush (generous timeout for CI).
		var aggregate map[NflogPacketTuple]*NflogPacketAggregate
		Eventually(ch, "1s").Should(Receive(&aggregate))

		// Should have exactly 1 tuple with the packet count summed to 3.
		Expect(aggregate).To(HaveLen(1))
		for _, agg := range aggregate {
			Expect(agg.Prefixes).To(HaveLen(1))
			Expect(agg.Prefixes[0].Packets).To(Equal(3))
		}

		// Close input; output channel should eventually close.
		close(resChan)
		Eventually(ch, "1s").Should(BeClosed())
	})

	It("should flush remaining data when input channel closes", func() {
		resChan := make(chan [][]byte, 10)
		ch := make(chan map[NflogPacketTuple]*NflogPacketAggregate, 10)

		parseAndAggregateFlowLogs(0, resChan, ch)

		// Send packets and immediately close before ticker fires.
		msg := makeNflogMessage()
		resChan <- [][]byte{msg, msg}
		close(resChan)

		// The final flush should deliver the data even without a ticker fire.
		var aggregate map[NflogPacketTuple]*NflogPacketAggregate
		Eventually(ch, "1s").Should(Receive(&aggregate))
		Expect(aggregate).To(HaveLen(1))
		for _, agg := range aggregate {
			Expect(agg.Prefixes).To(HaveLen(1))
			Expect(agg.Prefixes[0].Packets).To(Equal(2))
		}

		// Output channel should be closed.
		Eventually(ch, "1s").Should(BeClosed())
	})

	It("should close output channel when input closes with no data", func() {
		resChan := make(chan [][]byte, 10)
		ch := make(chan map[NflogPacketTuple]*NflogPacketAggregate, 10)

		parseAndAggregateFlowLogs(0, resChan, ch)

		close(resChan)

		// Output channel should close without sending any data.
		Eventually(ch, "1s").Should(BeClosed())
	})
})

var _ = Describe("Parse ICMPv6 packet header", func() {
	It("should read the type, code and echo identifier", func() {
		payload := make([]byte, 48)
		payload[0] = 0x60 // IPv6
		payload[6] = ProtoIcmpv6
		copy(payload[8:24], net.ParseIP("fd00::1"))
		copy(payload[24:40], net.ParseIP("fd00::2"))
		payload[40] = 129 // echo reply
		payload[41] = 0
		payload[44], payload[45] = 0x04, 0xd2

		var tuple NflogPacketTuple
		parsePacketHeader(&tuple, IPv6Proto, payload)
		Expect(tuple.Proto).To(Equal(58))
		Expect(net.IP(tuple.Src[:]).String()).To(Equal("fd00::1"))
		Expect(tuple.L4Src.Id).To(Equal(1234))
		Expect(tuple.L4Dst.Type).To(Equal(129))
		Expect(tuple.L4Dst.Code).To(Equal(0))
	})
})

var _ = Describe("Parse truncated packet headers", func() {
	// truncated builds an IP packet whose transport header stops after four bytes, the shape of a
	// packet conntrack marks invalid, which reaches the logging rules when Felix is configured not
	// to drop invalid packets.
	truncated := func(hwProtocol, ipProto int) []byte {
		if hwProtocol == IPv6Proto {
			payload := make([]byte, 44)
			payload[0] = 0x60
			payload[6] = byte(ipProto)
			copy(payload[8:24], net.ParseIP("fd00::1"))
			copy(payload[24:40], net.ParseIP("fd00::2"))
			copy(payload[40:], []byte{128, 0, 0, 0})
			return payload
		}
		payload := make([]byte, 24)
		payload[0] = 0x45
		payload[9] = byte(ipProto)
		copy(payload[12:16], net.ParseIP("10.0.0.1").To4())
		copy(payload[16:20], net.ParseIP("10.0.0.2").To4())
		copy(payload[20:], []byte{8, 0, 0, 0})
		return payload
	}

	DescribeTable("should keep the addresses and leave the transport fields empty",
		func(hwProtocol, ipProto int) {
			var tuple NflogPacketTuple
			Expect(func() { parsePacketHeader(&tuple, hwProtocol, truncated(hwProtocol, ipProto)) }).NotTo(Panic())
			Expect(tuple.Proto).To(Equal(ipProto))
			Expect(tuple.Src).NotTo(Equal([16]byte{}))
			Expect(tuple.L4Src).To(Equal(NflogL4Info{}))
			Expect(tuple.L4Dst).To(Equal(NflogL4Info{}))
		},
		Entry("ICMPv6", IPv6Proto, ProtoIcmpv6),
		Entry("ICMP", IPv4Proto, ProtoIcmp),
		Entry("TCP", IPv4Proto, ProtoTcp),
		Entry("UDP over IPv6", IPv6Proto, ProtoUdp),
	)
})
