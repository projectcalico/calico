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
	"fmt"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"
)

func TestTCPReset(t *testing.T) {
	RegisterTestingT(t)
	cleanUpMaps()
	defer cleanUpMaps()

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        false,
		Seq:        1000,
		DataOffset: 5,
	}

	_, ipv4, l4, _, pktBytes, err := testPacketV4(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())
	tcp, ok := l4.(*layers.TCP)
	Expect(ok).To(BeTrue())
	runBpfUnitTest(t, "tcp_rst.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(0))

		Expect(res.dataOut).To(HaveLen(54)) // eth + ip (60) + tcp(20)

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkTcpRst(pktR, ipv4, tcp, false)
	})
}

func TestTCPResetIPv6(t *testing.T) {
	RegisterTestingT(t)
	cleanUpMaps()
	defer cleanUpMaps()

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        false,
		Seq:        1000,
		DataOffset: 5,
	}

	_, ipv6, l4, _, pktBytes, err := testPacketV6(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())
	tcp, ok := l4.(*layers.TCP)
	Expect(ok).To(BeTrue())
	runBpfUnitTest(t, "tcp_rst.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(0))

		Expect(res.dataOut).To(HaveLen(74)) // eth + ip (60) + tcp(20)

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R, ok := ipv6L.(*layers.IPv6)
		Expect(ok).To(BeTrue())
		Expect(ipv6R.NextHeader).To(Equal(layers.IPProtocolTCP))
		Expect(ipv6R.SrcIP).To(Equal(ipv6.DstIP))
		Expect(ipv6R.DstIP).To(Equal(ipv6.SrcIP))

		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())
		tcpR, ok := tcpL.(*layers.TCP)
		Expect(ok).To(BeTrue())
		Expect(tcpR.RST).To(BeTrue())
		Expect(tcpR.SrcPort).To(Equal(tcp.DstPort))
		Expect(tcpR.DstPort).To(Equal(tcp.SrcPort))
		Expect(tcpR.Seq).To(Equal(uint32(0)))
	}, withIPv6())

}

func checkTcpRst(pktR gopacket.Packet, ipv4 *layers.IPv4, tcp *layers.TCP, ack bool) {
	ipv4L := pktR.Layer(layers.LayerTypeIPv4)
	Expect(ipv4L).NotTo(BeNil())
	ipv4R, ok := ipv4L.(*layers.IPv4)
	Expect(ok).To(BeTrue())
	Expect(ipv4R.SrcIP).To(Equal(ipv4.DstIP))
	Expect(ipv4R.DstIP).To(Equal(ipv4.SrcIP))
	Expect(ipv4R.Protocol).To(Equal(layers.IPProtocolTCP))
	Expect(ipv4R.TTL).To(Equal(uint8(64)))

	tcpL := pktR.Layer(layers.LayerTypeTCP)
	Expect(tcpL).NotTo(BeNil())
	tcpR, ok := tcpL.(*layers.TCP)
	Expect(ok).To(BeTrue())
	Expect(tcpR.RST).To(BeTrue())
	Expect(tcpR.SrcPort).To(Equal(tcp.DstPort))
	Expect(tcpR.DstPort).To(Equal(tcp.SrcPort))
	Expect(tcpR.Seq).To(Equal(uint32(0)))
}
