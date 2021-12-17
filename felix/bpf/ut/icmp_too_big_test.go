// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/netstack/tcpip/header"
	. "github.com/onsi/gomega"
)

func TestICMPTooBig(t *testing.T) {
	RegisterTestingT(t)

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	runBpfUnitTest(t, "icmp_too_big.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(0))

		Expect(res.dataOut).To(HaveLen(134)) // eth + ip + 64 + udp + ip + icmp

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPTooBig(pktR, ipv4, udp, natTunnelMTU)
	})
}

func TestICMPTooBigIPOptions(t *testing.T) {
	RegisterTestingT(t)
	ipv4 := &layers.IPv4{
		Version:  4,
		IHL:      6,
		SrcIP:    net.IPv4(1, 1, 1, 1),
		DstIP:    net.IPv4(2, 2, 2, 2),
		Protocol: layers.IPProtocolUDP,
		Options:  []layers.IPv4Option{{OptionType: 1, OptionLength: 0, OptionData: []byte{0, 0}}},
	}

	_, _, _, _, pktBytes, err := testPacket(nil, ipv4, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	runBpfUnitTest(t, "icmp_too_big.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(0xffffffff))
	})
}

func checkICMPTooBig(pktR gopacket.Packet, ipv4 *layers.IPv4, udp *layers.UDP, expMTU uint16) {
	ipv4L := pktR.Layer(layers.LayerTypeIPv4)
	Expect(ipv4L).NotTo(BeNil())
	ipv4R := ipv4L.(*layers.IPv4)

	Expect(ipv4R.Protocol).To(Equal(layers.IPProtocolICMPv4))
	Expect(ipv4R.SrcIP.String()).To(Equal(intfIP.String()))
	Expect(ipv4R.DstIP).To(Equal(ipv4.SrcIP))

	icmpL := pktR.Layer(layers.LayerTypeICMPv4)
	Expect(ipv4L).NotTo(BeNil())
	icmpR := icmpL.(*layers.ICMPv4)

	ipv4CSum := ipv4R.Checksum

	iptmp := gopacket.NewSerializeBuffer()
	err := ipv4R.SerializeTo(iptmp, gopacket.SerializeOptions{ComputeChecksums: true}) // recompute csum
	Expect(err).NotTo(HaveOccurred())
	Expect(ipv4CSum).To(Equal(ipv4R.Checksum))

	Expect(icmpR.TypeCode).To(Equal(
		layers.CreateICMPv4TypeCode(
			layers.ICMPv4TypeDestinationUnreachable,
			layers.ICMPv4CodeFragmentationNeeded,
		)))

	data := icmpR.Contents[4:]
	mtu := binary.BigEndian.Uint16(data[2:4])
	Expect(mtu).To(Equal(expMTU))

	/* calculate ICMP csum by hand since gopacket on CSums the header */
	toCSum := make([]byte, len(icmpR.Contents)+len(icmpR.Payload))
	copy(toCSum, icmpR.Contents)
	copy(toCSum[8:], icmpR.Payload)
	toCSum[2] = 0
	toCSum[3] = 0
	fmt.Printf("toCSum = %+v\n", toCSum)

	icmpCSum := header.Checksum(toCSum, 0)
	Expect(icmpR.Checksum).To(Equal(uint16(0xffff - icmpCSum)))

	icmpData := gopacket.NewPacket(icmpR.Payload, layers.LayerTypeIPv4, gopacket.Default)
	Expect(icmpData.Layer(layers.LayerTypeIPv4)).To(layersMatchFields(ipv4))
	// the extra 8 bytes will contain the entire UDP header
	Expect(icmpData.Layer(layers.LayerTypeUDP)).To(layersMatchFields(udp))
}
