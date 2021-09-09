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
	"fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"
)

func TestNatEncap(t *testing.T) {
	RegisterTestingT(t)

	_, ipv4, l4, payload, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	var encapedPkt []byte

	runBpfUnitTest(t, "nat_encap_test.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(0))

		Expect(res.dataOut).To(HaveLen(len(pktBytes) + 50))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkVxlanEncap(pktR, true, ipv4, udp, payload)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R).To(layersMatchFields(ipv4, "Length", "SrcIP", "Checksum"))

		encapedPkt = res.dataOut
	})

	runBpfUnitTest(t, "nat_decap_test.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(0))

		// adjust the now decremented TTL
		res.dataOut[14+8]++
		// and zero ip csums in both as they must differ now
		res.dataOut[14+8+1+1] = 0
		res.dataOut[14+8+1+2] = 0
		pktBytes[14+8+1+1] = 0
		pktBytes[14+8+1+2] = 0
		Expect(res.dataOut).To(Equal(pktBytes))
	})
}

func checkVxlanEncap(pktR gopacket.Packet, NATed bool, ipv4 *layers.IPv4,
	transport gopacket.Layer, payload []byte) {

	inner := checkVxlan(pktR)
	checkInnerIP(inner, NATed, ipv4, transport, payload)
}

func checkVxlan(pktR gopacket.Packet) gopacket.Packet {
	ipv4L := pktR.Layer(layers.LayerTypeIPv4)
	Expect(ipv4L).NotTo(BeNil())
	ipv4R := ipv4L.(*layers.IPv4)

	ipv4CSum := ipv4R.Checksum
	iptmp := gopacket.NewSerializeBuffer()
	err := ipv4R.SerializeTo(iptmp, gopacket.SerializeOptions{ComputeChecksums: true}) // recompute csum
	Expect(err).NotTo(HaveOccurred())
	Expect(ipv4CSum).To(Equal(ipv4R.Checksum))

	udpL := pktR.Layer(layers.LayerTypeUDP)
	Expect(udpL).NotTo(BeNil())
	udpR := udpL.(*layers.UDP)
	Expect(udpR.SrcPort).To(Equal(layers.UDPPort(testVxlanPort)))
	Expect(udpR.DstPort).To(Equal(layers.UDPPort(testVxlanPort)))
	Expect(udpR.Checksum).To(Equal(uint16(0)))

	payloadL := pktR.ApplicationLayer()
	Expect(payloadL).NotTo(BeNil())
	vxlanL := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeVXLAN, gopacket.Default)
	Expect(vxlanL).NotTo(BeNil())
	fmt.Printf("vxlanL = %+v\n", vxlanL)
	Expect(vxlanL.Layer(layers.LayerTypeVXLAN)).
		To(layersMatchFields(&layers.VXLAN{ValidIDFlag: true, VNI: 0xca11c0}))

	ethL := vxlanL.Layer(layers.LayerTypeEthernet)
	Expect(ethL).NotTo(BeNil())
	Expect(ethL).To(layersMatchFields(
		&layers.Ethernet{
			SrcMAC:       []byte{0, 0, 0, 0, 0, 0},
			DstMAC:       []byte{0, 0, 0, 0, 0, 0},
			EthernetType: layers.EthernetTypeIPv4,
		}))

	return gopacket.NewPacket(ethL.LayerPayload(), layers.LayerTypeIPv4, gopacket.Default)
}

func encapedResponse(pktR gopacket.Packet) []byte {
	ethL := pktR.Layer(layers.LayerTypeEthernet)
	Expect(ethL).NotTo(BeNil())
	ethR := ethL.(*layers.Ethernet)

	ipv4L := pktR.Layer(layers.LayerTypeIPv4)
	Expect(ipv4L).NotTo(BeNil())
	ipv4R := ipv4L.(*layers.IPv4)

	ipv4R.SrcIP, ipv4R.DstIP = ipv4R.DstIP, ipv4R.SrcIP

	udpL := pktR.Layer(layers.LayerTypeUDP)
	Expect(udpL).NotTo(BeNil())
	udpR := udpL.(*layers.UDP)
	udpR.Checksum = 0

	payloadL := pktR.ApplicationLayer()
	Expect(payloadL).NotTo(BeNil())
	vxlanP := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeVXLAN, gopacket.Default)
	Expect(vxlanP).NotTo(BeNil())
	vxlanL := vxlanP.Layer(layers.LayerTypeVXLAN)
	Expect(vxlanL).NotTo(BeNil())
	vxlanR := vxlanL.(*layers.VXLAN)

	inner := gopacket.NewPacket(vxlanR.LayerPayload(), layers.LayerTypeEthernet, gopacket.Default)
	resp := udpResponseRaw(inner.Data())

	pkt := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: false},
		ethR, ipv4R, udpR, vxlanR, gopacket.Payload(resp))
	Expect(err).NotTo(HaveOccurred())

	return pkt.Bytes()
}

func getVxlanVNI(pktR gopacket.Packet) uint32 {
	ipv4L := pktR.Layer(layers.LayerTypeIPv4)
	Expect(ipv4L).NotTo(BeNil())

	udpL := pktR.Layer(layers.LayerTypeUDP)
	Expect(udpL).NotTo(BeNil())
	udpR := udpL.(*layers.UDP)
	Expect(udpR.SrcPort).To(Equal(layers.UDPPort(testVxlanPort)))
	Expect(udpR.DstPort).To(Equal(layers.UDPPort(testVxlanPort)))
	Expect(udpR.Checksum).To(Equal(uint16(0)))

	payloadL := pktR.ApplicationLayer()
	Expect(payloadL).NotTo(BeNil())
	vxlan := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeVXLAN, gopacket.Default)
	Expect(vxlan).NotTo(BeNil())

	vxlanL := vxlan.Layer(layers.LayerTypeVXLAN)
	Expect(vxlanL).NotTo(BeNil())

	return vxlanL.(*layers.VXLAN).VNI
}

func checkInnerIP(ip gopacket.Packet, NATed bool, ipv4 *layers.IPv4,
	transport gopacket.Layer, payload []byte) {
	ipv4L := ip.Layer(layers.LayerTypeIPv4)
	Expect(ipv4L).NotTo(BeNil())
	if NATed {
		Expect(ipv4L).To(layersMatchFields(ipv4, "Checksum", "TTL"))
	} else {
		Expect(ipv4L).To(layersMatchFields(ipv4, "DstIP", "Checksum", "TTL"))
	}

	Expect(ipv4L.(*layers.IPv4).TTL).To(Equal(ipv4.TTL - 1))

	transportL := ip.Layer(transport.LayerType())
	Expect(transportL).NotTo(BeNil())
	if NATed {
		Expect(transportL).To(layersMatchFields(transport))
	} else {
		Expect(transportL).To(layersMatchFields(transport, "DstPort", "Checksum"))
	}

	p := ip.ApplicationLayer()
	Expect(p).NotTo(BeNil())
	Expect(payload).To(Equal(p.Payload()))
}
