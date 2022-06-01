// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
)

var rulesAllowUDP = &polprog.Rules{
	Tiers: []polprog.Tier{{
		Name: "base tier",
		Policies: []polprog.Policy{{
			Name: "allow all udp",
			Rules: []polprog.Rule{{Rule: &proto.Rule{
				Action:   "Allow",
				Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "udp"}},
			}}},
		}},
	}},
}

func TestICMPRelatedPlain(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	icmpUNreachable := makeICMPError(ipv4, udp, 3 /* Unreachable */, 1 /*Host unreachable error */)

	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpUNreachable)
		Expect(err).NotTo(HaveOccurred())
		// there is no normal CT record yet, must be denied
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})
	expectMark(tcdefs.MarkSeen)

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

func TestICMPRelatedNATPodPod(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0, 1, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		err := natMap.Delete(nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}()

	natIP := net.IPv4(8, 8, 8, 8)
	natPort := uint16(666)

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		err := natBEMap.Delete(nat.NewNATBackendKey(0, 0).AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}()

	var natPkt gopacket.Packet

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		natPkt = gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
	})
	expectMark(tcdefs.MarkSeen)

	dumpCTMap(ctMap)

	natIPv4L := natPkt.Layer(layers.LayerTypeIPv4)
	Expect(natIPv4L).NotTo(BeNil())
	natUDPL := natPkt.Layer(layers.LayerTypeUDP)
	Expect(natUDPL).NotTo(BeNil())

	icmpUNreachable := makeICMPError(natIPv4L.(*layers.IPv4), natUDPL.(*layers.UDP), 3, 1)

	runBpfTest(t, "calico_to_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpUNreachable)
		Expect(err).NotTo(HaveOccurred())
		// we have a normal ct record, it is related, must be allowed
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		checkICMP(res.dataOut, hostIP, ipv4.SrcIP, ipv4.SrcIP, ipv4.DstIP, ipv4.Protocol,
			uint16(udp.SrcPort), uint16(udp.DstPort))
	})
}

func TestICMPRelatedFromHost(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})
	expectMark(tcdefs.MarkSeen)

	icmpTTLExceeded := makeICMPError(ipv4, udp, 11 /* Time Exceeded */, 0 /* TTL expired */)

	runBpfTest(t, "calico_to_host_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpTTLExceeded)
		Expect(err).NotTo(HaveOccurred())
		// we have a normal ct record, it is related, must be allowed
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		checkICMP(res.dataOut, hostIP, ipv4.SrcIP, ipv4.SrcIP, ipv4.DstIP, ipv4.Protocol,
			uint16(udp.SrcPort), uint16(udp.DstPort))
	})
}

func TestICMPRelatedFromHostBeforeNAT(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0, 1, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		err := natMap.Delete(nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}()

	natIP := net.IPv4(8, 8, 8, 8)
	natPort := uint16(666)

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		err := natBEMap.Delete(nat.NewNATBackendKey(0, 0).AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}()

	// NP route
	node2IP := net.IPv4(3, 3, 3, 3)
	node2wCIDR := net.IPNet{
		IP:   natIP,
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}

	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload, ip.FromNetIP(node2IP).(ip.V4Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	// this will create NAT tracking entries for a nodeport
	runBpfTest(t, "calico_from_host_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})
	expectMark(tcdefs.MarkSeenBypassForwardSourceFixup)

	// we base the packet on the original packet before NAT as if we let the original packet through
	// before we do the actual NAT as that is where we check for TTL as doing it for the tunneled
	// packet would be complicated
	icmpTTLExceeded := makeICMPError(ipv4, udp, 11 /* Time Exceeded */, 0 /* TTL expired */)

	runBpfTest(t, "calico_to_host_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpTTLExceeded)
		Expect(err).NotTo(HaveOccurred())
		// we have a normal ct record, it is related, must be allowed
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		checkICMP(res.dataOut, hostIP, ipv4.SrcIP, ipv4.SrcIP, ipv4.DstIP, ipv4.Protocol,
			uint16(udp.SrcPort), uint16(udp.DstPort))
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
		SrcIP:    hostIP,
		DstIP:    ipInner.SrcIP,
		Protocol: layers.IPProtocolICMPv4,
		Length:   uint16(20 + 8 + len(payload)),
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

func checkICMP(bytes []byte, outSrc, outDst, innerSrc, innerDst net.IP,
	innerProto layers.IPProtocol, innerPortSrc, innerPortDst uint16) {

	icmpPkt := gopacket.NewPacket(bytes, layers.LayerTypeEthernet, gopacket.Default)

	fmt.Printf("pktR = %+v\n", icmpPkt)

	ipv4L := icmpPkt.Layer(layers.LayerTypeIPv4)
	Expect(ipv4L).NotTo(BeNil())
	ipv4R := ipv4L.(*layers.IPv4)

	Expect(ipv4R.SrcIP.String()).To(Equal(outSrc.String()))
	Expect(ipv4R.DstIP.String()).To(Equal(outDst.String()))

	payloadL := icmpPkt.ApplicationLayer()
	Expect(payloadL).NotTo(BeNil())
	origPkt := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeIPv4, gopacket.Default)
	Expect(origPkt).NotTo(BeNil())

	ipv4L = origPkt.Layer(layers.LayerTypeIPv4)
	Expect(ipv4L).NotTo(BeNil())
	ipv4R = ipv4L.(*layers.IPv4)

	Expect(ipv4R.SrcIP.String()).To(Equal(innerSrc.String()))
	Expect(ipv4R.DstIP.String()).To(Equal(innerDst.String()))
	Expect(ipv4R.Protocol).To(Equal(innerProto))

	switch innerProto {
	case layers.IPProtocolUDP:
		udpL := origPkt.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)

		Expect(uint16(udpR.SrcPort)).To(Equal(innerPortSrc))
		Expect(uint16(udpR.DstPort)).To(Equal(innerPortDst))
	case layers.IPProtocolTCP:
		tcpL := origPkt.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())
		tcpR := tcpL.(*layers.TCP)

		Expect(uint16(tcpR.SrcPort)).To(Equal(innerPortSrc))
		Expect(uint16(tcpR.DstPort)).To(Equal(innerPortDst))
	}
}
