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

type ICMPv6ErrHeader struct {
	layers.ICMPv6
}

func (i *ICMPv6ErrHeader) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// There need to be extra 4 bytes of unused data to make the header 8 bytes
	// in total.
	_, err := b.PrependBytes(4)
	if err != nil {
		return err
	}

	return i.ICMPv6.SerializeTo(b, opts)
}

var rulesAllowUDP = &polprog.Rules{
	SuppressNormalHostPolicy: true,
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

	bpfIfaceName = "ICMPPlain"
	defer func() { bpfIfaceName = "" }()

	defer resetBPFMaps()
	hostIP = node1ip

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
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		inner := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeIPv4, gopacket.Default)
		Expect(inner).NotTo(BeNil())
		fmt.Printf("inner = %+v\n", inner)
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
	hostIP = node1ip

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
	hostIP = node1ip

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	rtKey := routes.NewKey(dstV4CIDR).AsBytes()
	rtVal := routes.NewValue(routes.FlagsLocalHost).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

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
	hostIP = node1ip

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
	expectMark(tcdefs.MarkSeenBypassForward)

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
	return makeICMPErrorFrom(node1ip, ipInner, l4, icmpType, icmpCode)
}

func makeICMPErrorFrom(from net.IP, ipInner *layers.IPv4, l4 gopacket.SerializableLayer, icmpType, icmpCode uint8) []byte {
	payloadBuf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(payloadBuf, gopacket.SerializeOptions{}, ipInner, l4)
	Expect(err).NotTo(HaveOccurred())
	payload := payloadBuf.Bytes()

	fmt.Printf("inner reply = %+v\n", gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default))

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
		SrcIP:    from,
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

func makeICMPv6Error(ipInner *layers.IPv6, l4 gopacket.SerializableLayer, icmpType, icmpCode uint8) []byte {
	payloadBuf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(payloadBuf, gopacket.SerializeOptions{}, ipInner, l4)
	Expect(err).NotTo(HaveOccurred())
	payload := payloadBuf.Bytes()

	fmt.Printf("inner reply = %+v\n", gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.Default))

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0xee, 0, 0, 0, 0, 1},
		DstMAC:       []byte{0xfe, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv6,
	}

	ipv6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      hostIP,
		DstIP:      ipInner.SrcIP,
		Length:     uint16(40 + 8 + 8 + len(payload)),
		NextHeader: layers.IPProtocolIPv6HopByHop,
	}

	hop := &layers.IPv6HopByHop{}
	hop.NextHeader = layers.IPProtocolICMPv6

	/* from gopacket ip6_test.go */
	tlv := &layers.IPv6HopByHopOption{}
	tlv.OptionType = 0x01 //PadN
	tlv.OptionData = []byte{0x00, 0x00, 0x00, 0x00}
	hop.Options = append(hop.Options, tlv)

	icmp := &ICMPv6ErrHeader{
		layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(icmpType, icmpCode),
		},
	}
	_ = icmp.SetNetworkLayerForChecksum(ipv6)

	pkt := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		eth, ipv6, hop, icmp, gopacket.Payload(payload))
	Expect(err).NotTo(HaveOccurred())

	return pkt.Bytes()
}

func checkICMP(bytes []byte, outSrc, outDst, innerSrc, innerDst net.IP,
	innerProto layers.IPProtocol, innerPortSrc, innerPortDst uint16) {

	icmpPkt := gopacket.NewPacket(bytes, layers.LayerTypeEthernet, gopacket.Default)

	fmt.Printf("pktR = %+v\n", icmpPkt)

	ethL := icmpPkt.Layer(layers.LayerTypeEthernet)
	Expect(ethL).NotTo(BeNil())
	ethR := ethL.(*layers.Ethernet)

	ipv4L := icmpPkt.Layer(layers.LayerTypeIPv4)
	Expect(ipv4L).NotTo(BeNil())
	ipv4R := ipv4L.(*layers.IPv4)

	Expect(ipv4R.SrcIP.String()).To(Equal(outSrc.String()))
	Expect(ipv4R.DstIP.String()).To(Equal(outDst.String()))

	icmpL := icmpPkt.Layer(layers.LayerTypeICMPv4)
	Expect(icmpL).NotTo(BeNil())
	icmpR := icmpL.(*layers.ICMPv4)

	payloadL := icmpPkt.ApplicationLayer()
	Expect(payloadL).NotTo(BeNil())

	// Check if the packet has correct checksums
	pkt := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
		ethR, ipv4R, icmpR, gopacket.Payload(payloadL.Payload()))
	Expect(err).NotTo(HaveOccurred())
	pktBytes := pkt.Bytes()

	Expect(bytes).To(Equal(pktBytes))

	origPkt := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeIPv4, gopacket.Default)
	Expect(origPkt).NotTo(BeNil())
	fmt.Printf("origPkt = %+v\n", origPkt)

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

func checkICMPv6(bytes []byte, outSrc, outDst, innerSrc, innerDst net.IP,
	innerProto layers.IPProtocol, innerPortSrc, innerPortDst uint16) {

	icmpPkt := gopacket.NewPacket(bytes, layers.LayerTypeEthernet, gopacket.Default)

	fmt.Printf("pktR = %+v\n", icmpPkt)

	ethL := icmpPkt.Layer(layers.LayerTypeEthernet)
	Expect(ethL).NotTo(BeNil())
	ethR := ethL.(*layers.Ethernet)

	ipv6L := icmpPkt.Layer(layers.LayerTypeIPv6)
	Expect(ipv6L).NotTo(BeNil())
	ipv6R := ipv6L.(*layers.IPv6)

	Expect(ipv6R.SrcIP.String()).To(Equal(outSrc.String()))
	Expect(ipv6R.DstIP.String()).To(Equal(outDst.String()))

	icmpL := icmpPkt.Layer(layers.LayerTypeICMPv6)
	Expect(icmpL).NotTo(BeNil())
	icmpR := icmpL.(*layers.ICMPv6)
	_ = icmpR.SetNetworkLayerForChecksum(ipv6L.(gopacket.NetworkLayer))

	payloadL := icmpPkt.ApplicationLayer()
	Expect(payloadL).NotTo(BeNil())

	// Check if the packet has correct checksums
	pkt := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
		ethR, ipv6R, icmpR, gopacket.Payload(payloadL.Payload()))
	Expect(err).NotTo(HaveOccurred())
	pktBytes := pkt.Bytes()

	Expect(bytes).To(Equal(pktBytes))

	origPkt := gopacket.NewPacket(payloadL.Payload()[4:], layers.LayerTypeIPv6, gopacket.Default)
	Expect(origPkt).NotTo(BeNil())
	fmt.Printf("origPkt = %+v\n", origPkt)

	ipv6L = origPkt.Layer(layers.LayerTypeIPv6)
	Expect(ipv6L).NotTo(BeNil())
	ipv6R = ipv6L.(*layers.IPv6)

	Expect(ipv6R.SrcIP.String()).To(Equal(innerSrc.String()))
	Expect(ipv6R.DstIP.String()).To(Equal(innerDst.String()))

	var l4L gopacket.Layer

	switch innerProto {
	case layers.IPProtocolUDP:
		l4L = origPkt.Layer(layers.LayerTypeUDP)
	case layers.IPProtocolTCP:
		l4L = origPkt.Layer(layers.LayerTypeTCP)
	}
	Expect(l4L).NotTo(BeNil())

	switch l4 := l4L.(type) {
	case *layers.UDP:
		Expect(uint16(l4.SrcPort)).To(Equal(innerPortSrc))
		Expect(uint16(l4.DstPort)).To(Equal(innerPortDst))
	case *layers.TCP:
		Expect(uint16(l4.SrcPort)).To(Equal(innerPortSrc))
		Expect(uint16(l4.DstPort)).To(Equal(innerPortDst))
	}
}

func TestICMPv6RelatedPlain(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "ICMPPlain"
	defer func() { bpfIfaceName = "" }()

	defer resetBPFMaps()

	hostIP = node1ipV6
	defer func() { hostIP = node1ip }()

	_, ipv6, l4, _, pktBytes, err := testPacketV6(nil, nil, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	icmpUNreachable := makeICMPv6Error(ipv6, udp, layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodePortUnreachable)

	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpUNreachable)
		Expect(err).NotTo(HaveOccurred())
		// there is no normal CT record yet, must be denied
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	}, withIPv6())

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKeyV6(srcV6CIDR).AsBytes()
	rtVal := routes.NewValueV6WithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMapV6.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	}, withIPv6())
	expectMark(tcdefs.MarkSeen)

	runBpfTest(t, "calico_to_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpUNreachable)
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		inner := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeIPv4, gopacket.Default)
		Expect(inner).NotTo(BeNil())
		fmt.Printf("inner = %+v\n", inner)
		Expect(err).NotTo(HaveOccurred())
		// we have a normal ct record, it is related, must be allowed
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	}, withIPv6())

	// fake icmp echo reply, we do not really care about the payload, just the type and code
	icmpEchoResp := makeICMPv6Error(ipv6, udp, layers.ICMPv6TypeEchoReply, 0)

	runBpfTest(t, "calico_to_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpEchoResp)
		Expect(err).NotTo(HaveOccurred())
		// echo is unrelated, must be denied
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	}, withIPv6())
}

func TestICMPv6RelatedNATPodPod(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()

	hostIP = node1ipV6
	defer func() { hostIP = node1ip }()

	_, ipv6, l4, _, pktBytes, err := testPacketV6(nil, nil, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKeyV6(srcV6CIDR).AsBytes()
	rtVal := routes.NewValueV6WithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMapV6.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	err = natMapV6.Update(
		nat.NewNATKeyV6(ipv6.DstIP, uint16(udp.DstPort), 17).AsBytes(),
		nat.NewNATValue(0, 1, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		err := natMapV6.Delete(nat.NewNATKeyV6(ipv6.DstIP, uint16(udp.DstPort), 17).AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}()

	natIP := net.ParseIP("abcd::ffff:0808:0808")
	natPort := uint16(666)

	err = natBEMapV6.Update(
		nat.NewNATBackendKeyV6(0, 0).AsBytes(),
		nat.NewNATBackendValueV6(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		err := natBEMapV6.Delete(nat.NewNATBackendKey(0, 0).AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}()

	var natPkt gopacket.Packet

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		natPkt = gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
	}, withIPv6())
	expectMark(tcdefs.MarkSeen)

	dumpCTMap(ctMap)

	natIPv6L := natPkt.Layer(layers.LayerTypeIPv6)
	Expect(natIPv6L).NotTo(BeNil())
	natUDPL := natPkt.Layer(layers.LayerTypeUDP)
	Expect(natUDPL).NotTo(BeNil())

	icmpUNreachable := makeICMPv6Error(natIPv6L.(*layers.IPv6), natUDPL.(*layers.UDP), 4, 1)

	runBpfTest(t, "calico_to_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpUNreachable)
		Expect(err).NotTo(HaveOccurred())
		// we have a normal ct record, it is related, must be allowed
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		checkICMPv6(res.dataOut, hostIP, ipv6.SrcIP, ipv6.SrcIP, ipv6.DstIP, 17,
			uint16(udp.SrcPort), uint16(udp.DstPort))
	}, withIPv6())
}
