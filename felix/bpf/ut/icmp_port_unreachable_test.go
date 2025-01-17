// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

func TestICMPPortUnreachable(t *testing.T) {
	RegisterTestingT(t)
	cleanUpMaps()

	ipHdr := *ipv4Default
	ipHdr.Options = []layers.IPv4Option{{
		OptionType:   123,
		OptionLength: 6,
		OptionData:   []byte{0xde, 0xad, 0xbe, 0xef},
	}}
	ipHdr.IHL += 2

	_, ipv4, _, _, pktBytes, err := testPacketV4(nil, &ipHdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	runBpfUnitTest(t, "icmp_port_unreachable.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(0))

		Expect(res.dataOut).To(HaveLen(110)) // eth + ip(60) + udp + ip + ipopts(8) + icmp

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPPortUnreachable(pktR, ipv4)
	})

}

func TestNATNoBackendFromHEP(t *testing.T) {
	RegisterTestingT(t)
	cleanUpMaps()

	iphdr := *ipv4Default

	_, ipv4, l4, _, pktBytes, err := testPacketV4(nil, &iphdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	udp := l4.(*layers.UDP)

	// Test with count as 1 but no backend. This results in a NAT backend lookup failure
	natkey := nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes()
	err = natMap.Update(
		natkey,
		nat.NewNATValue(0, 1, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		err := natMap.Delete(natkey)
		Expect(err).NotTo(HaveOccurred())
	}()

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_UNSPEC"), "expected program to return TC_ACT_UNSPEC")

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPPortUnreachable(pktR, ipv4)
	})
	expectMark(tcdefs.MarkSeenBypassForward)

	// Test with count as 0. This results in a no backend after frontend lookup as count is 0.
	err = natMap.Update(
		natkey,
		nat.NewNATValue(0, 0, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_UNSPEC"), "expected program to return TC_ACT_UNSPEC")

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPPortUnreachable(pktR, ipv4)
	})
	expectMark(tcdefs.MarkSeenBypassForward)
}

func checkICMPPortUnreachable(pktR gopacket.Packet, ipv4 *layers.IPv4) {
	ipv4L := pktR.Layer(layers.LayerTypeIPv4)
	Expect(ipv4L).NotTo(BeNil())
	ipv4R := ipv4L.(*layers.IPv4)

	Expect(ipv4R.Protocol).To(Equal(layers.IPProtocolICMPv4))
	Expect(ipv4R.SrcIP.String()).To(Equal(intfIP.String()))
	Expect(ipv4R.DstIP).To(Equal(ipv4.SrcIP))

	icmpL := pktR.Layer(layers.LayerTypeICMPv4)
	Expect(ipv4L).NotTo(BeNil())
	icmpR := icmpL.(*layers.ICMPv4)

	Expect(icmpR.TypeCode).To(Equal(
		layers.CreateICMPv4TypeCode(
			layers.ICMPv4TypeDestinationUnreachable,
			layers.ICMPv4CodePort,
		)))
}

func TestICMPV6PortUnreachable(t *testing.T) {
	RegisterTestingT(t)
	cleanUpMaps()

	hop := &layers.IPv6HopByHop{}
	hop.NextHeader = layers.IPProtocolUDP

	/* from gopacket ip6_test.go */
	tlv := &layers.IPv6HopByHopOption{}
	tlv.OptionType = 0x01 //PadN
	tlv.OptionData = []byte{0x00, 0x00, 0x00, 0x00}
	hop.Options = append(hop.Options, tlv)

	_, ipv6, _, _, pktBytes, err := testPacketV6(nil, ipv6Default, nil, nil, hop)
	Expect(err).NotTo(HaveOccurred())

	runBpfUnitTest(t, "icmp6_port_unreachable.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(0))

		Expect(res.dataOut).To(HaveLen(140)) // eth(14) + ipv6(40) + icmp(8) + ipv6(40) + ipopts(8) + len(pktBytes) - eth

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPv6PortUnreachable(pktR, ipv6)
	}, withIPv6(), withObjName("icmp6_port_unreachable.o"))
}

func checkICMPv6PortUnreachable(pktR gopacket.Packet, ipv6 *layers.IPv6) {
	ipv6L := pktR.Layer(layers.LayerTypeIPv6)
	Expect(ipv6L).NotTo(BeNil())
	ipv6R := ipv6L.(*layers.IPv6)

	Expect(ipv6R.NextHeader).To(Equal(layers.IPProtocolICMPv6))
	Expect(ipv6R.SrcIP.String()).To(Equal(intfIPV6.String()))
	Expect(ipv6R.DstIP).To(Equal(ipv6.SrcIP))

	icmpL := pktR.Layer(layers.LayerTypeICMPv6)
	Expect(ipv6L).NotTo(BeNil())
	icmpR := icmpL.(*layers.ICMPv6)

	Expect(icmpR.TypeCode).To(Equal(
		layers.CreateICMPv6TypeCode(
			layers.ICMPv6TypeDestinationUnreachable,
			layers.ICMPv6CodePortUnreachable,
		)))

	// serialize to recalculate csums

	icmp := *icmpR
	_ = icmp.SetNetworkLayerForChecksum(ipv6L.(gopacket.NetworkLayer))

	cpkt := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(cpkt, gopacket.SerializeOptions{ComputeChecksums: true},
		(pktR.Layer(layers.LayerTypeEthernet)).(gopacket.SerializableLayer),
		ipv6L.(gopacket.SerializableLayer), &icmp,
		(pktR.ApplicationLayer()).(gopacket.SerializableLayer))
	Expect(err).NotTo(HaveOccurred())

	fmt.Printf("pktR.Bytes() = %+v\n", pktR.Data())
	fmt.Printf("cpkt.Bytes() = %+v\n", cpkt.Bytes())

	Expect(icmpR.Checksum).To(Equal(
		gopacket.NewPacket(cpkt.Bytes(), layers.LayerTypeEthernet, gopacket.Default).
			Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6).Checksum))
}

func TestSVCLoopPrevention(t *testing.T) {
	RegisterTestingT(t)

	iphdr := *ipv4Default

	_, ipv4, _, _, pktBytesV4, err := testPacketV4(nil, &iphdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	_ = ipv4
	rtKey := routes.NewKey(dstV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagBlackHoleDrop, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	_, ipv6, _, _, pktBytesV6, err := testPacketV6(nil, ipv6Default, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	rtKeyV6 := routes.NewKeyV6(dstV6CIDR).AsBytes()
	rtValV6 := routes.NewValueV6WithIfIndex(routes.FlagBlackHoleReject, 1).AsBytes()
	err = rtMapV6.Update(rtKeyV6, rtValV6)
	Expect(err).NotTo(HaveOccurred())

	// Insert a reverse route for the source workload.
	rtKeyW := routes.NewKey(srcV4CIDR).AsBytes()
	rtValW := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMap.Update(rtKeyW, rtValW)
	Expect(err).NotTo(HaveOccurred())

	defer func() {
		err := rtMap.Delete(rtKey)
		Expect(err).NotTo(HaveOccurred())
		err = rtMapV6.Delete(rtKeyV6)
		Expect(err).NotTo(HaveOccurred())
		err = rtMap.Delete(rtKeyW)
		Expect(err).NotTo(HaveOccurred())
	}()

	// Test with action = drop
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytesV4)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_SHOT"), "expected program to return TC_ACT_SHOT")

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		bpfCounters, err := counters.Read(countersMap, 1, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(int(bpfCounters[counters.DroppedBlackholeRoute])).To(Equal(1))
	})

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytesV4)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_SHOT"), "expected program to return TC_ACT_SHOT")

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		bpfCounters, err := counters.Read(countersMap, 1, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(int(bpfCounters[counters.DroppedBlackholeRoute])).To(Equal(2))
	})

	rtVal = routes.NewValueWithIfIndex(routes.FlagBlackHoleReject, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	// Test with action = reject
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytesV4)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_UNSPEC"), "expected program to return TC_ACT_UNSPEC")

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPPortUnreachable(pktR, ipv4)
		bpfCounters, err := counters.Read(countersMap, 1, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(int(bpfCounters[counters.DroppedBlackholeRoute])).To(Equal(3))
	})

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytesV6)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_UNSPEC"), "expected program to return TC_ACT_UNSPEC")

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPv6PortUnreachable(pktR, ipv6)
		bpfCounters, err := counters.Read(countersMap, 1, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(int(bpfCounters[counters.DroppedBlackholeRoute])).To(Equal(4))
	}, withIPv6())
}
