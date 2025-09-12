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

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	conntrack3 "github.com/projectcalico/calico/felix/bpf/conntrack/v3"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
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

		Expect(res.dataOut).To(HaveLen(110)) // eth + ip (60) + udp + ip + icmp

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPTooBig(pktR, ipv4, udp, intfIP, natTunnelMTU)
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
		Options: []layers.IPv4Option{{
			OptionType:   111,
			OptionLength: 4,
			OptionData:   []byte{1, 2},
		}},
	}

	_, ipv4, l4, _, pktBytes, err := testPacketV4(nil, ipv4, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	runBpfUnitTest(t, "icmp_too_big.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(0))

		Expect(res.dataOut).To(HaveLen(110)) // eth + ip (60) + udp + ip opts + icmp

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPTooBig(pktR, ipv4, udp, intfIP, natTunnelMTU)
	})
}

func checkICMPTooBig(pktR gopacket.Packet, ipv4 *layers.IPv4, udp *layers.UDP, src net.IP, expMTU uint16) {
	ipv4L := pktR.Layer(layers.LayerTypeIPv4)
	Expect(ipv4L).NotTo(BeNil())
	ipv4R := ipv4L.(*layers.IPv4)

	Expect(ipv4R.Protocol).To(Equal(layers.IPProtocolICMPv4))
	Expect(ipv4R.SrcIP).To(Equal(src))
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

	icmpCSum := header.Checksum(toCSum, 0)
	fmt.Printf("icmpCSum 0x%x toCSum len(%d) = %+v\n", icmpCSum, len(toCSum), toCSum)
	Expect(icmpR.Checksum).To(Equal(uint16(0xffff - icmpCSum)))

	icmpData := gopacket.NewPacket(icmpR.Payload, layers.LayerTypeIPv4, gopacket.Default)
	fmt.Printf("icmpData = %+v\n", icmpData)
	Expect(icmpData.Layer(layers.LayerTypeIPv4)).To(layersMatchFields(ipv4))
	// the extra 8 bytes will contain the entire UDP header
	Expect(icmpData.Layer(layers.LayerTypeUDP)).To(layersMatchFields(udp))
}

func TestICMPTooBigNATNodePort(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "PMTU"
	defer func() { bpfIfaceName = "" }()

	extHostIP := net.ParseIP("55.55.0.1")
	_, ipv4, l4, payload, pktBytes, err := testPacketUDPDefaultNP(extHostIP)
	Expect(err).NotTo(HaveOccurred())

	origIPHeader := *ipv4
	origIPHeader.IHL = 5 /* no options */
	origIPHeader.Options = nil

	udp := l4.(*layers.UDP)
	natMap := nat.FrontendMap()
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap()
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	err = natMap.Update(
		nat.NewNATKey(node1ip, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0, 1, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = natMap.Update(
		nat.NewNATKey(extHostIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0, 1, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	natIP := net.IPv4(8, 8, 8, 8)
	natPort := uint16(666)

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	node2wCIDR := net.IPNet{
		IP:   natIP,
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}

	ctMap := conntrack.Map()
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	resetRTMap(rtMap)

	hostIP = node1ip
	skbMark = 0

	// Setup routing
	rtMap := routes.Map()
	err = rtMap.EnsureExists()
	defer resetRTMap(rtMap)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool,
			ip.FromNetIP(node2ip).(ip.V4Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node1CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	extNodeCIDR := net.IPNet{
		IP:   extHostIP,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&extNodeCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	dumpRTMap(rtMap)

	// Arriving at node 1, goodpacket, creates conntrack
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

		checkVxlanEncap(pktR, false, ipv4, udp, payload)

		//		encapedPkt = res.dataOut

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.DstIP, uint16(udp.DstPort), ipv4.SrcIP, uint16(udp.SrcPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey().(conntrack.Key)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Approved for both sides due to forwarding through the tunnel
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		Expect(ctr.Data().B2A.Approved).To(BeTrue())
	})

	dumpCTMap(ctMap)
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	v, ok := ct[conntrack.NewKey(uint8(ipv4.Protocol), ipv4.SrcIP, uint16(udp.SrcPort), natIP.To4(), natPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack3.FlagNATNPFwd))

	_, _, _, _, pkt2Bytes, err := testPacket(4, nil, &origIPHeader, udpDefault, make([]byte, 1600))
	Expect(err).NotTo(HaveOccurred())

	// Large packet arriving at node 1
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pkt2Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(extHostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(srcIP.String()))

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())

		origPkt := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeIPv4, gopacket.Default)
		Expect(origPkt).NotTo(BeNil())
		fmt.Printf("origPkt = %+v\n", origPkt)

		ipv4L = origPkt.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R = ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(srcIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(extHostIP.String()))
	})

	extSvcIP := net.ParseIP("123.55.0.1")
	_, _, _, _, pktBytes, err = testPacketUDPDefaultNPWithPayload(extSvcIP, make([]byte, 1600))
	Expect(err).NotTo(HaveOccurred())

	err = natMap.Update(
		nat.NewNATKey(extSvcIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0, 1, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	resetCTMap(ctMap) // avoid source collision with the previous connetion

	// Large packet arriving at node 1 for a external service IP
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(extSvcIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(srcIP.String()))

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())

		origPkt := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeIPv4, gopacket.Default)
		Expect(origPkt).NotTo(BeNil())
		fmt.Printf("origPkt = %+v\n", origPkt)

		ipv4L = origPkt.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R = ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(srcIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(extSvcIP.String()))
	})
}

func TestICMPv6TooBigNATNodePort(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "PMTU"
	defer func() { bpfIfaceName = "" }()

	extHostIP := net.ParseIP("dead::5555:0001")
	_, ipv6, l4, _, pktBytes, err := testPacketUDPDefaultNPV6WithPayload(extHostIP, make([]byte, 1600))
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	err = natMapV6.Update(
		nat.NewNATKeyV6(ipv6.DstIP, uint16(udp.DstPort), uint8(17)).AsBytes(),
		nat.NewNATValueV6(0, 1, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	err = natMapV6.Update(
		nat.NewNATKeyV6(node1ipV6, uint16(udp.DstPort), uint8(17)).AsBytes(),
		nat.NewNATValueV6(0, 1, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	natIP := net.ParseIP("abcd::ffff:0808:0808")
	natPort := uint16(666)

	err = natBEMapV6.Update(
		nat.NewNATBackendKeyV6(0, 0).AsBytes(),
		nat.NewNATBackendValueV6(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	resetCTMapV6(ctMapV6) // ensure it is clean

	hostIP = node1ipV6

	// Insert a reverse route for the source workload that is not in a calico
	// poll, for example 3rd party CNI is used.
	rtKey := routes.NewKeyV6(srcV6CIDR).AsBytes()
	rtVal := routes.NewValueV6WithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMapV6.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	extNodeCIDR := net.IPNet{
		IP:   extHostIP,
		Mask: net.CIDRMask(128, 128),
	}
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&extNodeCIDR).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	node2wCIDR := net.IPNet{
		IP:   natIP,
		Mask: net.CIDRMask(128, 128),
	}
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node2wCIDR).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6WithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool,
			ip.FromNetIP(node2ipV6).(ip.V6Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	dumpRTMapV6(rtMapV6)
	dumpNATMapV6(natMapV6)

	skbMark = 0
	// Leaving workloada test for fc711b192f */
	runBpfTest(t, "calico_from_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R := ipv6L.(*layers.IPv6)
		Expect(ipv6R.SrcIP.String()).To(Equal(extHostIP.String()))
		Expect(ipv6R.DstIP.String()).To(Equal(srcIPv6.String()))

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())

		origPkt := gopacket.NewPacket(payloadL.Payload()[4:], layers.LayerTypeIPv6, gopacket.Default)
		Expect(origPkt).NotTo(BeNil())
		fmt.Printf("origPkt = %+v\n", origPkt)

		ipv6L = origPkt.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R = ipv6L.(*layers.IPv6)
		Expect(ipv6R.SrcIP.String()).To(Equal(srcIPv6.String()))
		Expect(ipv6R.DstIP.String()).To(Equal(extHostIP.String()))
	}, withIPv6())
}
