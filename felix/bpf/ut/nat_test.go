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

	"github.com/projectcalico/calico/felix/bpf"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
)

func TestNATPodPodXNode(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "NAT1"
	defer func() { bpfIfaceName = "" }()

	eth, ipv4, l4, payload, pktBytes, err := testPacketUDPDefaultNP(node1ip)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	mc := &bpf.MapContext{}
	natMap := nat.FrontendMap(mc)
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap(mc)
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
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

	ctMap := conntrack.Map(mc)
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	var natedPkt []byte

	hostIP = node1ip

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	// Leaving workload
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4Nat := *ipv4
		ipv4Nat.DstIP = natIP

		udpNat := *udp
		udpNat.DstPort = layers.UDPPort(natPort)

		// created the expected packet after NAT, with recalculated csums
		_, _, _, _, resPktBytes, err := testPacket(eth, &ipv4Nat, &udpNat, payload)
		Expect(err).NotTo(HaveOccurred())

		// expect them to be the same
		Expect(res.dataOut).To(Equal(resPktBytes))

		natedPkt = res.dataOut
	})

	// Leaving node 1
	skbMark = tcdefs.MarkSeen // CALI_SKB_MARK_SEEN

	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(natedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(natedPkt))
	})

	dumpCTMap(ctMap)
	fromHostCT := saveCTMap(ctMap)
	resetCTMap(ctMap)

	var recvPkt []byte

	hostIP = node2ip
	skbMark = 0

	bpfIfaceName = "NAT2"
	// Arriving at node 2
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(natedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(natedPkt))
	})

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	v, ok := ct[conntrack.NewKey(uint8(ipv4.Protocol), ipv4.SrcIP, uint16(udp.SrcPort), natIP.To4(), natPort)]
	Expect(ok).To(BeTrue())
	// No NATing, service already resolved
	Expect(v.Type()).To(Equal(conntrack.TypeNormal))
	Expect(v.Flags()).To(Equal(uint16(0)))

	// Insert the reverse route for backend for RPF check.
	resetRTMap(rtMap)
	beV4CIDR := ip.CIDRFromNetIP(natIP).(ip.V4CIDR)
	bertKey := routes.NewKey(beV4CIDR).AsBytes()
	bertVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(bertKey, bertVal)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at workload at node 2
	skbMark = tcdefs.MarkSeen // CALI_SKB_MARK_SEEN
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(natedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(natedPkt))

		recvPkt = res.dataOut
	})

	dumpCTMap(ctMap)

	var respPkt []byte

	// Response leaving workload at node 2
	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		respPkt = udpResponseRaw(recvPkt)
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(respPkt))
	})

	// Response leaving node 2
	skbMark = tcdefs.MarkSeen // CALI_SKB_MARK_SEEN
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(respPkt))
	})

	dumpCTMap(ctMap)
	resetCTMap(ctMap)
	restoreCTMap(ctMap, fromHostCT)
	dumpCTMap(ctMap)

	hostIP = node1ip

	// Response arriving at node 1
	bpfIfaceName = "NAT1"
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(respPkt))
	})

	dumpCTMap(ctMap)

	// Response arriving at workload at node 1
	skbMark = tcdefs.MarkSeen // CALI_SKB_MARK_SEEN
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		pktExp := gopacket.NewPacket(respPkt, layers.LayerTypeEthernet, gopacket.Default)
		ipv4L := pktExp.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		udpL := pktExp.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)

		ipv4R.SrcIP = ipv4.DstIP
		udpR.SrcPort = udp.DstPort
		_ = udpR.SetNetworkLayerForChecksum(ipv4R)

		pktExpSer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializePacket(pktExpSer, gopacket.SerializeOptions{ComputeChecksums: true}, pktExp)
		Expect(err).NotTo(HaveOccurred())

		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(pktExpSer.Bytes()))
	})

	dumpCTMap(ctMap)

	// Response leaving to original source

	// clean up
	resetCTMap(ctMap)
}

func TestNATNodePort(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "NP-1"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, l4, payload, pktBytes, err := testPacketUDPDefaultNP(node1ip)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)
	mc := &bpf.MapContext{}
	natMap := nat.FrontendMap(mc)
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap(mc)
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
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

	ctMap := conntrack.Map(mc)
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	var encapedPkt []byte

	hostIP = node1ip
	skbMark = 0

	// Arriving at node 1 - non-routable -> denied
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	// Setup routing
	rtMap := routes.Map(mc)
	err = rtMap.EnsureExists()
	defer resetRTMap(rtMap)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload, ip.FromNetIP(node2ip).(ip.V4Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node1CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	dumpRTMap(rtMap)
	rtNode1 := saveRTMap(rtMap)

	vni := uint32(0)

	// Arriving at node 1
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

		checkVxlanEncap(pktR, false, ipv4, udp, payload)
		vni = getVxlanVNI(pktR)

		encapedPkt = res.dataOut

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.DstIP, uint16(udp.DstPort), ipv4.SrcIP, uint16(udp.SrcPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey()
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Whitelisted for both sides due to forwarding through the tunnel
		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).To(BeTrue())
	})

	dumpCTMap(ctMap)
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	v, ok := ct[conntrack.NewKey(uint8(ipv4.Protocol), ipv4.SrcIP, uint16(udp.SrcPort), natIP.To4(), natPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack.FlagNATNPFwd))

	skbMark = tcdefs.MarkSeenBypassForwardSourceFixup // CALI_SKB_MARK_BYPASS_FWD_SRC_FIXUP
	// Leaving node 1
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(encapedPkt))
	})

	dumpCTMap(ctMap)
	fromHostCT := saveCTMap(ctMap)

	encapedPktArrivesAtNode2 := make([]byte, len(encapedPkt))
	copy(encapedPktArrivesAtNode2, encapedPkt)

	resetCTMap(ctMap)

	var recvPkt []byte

	hostIP = node2ip
	skbMark = 0

	// change the routing - it is a local workload now!
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalWorkload).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// we must know that the encaped packet src ip if from a known host
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node1CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	dumpRTMap(rtMap)

	// now we are at the node with local workload
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0 /* id */, 1 /* count */, 1 /* local */, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at node 2
	bpfIfaceName = "NP-2"

	arpMapN2 := saveARPMap(arpMap)
	Expect(arpMapN2).To(HaveLen(0))

	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.SrcIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(natIP.String()))

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)
		Expect(udpR.SrcPort).To(Equal(layers.UDPPort(udp.SrcPort)))
		Expect(udpR.DstPort).To(Equal(layers.UDPPort(natPort)))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.DstIP, uint16(udp.DstPort), ipv4.SrcIP, uint16(udp.SrcPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))
		Expect(ctr.NATSPort()).To(Equal(uint16(0)))

		ctKey = ctr.ReverseNATKey()
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Whitlisted source side
		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		// Dest not whitelisted yet
		Expect(ctr.Data().B2A.Whitelisted).NotTo(BeTrue())

		recvPkt = res.dataOut
	})

	dumpCTMap(ctMap)
	ct, err = conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	v, ok = ct[conntrack.NewKey(uint8(ipv4.Protocol), ipv4.SrcIP, uint16(udp.SrcPort), natIP.To4(), natPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack.FlagExtLocal))

	dumpARPMap(arpMap)

	arpMapN2 = saveARPMap(arpMap)
	Expect(arpMapN2).To(HaveLen(1))
	arpKey := arp.NewKey(node1ip, 1 /* ifindex is always 1 in UT */)
	Expect(arpMapN2).To(HaveKey(arpKey))
	macDst := encapedPkt[0:6]
	macSrc := encapedPkt[6:12]
	Expect(arpMapN2[arpKey]).To(Equal(arp.NewValue(macDst, macSrc)))

	// try a spoofed tunnel packet, should be dropped and have no effect
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// modify the only known good src IP, we do not care about csums at this point
		encapedPkt[26] = 234
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	hostIP = net.IPv4(0, 0, 0, 0) // workloads do not have it set

	skbMark = tcdefs.MarkSeen

	// Insert the reverse route for backend for RPF check.
	resetRTMap(rtMap)
	beV4CIDR := ip.CIDRFromNetIP(natIP).(ip.V4CIDR)
	bertKey := routes.NewKey(beV4CIDR).AsBytes()
	bertVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(bertKey, bertVal)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at workload at node 2
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(recvPkt))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.DstIP, uint16(udp.DstPort), ipv4.SrcIP, uint16(udp.SrcPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey()
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse),
			fmt.Sprintf("Expected reverse conntrack entry but got %v", ctr))

		// Whitelisted source side
		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		// Whitelisted destination side as well
		Expect(ctr.Data().B2A.Whitelisted).To(BeTrue())
	})

	skbMark = 0

	// Response leaving workload at node 2
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		respPkt := udpResponseRaw(recvPkt)
		// Change the MAC addresses so that we can observe that the right
		// addresses were patched in.
		copy(respPkt[:6], []byte{1, 2, 3, 4, 5, 6})
		copy(respPkt[6:12], []byte{6, 5, 4, 3, 2, 1})
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ethL := pktR.Layer(layers.LayerTypeEthernet)
		Expect(ethL).NotTo(BeNil())
		ethR := ethL.(*layers.Ethernet)
		Expect(ethR).To(layersMatchFields(&layers.Ethernet{
			SrcMAC:       macDst,
			DstMAC:       macSrc,
			EthernetType: layers.EthernetTypeIPv4,
		}))

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(natIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node1ip.String()))

		checkVxlan(pktR)

		encapedPkt = res.dataOut
	})

	dumpCTMap(ctMap)

	skbMark = tcdefs.MarkSeenBypassForwardSourceFixup // CALI_SKB_MARK_BYPASS_FWD_SRC_FIXUP

	hostIP = node2ip

	// Response leaving node 2
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		// check that the IP is fixed up
		Expect(ipv4R.SrcIP.String()).To(Equal(node2ip.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node1ip.String()))

		checkVxlan(pktR)

		encapedPkt = res.dataOut
	})

	dumpCTMap(ctMap)
	resetCTMap(ctMap)
	restoreCTMap(ctMap, fromHostCT)
	dumpCTMap(ctMap)

	hostIP = node1ip

	// change to routing again to a remote workload
	resetRTMap(rtMap)
	restoreRTMap(rtMap, rtNode1)
	dumpRTMap(rtMap)

	// Response arriving at node 1
	bpfIfaceName = "NP-1"

	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.DstIP.String()).To(Equal(ipv4.SrcIP.String()))
		Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.DstIP.String()))

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)
		Expect(udpR.SrcPort).To(Equal(udp.DstPort))
		Expect(udpR.DstPort).To(Equal(udp.SrcPort))

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		Expect(payload).To(Equal(payloadL.Payload()))

		recvPkt = res.dataOut
	})

	dumpCTMap(ctMap)

	// try a spoofed tunnel packet returnign back, should be dropped and have no effect
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// modify the only known good src IP, we do not care about csums at this point
		encapedPkt[26] = 235
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	skbMark = tcdefs.MarkSeenBypassForward // CALI_SKB_MARK_BYPASS_FWD

	// Response leaving to original source
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.DstIP, uint16(udp.DstPort), ipv4.SrcIP, uint16(udp.SrcPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey()
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Whitelisted for both sides due to forwarding through the tunnel
		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).To(BeTrue())
	})

	dumpCTMap(ctMap)

	// Another pkt arriving at node 1 - uses existing CT entries
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

		checkVxlanEncap(pktR, false, ipv4, udp, payload)
	})

	/*
	 * TEST that unknown VNI is passed through
	 */
	testUnrelatedVXLAN(t, node2ip, vni)

	// TEST host-networked backend
	{
		resetCTMap(ctMap)

		var recvPkt []byte

		hostIP = node2ip
		skbMark = 0

		// we must know that the encaped packet src ip is from a known host
		err = rtMap.Update(
			routes.NewKey(ip.CIDRFromIPNet(&node1CIDR).(ip.V4CIDR)).AsBytes(),
			routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
		err = rtMap.Update(
			routes.NewKey(ip.CIDRFromIPNet(&node2CIDR).(ip.V4CIDR)).AsBytes(),
			routes.NewValue(routes.FlagsLocalHost).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())

		dumpRTMap(rtMap)

		// now we are at the node with local workload
		err = natMap.Update(
			nat.NewNATKey(net.IPv4(255, 255, 255, 255), uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
			nat.NewNATValue(0 /* count */, 1 /* local */, 1, 0).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())

		// make it point to the local host - host networked backend
		err = natBEMap.Update(
			nat.NewNATBackendKey(0, 0).AsBytes(),
			nat.NewNATBackendValue(node2ip, natPort).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())

		// Arriving at node 2
		bpfIfaceName = "NP-2"

		runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(encapedPktArrivesAtNode2)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)

			ipv4L := pktR.Layer(layers.LayerTypeIPv4)
			ipv4R := ipv4L.(*layers.IPv4)
			Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.SrcIP.String()))
			Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

			udpL := pktR.Layer(layers.LayerTypeUDP)
			Expect(udpL).NotTo(BeNil())
			udpR := udpL.(*layers.UDP)
			Expect(udpR.SrcPort).To(Equal(layers.UDPPort(udp.SrcPort)))
			Expect(udpR.DstPort).To(Equal(layers.UDPPort(natPort)))

			ct, err := conntrack.LoadMapMem(ctMap)
			Expect(err).NotTo(HaveOccurred())

			ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
				ipv4.DstIP, uint16(udp.DstPort), ipv4.SrcIP, uint16(udp.SrcPort))

			Expect(ct).Should(HaveKey(ctKey))
			ctr := ct[ctKey]
			Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

			ctKey = ctr.ReverseNATKey()
			Expect(ct).Should(HaveKey(ctKey))
			ctr = ct[ctKey]
			Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

			// Whitlisted source side
			Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
			// Dest not whitelisted yet
			Expect(ctr.Data().B2A.Whitelisted).NotTo(BeTrue())

			recvPkt = res.dataOut
		})

		dumpCTMap(ctMap)

		skbMark = 0

		// Response leaving workload at node 2
		runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
			respPkt := udpResponseRaw(recvPkt)

			// Change the MAC addresses so that we can observe that the right
			// addresses were patched in.
			macUntouched := []byte{6, 5, 4, 3, 2, 1}
			copy(respPkt[:6], []byte{1, 2, 3, 4, 5, 6})
			copy(respPkt[6:12], macUntouched)

			res, err := bpfrun(respPkt)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)

			ethL := pktR.Layer(layers.LayerTypeEthernet)
			Expect(ethL).NotTo(BeNil())
			ethR := ethL.(*layers.Ethernet)
			Expect(ethR).To(layersMatchFields(&layers.Ethernet{
				SrcMAC:       macUntouched, // Source is set by net stack and should not be touched.
				DstMAC:       macSrc,
				EthernetType: layers.EthernetTypeIPv4,
			}))

			ipv4L := pktR.Layer(layers.LayerTypeIPv4)
			Expect(ipv4L).NotTo(BeNil())
			ipv4R := ipv4L.(*layers.IPv4)
			Expect(ipv4R.SrcIP.String()).To(Equal(node2ip.String()))
			Expect(ipv4R.DstIP.String()).To(Equal(node1ip.String()))

			checkVxlan(pktR)
		})
	}
}

func TestNATNodePortNoFWD(t *testing.T) {
	RegisterTestingT(t)

	defer resetCTMap(ctMap)

	bpfIfaceName = "NPlo"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, l4, payload, pktBytes, err := testPacketUDPDefaultNP(node1ip)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)
	mc := &bpf.MapContext{}
	natMap := nat.FrontendMap(mc)
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap(mc)
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	// local workload
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0 /* count */, 1 /* local */, 1, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	natIP := net.IPv4(8, 8, 8, 8)
	natPort := uint16(666)

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	ctMap := conntrack.Map(mc)
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	var recvPkt []byte

	hostIP = node1ip
	skbMark = 0

	// Setup routing
	rtMap := routes.Map(mc)
	err = rtMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)
	// backend it is a local workload
	resetRTMap(rtMap)
	beV4CIDR := ip.CIDRFromNetIP(natIP).(ip.V4CIDR)
	bertKey := routes.NewKey(beV4CIDR).AsBytes()
	bertVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(bertKey, bertVal)
	Expect(err).NotTo(HaveOccurred())
	dumpRTMap(rtMap)

	// Arriving at node
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.SrcIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(natIP.String()))

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)
		Expect(udpR.SrcPort).To(Equal(layers.UDPPort(udp.SrcPort)))
		Expect(udpR.DstPort).To(Equal(layers.UDPPort(natPort)))

		recvPkt = res.dataOut
	})

	dumpCTMap(ctMap)

	hostIP = net.IPv4(0, 0, 0, 0) // workloads do not have it set

	skbMark = tcdefs.MarkSeen // CALI_SKB_MARK_SEEN

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	v, ok := ct[conntrack.NewKey(uint8(ipv4.Protocol), ipv4.SrcIP, uint16(udp.SrcPort), natIP.To4(), natPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack.FlagExtLocal))

	// Arriving at workload
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(recvPkt))
	})

	skbMark = 0
	var respPkt []byte

	// Response leaving workload at node 2
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		respPkt = udpResponseRaw(recvPkt)
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(respPkt))
	})

	skbMark = tcdefs.MarkSeen // CALI_SKB_MARK_SEEN

	// Response leaving to original source
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.DstIP.String()).To(Equal(ipv4.SrcIP.String()))
		Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.DstIP.String()))

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)
		Expect(udpR.SrcPort).To(Equal(udp.DstPort))
		Expect(udpR.DstPort).To(Equal(udp.SrcPort))

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		Expect(payload).To(Equal(payloadL.Payload()))

	})

	dumpCTMap(ctMap)
}

func TestNATNodePortMultiNIC(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "NPM1"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, l4, payload, pktBytes, err := testPacketUDPDefaultNP(node1ip2)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)
	mc := &bpf.MapContext{}
	natMap := nat.FrontendMap(mc)
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap(mc)
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	// NP for node1ip
	err = natMap.Update(
		nat.NewNATKey(node1ip, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0, 1, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// NP for node1ip2
	err = natMap.Update(
		nat.NewNATKey(node1ip2, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
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

	ctMap := conntrack.Map(mc)
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	var encapedPkt []byte

	hostIP = node1ip2
	skbMark = 0

	// Setup routing
	rtMap := routes.Map(mc)
	err = rtMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload, ip.FromNetIP(node2ip).(ip.V4Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node1CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	dumpRTMap(rtMap)

	// Arriving at node 1 through 10.10.2.x
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

		checkVxlanEncap(pktR, false, ipv4, udp, payload)

		encapedPkt = res.dataOut

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey()
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Whitelisted for both sides due to forwarding through the tunnel
		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).To(BeTrue())
	})

	dumpCTMap(ctMap)

	skbMark = tcdefs.MarkSeenBypassForwardSourceFixup // CALI_SKB_MARK_BYPASS_FWD_SRC_FIXUP

	hostIP = node1ip
	var encapedGoPkt gopacket.Packet

	// Leaving node 1 through 10.10.0.x
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

		checkVxlanEncap(pktR, false, ipv4, udp, payload)

		encapedGoPkt = pktR
	})

	dumpCTMap(ctMap)

	// craft response packet - short-circuit the remote node side, tested in
	// TestNATNodePort()
	respPkt := encapedResponse(encapedGoPkt)

	var recvPkt []byte

	// Response arriving at node 1 through 10.10.0.x
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// Initially, blocked by the VXLAN source policing.
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))

		// Add the route for the remote node.  Should now be allowed...
		err = rtMap.Update(
			routes.NewKey(ip.FromNetIP(node2ip).AsCIDR().(ip.V4CIDR)).AsBytes(),
			routes.NewValueWithNextHop(routes.FlagsRemoteHost, ip.FromNetIP(node2ip).(ip.V4Addr)).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
		res, err = bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.DstIP.String()).To(Equal(ipv4.SrcIP.String()))
		Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.DstIP.String()))

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)
		Expect(udpR.SrcPort).To(Equal(udp.DstPort))
		Expect(udpR.DstPort).To(Equal(udp.SrcPort))

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		Expect(payload).To(Equal(payloadL.Payload()))

		recvPkt = res.dataOut
	})

	dumpCTMap(ctMap)

	skbMark = tcdefs.MarkSeenBypassForward // CALI_SKB_MARK_BYPASS_FWD

	// Response leaving to original source
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey()
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Whitelisted for both sides due to forwarding through the tunnel
		Expect(ctr.Data().A2B.Whitelisted).To(BeTrue())
		Expect(ctr.Data().B2A.Whitelisted).To(BeTrue())
	})

	dumpCTMap(ctMap)
}

func testUnrelatedVXLAN(t *testing.T, nodeIP net.IP, vni uint32) {
	vxlanTest := func(fillUDPCsum bool, validVNI bool) {
		eth := ethDefault
		ipv4 := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    net.IPv4(1, 2, 3, 4),
			DstIP:    nodeIP,
			Protocol: layers.IPProtocolUDP,
		}

		udp := &layers.UDP{
			SrcPort: layers.UDPPort(testVxlanPort),
			DstPort: layers.UDPPort(testVxlanPort),
		}

		vxlan := &layers.VXLAN{
			ValidIDFlag: validVNI,
			VNI:         vni + 1,
		}

		payload := make([]byte, 64)

		udp.Length = uint16(8 + 8 + len(payload))
		_ = udp.SetNetworkLayerForChecksum(ipv4)

		pkt := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
			eth, ipv4, udp, vxlan, gopacket.Payload(payload))
		Expect(err).NotTo(HaveOccurred())
		pktBytes := pkt.Bytes()

		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)

			Expect(res.dataOut).To(Equal(pktBytes))
		})
	}

	hostIP = nodeIP

	vxlanTest(true, true)
	vxlanTest(false, false)
}

func TestNATNodePortICMPTooBig(t *testing.T) {
	RegisterTestingT(t)

	_, ipv4, l4, _, pktBytes, err := testPacket(nil, nil, nil, make([]byte, natTunnelMTU))
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	mc := &bpf.MapContext{}
	natMap := nat.FrontendMap(mc)
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap(mc)
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
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

	node2IP := net.IPv4(3, 3, 3, 3)
	node2wCIDR := net.IPNet{
		IP:   natIP,
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}

	rtMap := routes.Map(mc)
	err = rtMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload, ip.FromNetIP(node2IP).(ip.V4Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	ctMap := conntrack.Map(mc)
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	hostIP = node1ip

	// Arriving at node but is rejected because of MTU, expect ICMP too big reply
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_UNSPEC"), "expected program to return TC_ACT_UNSPEC")

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPTooBig(pktR, ipv4, udp, natTunnelMTU)
	})

	// clean up
	resetCTMap(ctMap)
}

// TestNormalSYNRetryForcePolicy does the same test for forcing policy
// as TestNATSYNRetryGoesToSameBackend but without NAT.
func TestNormalSYNRetryForcePolicy(t *testing.T) {
	RegisterTestingT(t)

	defer func() { bpfIfaceName = "" }()
	bpfIfaceName = "SYN1"

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        true,
		DataOffset: 5,
	}

	_, ipv4, _, _, synPkt, err := testPacket(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})

	bpfIfaceName = "SYN2"
	explicitAllow := &polprog.Rules{
		Tiers: []polprog.Tier{{
			Name: "base tier",
			Policies: []polprog.Policy{{
				Name: "expAllow",
				Rules: []polprog.Rule{{
					Rule: &proto.Rule{
						Action:   "Allow",
						DstPorts: []*proto.PortRange{{First: 7890, Last: 7890}},
						DstNet:   []string{ipv4.DstIP.String()},
					}}},
			}},
		}},
	}

	// Make sure that policy still allows the retry (is enforce correctly)
	runBpfTest(t, "calico_from_workload_ep", explicitAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})

	bpfIfaceName = "SYN3"
	changedToDeny := &polprog.Rules{
		Tiers: []polprog.Tier{{
			Name: "base tier",
			Policies: []polprog.Policy{{
				Name: "allow->deny",
				Rules: []polprog.Rule{{
					Rule: &proto.Rule{
						Action:      "Allow",
						NotDstPorts: []*proto.PortRange{{First: 7890, Last: 7890}},
						NotDstNet:   []string{ipv4.DstIP.String()},
					}}},
			}},
		}},
	}

	// Make sure that when the policy changes, it is applied correctly to the next SYN
	runBpfTest(t, "calico_from_workload_ep", changedToDeny, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})
}

// TestNATSYNRetryGoesToSameBackend checks that SYN retries all go to the same backend.  I.e.
// that we conntrack SYN packets once they're past policy.  If we load balance each SYN independently
// then we run into trouble if the response SYN-ACK is lost.  In that case, the client can end up
// talking to two backends at the same time.
func TestNATSYNRetryGoesToSameBackend(t *testing.T) {
	RegisterTestingT(t)

	mc := &bpf.MapContext{}
	natMap := nat.FrontendMap(mc)
	err := natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap(mc)
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	ctMap := conntrack.Map(mc)
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        true,
		DataOffset: 5,
	}

	_, ipv4, _, _, synPkt, err := testPacket(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(tcpSyn.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0, 2, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	natIPs := []net.IP{net.IPv4(192, 0, 0, 1), net.IPv4(192, 0, 0, 2)}
	natPort := uint16(666)
	for i, natIP := range natIPs {
		err = natBEMap.Update(
			nat.NewNATBackendKey(0, uint32(i)).AsBytes(),
			nat.NewNATBackendValue(natIP, natPort).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	origTCPSrcPort := tcpSyn.SrcPort
	var firstIP net.IP

	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		// Part 1: if we resend the same SYN, then it should get conntracked to the same backend.
		for attempt := 0; attempt < 10; attempt++ {
			res, err := bpfrun(synPkt)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)
			ipv4L := pktR.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if attempt == 0 {
				firstIP = ipv4L.DstIP
			} else {
				Expect(ipv4L.DstIP).To(Equal(firstIP), "SYN retries should go to the same backend")
			}
		}

		// Part 2: If we vary the source port, we should hit both backends eventually.
		seenOtherIP := false
		for attempt := 0; attempt < 100; attempt++ {
			tcpSyn.SrcPort++
			_, _, _, _, synPkt, err := testPacket(nil, nil, tcpSyn, nil)
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(synPkt)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)
			ipv4L := pktR.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !firstIP.Equal(ipv4L.DstIP) {
				seenOtherIP = true
				break
			}
		}
		Expect(seenOtherIP).To(BeTrue(), "SYNs from varying source ports all went to same backend")
	})

	// Change back to the original SYN packet so that we can test the new policy
	// with an existing CT entry.
	tcpSyn.SrcPort = origTCPSrcPort
	_, _, _, _, synPkt, err = testPacket(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	bpfIfaceName = "SYNP"
	changedToDeny := &polprog.Rules{
		Tiers: []polprog.Tier{{
			Name: "base tier",
			Policies: []polprog.Policy{{
				Name: "allow->deny",
				Rules: []polprog.Rule{{
					Rule: &proto.Rule{
						Action:      "Allow",
						NotDstPorts: []*proto.PortRange{{First: 666, Last: 666}},
						NotDstNet:   []string{firstIP.String()}, // We should hit the same backend as before
					}}},
			}},
		}},
	}

	// Make sure that when the policy changes, it is applied correctly to the next SYN
	runBpfTest(t, "calico_from_workload_ep", changedToDeny, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})
}

func TestNATAffinity(t *testing.T) {
	RegisterTestingT(t)

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	mc := &bpf.MapContext{}
	natMap := nat.FrontendMap(mc)
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap(mc)
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natAffMap := nat.AffinityMap(mc)
	err = natAffMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	ctMap := conntrack.Map(mc)
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
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

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	// Check the no affinity entry exists if no affinity is set
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		aff, err := nat.LoadAffinityMap(natAffMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(aff).To(HaveLen(0))
	})

	// After we set affinity, new entry is acreated in affinity table
	natKey := nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol))
	err = natMap.Update(
		natKey.AsBytes(),
		nat.NewNATValue(0, 1, 0, 1 /* second */).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	dumpNATMap(natMap)
	resetCTMap(ctMap)

	var affEntry nat.AffinityValue
	affKey := nat.NewAffinityKey(ipv4.SrcIP, natKey)

	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		aff, err := nat.LoadAffinityMap(natAffMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(aff).To(HaveLen(1))
		Expect(aff).To(HaveKey(affKey))
		affEntry = aff[affKey]
		Expect(affEntry.Backend()).To(Equal(nat.NewNATBackendValue(natIP, natPort)))
	})
	resetCTMap(ctMap)

	// check that the selection is the same with a new entry to pick and the
	// entry is not overwritten (ts does not change)
	natIP2 := net.IPv4(7, 7, 7, 7)
	natPort2 := uint16(777)

	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0, 2, 0, 1 /* second */).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 1).AsBytes(),
		nat.NewNATBackendValue(natIP2, natPort2).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		aff, err := nat.LoadAffinityMap(natAffMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(aff).To(HaveLen(1))
		Expect(aff).To(HaveKey(affKey))
		Expect(aff[affKey]).To(Equal(affEntry))
	})
	resetCTMap(ctMap)

	// delete the currently selected backend, expire the affinity check and make
	// sure that a new selection in made
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0, 1, 0, 1 /* second */).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(natIP2, natPort2).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	err = natBEMap.Delete(nat.NewNATBackendKey(0, 1).AsBytes())
	Expect(err).NotTo(HaveOccurred())

	err = natAffMap.Update(
		affKey.AsBytes(),
		nat.NewAffinityValue(0, nat.NewNATBackendValue(natIP, natPort)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		aff, err := nat.LoadAffinityMap(natAffMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(aff).To(HaveLen(1))
		Expect(aff).To(HaveKey(affKey))
		affEntry = aff[affKey]
		Expect(affEntry.Backend()).To(Equal(nat.NewNATBackendValue(natIP2, natPort2)))
	})
	resetCTMap(ctMap)
}

func TestNATNodePortIngressDSR(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "DSR1"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, l4, payload, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)
	mc := &bpf.MapContext{}
	natMap := nat.FrontendMap(mc)
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap(mc)
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
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

	ctMap := conntrack.Map(mc)
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean
	defer resetCTMap(ctMap)

	hostIP = node1ip
	skbMark = 0

	// Setup routing
	rtMap := routes.Map(mc)
	err = rtMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload, ip.FromNetIP(node2ip).(ip.V4Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	dumpRTMap(rtMap)

	// Arriving at node 1
	runBpfTest(t, "calico_from_host_ep_dsr", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

		checkVxlanEncap(pktR, false, ipv4, udp, payload)
	})

	dumpCTMap(ctMap)

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	v, ok := ct[conntrack.NewKey(uint8(ipv4.Protocol), ipv4.SrcIP, uint16(udp.SrcPort), natIP.To4(), natPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack.FlagNATFwdDsr | conntrack.FlagNATNPFwd))
}

func TestNATSourceCollision(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "SPRT"
	defer func() { bpfIfaceName = "" }()
	resetCTMap(ctMap)

	// Setup node2 with backend pod such that conntrack has an active TCP
	// connection with which we will collide the next SYN.

	hostIP = node2ip
	skbMark = 0

	var err error

	podIP := net.IPv4(5, 0, 0, 1)
	podPort := uint16(1234)

	clientIP := net.IPv4(3, 2, 1, 0)
	clientPort := uint16(50555)

	tcpProto := uint8(6)
	nodeportPort := uint16(1122)

	node2wCIDR := net.IPNet{
		IP:   podIP,
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}

	// change the routing - it is a local workload now!
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalWorkload).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	dumpRTMap(rtMap)

	// we are at the node with local workload
	err = natMap.Update(
		nat.NewNATKey(node2ip, nodeportPort, tcpProto).AsBytes(),
		nat.NewNATValue(0 /* id */, 1 /* count */, 1 /* local */, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(podIP, podPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Create an active TCP conntrack entry pair
	ctKey := conntrack.NewKey(tcpProto, clientIP, clientPort, node1ip, nodeportPort)
	revKey := conntrack.NewKey(tcpProto, clientIP, clientPort, podIP, podPort)
	ctVal := conntrack.NewValueNATForward(0, 0, 0, revKey)
	revVal := conntrack.NewValueNATReverse(0, 0, 0,
		conntrack.Leg{
			Seqno:       12345,
			SynSeen:     true,
			AckSeen:     true,
			Whitelisted: true,
		},
		conntrack.Leg{
			Seqno:       7890,
			SynSeen:     true,
			AckSeen:     true,
			Whitelisted: true,
		},
		node1ip, node1ip, nodeportPort)

	_ = ctMap.Update(ctKey.AsBytes(), ctVal.AsBytes())
	_ = ctMap.Update(revKey.AsBytes(), revVal.AsBytes())

	dumpCTMap(ctMap)

	pktIPHdr := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    clientIP,
		DstIP:    node2ip,
		Protocol: layers.IPProtocolTCP,
	}

	pktTCPHdr := &layers.TCP{
		SrcPort:    layers.TCPPort(clientPort),
		DstPort:    layers.TCPPort(nodeportPort),
		SYN:        true,
		DataOffset: 5,
	}

	var recvPkt []byte

	_, _, _, _, pktBytes, _ := testPacket(nil, pktIPHdr, pktTCPHdr,
		[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 11, 22, 33, 44, 55, 66, 77, 88, 99, 0})

	skbMark = 0
	var newSPort uint16

	// Insert the reverse route for backend for RPF check.
	resetRTMap(rtMap)
	beV4CIDR := ip.CIDRFromNetIP(podIP).(ip.V4CIDR)
	bertKey := routes.NewKey(beV4CIDR).AsBytes()
	bertVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(bertKey, bertVal)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at node2 HEP
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())

		tcp := tcpL.(*layers.TCP)
		newSPort = uint16(tcp.SrcPort)
		Expect(newSPort).To(Equal(uint16(22222)))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(6 /* TCP */), clientIP, clientPort, node2ip, nodeportPort)

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))
		Expect(ctr.NATSPort()).To(Equal(newSPort))

		revKey = ctr.ReverseNATKey()
		Expect(revKey.AsBytes()).To(Equal(
			conntrack.NewKey(uint8(6 /* TCP */), clientIP, newSPort, podIP, podPort).AsBytes()))

		recvPkt = res.dataOut
	}, withPSNATPorts(22222, 22222))

	dumpCTMap(ctMap)

	hostIP = net.IPv4(0, 0, 0, 0) // workloads do not have it set

	skbMark = tcdefs.MarkSeen

	// Arriving at workload at node 2
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(recvPkt))
	})

	respPkt := tcpResponseRaw(recvPkt)
	skbMark = 0

	// Response leaving workload at node 2
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		Expect(res.dataOut).To(Equal(respPkt))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})

	// Response leaving node 2
	skbMark = tcdefs.MarkSeen // CALI_SKB_MARK_SEEN
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())

		tcp := tcpL.(*layers.TCP)
		Expect(uint16(tcp.DstPort)).To(Equal(clientPort))
	})

	pktTCPHdr.SYN = false
	pktTCPHdr.ACK = true
	pktTCPHdr.Seq = 1

	_, _, _, _, pktBytes, _ = testPacket(nil, pktIPHdr, pktTCPHdr,
		[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 11, 22, 33, 44, 55, 66, 77, 88, 99, 0})

	dumpCTMap(ctMap)

	skbMark = 0

	// Another packet arriving from client to HEP
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())

		tcp := tcpL.(*layers.TCP)
		Expect(uint16(tcp.SrcPort)).To(Equal(newSPort))

		recvPkt = res.dataOut
	})

	// Test random port conflict by sending another SYN packet. To avoid the
	// complexity of VXLAN encap in the test, send it with a different node IP,
	// which in fact mimics as if this node had 2 IPs. That is a realistic
	// scenario, but the main reason is to exercise the conflict after the
	// packet is unpacked and DNATed and that a retransmit eventually picks a
	// different port.

	node2ip2 := net.IPv4(10, 10, 1, 2).To4()
	// Create a NAT entry pointing to the same backend
	err = natMap.Update(
		nat.NewNATKey(node2ip2, nodeportPort, tcpProto).AsBytes(),
		nat.NewNATValue(0 /* id */, 1 /* count */, 1 /* local */, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	pktIPHdr = &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    clientIP,
		DstIP:    node2ip2,
		Protocol: layers.IPProtocolTCP,
	}

	pktTCPHdr = &layers.TCP{
		SrcPort:    layers.TCPPort(clientPort),
		DstPort:    layers.TCPPort(nodeportPort),
		SYN:        true,
		DataOffset: 5,
	}

	_, _, _, _, pktBytes, _ = testPacket(nil, pktIPHdr, pktTCPHdr,
		[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 11, 22, 33, 44, 55, 66, 77, 88, 99, 0})

	skbMark = 0

	// It must fail if we force the collision on the random port
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	}, withPSNATPorts(22222, 22222))

	// It should eventually succeed if we keep retransmitting and it is possible to pick
	// non-colliding port. TCP would retransmit a few times. linux retries 6 times by default with
	// 1s initial timeout https://sysctl-explorer.net/net/ipv4/tcp_syn_retries/
	Eventually(func() error {
		var res bpfRunResult

		runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
			var err error
			res, err = bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
		}, withPSNATPorts(22222, 22223))

		if res.Retval != resTC_ACT_UNSPEC {
			return fmt.Errorf("Unresolved collision")
		}

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())

		tcp := tcpL.(*layers.TCP)
		newSPort = uint16(tcp.SrcPort)
		if newSPort != uint16(22223) {
			return fmt.Errorf("Unexpected resolution port")
		}

		return nil
	}, "120s").Should(Succeed())
}
