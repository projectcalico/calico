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

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	ctv4 "github.com/projectcalico/calico/felix/bpf/conntrack/v4"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/ip"
)

func TestSNATHostServiceRemotePod(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "SNAT"
	defer func() { bpfIfaceName = "" }()

	ipHdr := ipv4Default
	ipHdr.Id = 1
	eth, ipv4, l4, payload, pktBytes, err := testPacketV4(nil, ipHdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	natMap := nat.FrontendMap()
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap()
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

	ctMap := conntrack.Map()
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	//	var natedPkt []byte

	hostIP = node1ip

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	// Insert route to the destination
	destCIDR := net.IPNet{
		IP:   natIP,
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&destCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(
			routes.FlagsRemoteWorkload|routes.FlagTunneled,
			ip.FromNetIP(node2ip).(ip.V4Addr),
		).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	// From host via bpfnat - first packet - conntrack miss
	runBpfTest(t, "calico_from_nat_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4Nat := *ipv4
		ipv4Nat.DstIP = natIP
		ipv4Nat.SrcIP = ipv4.SrcIP

		udpNat := *udp
		udpNat.DstPort = layers.UDPPort(natPort)

		// created the expected packet after NAT, with recalculated csums
		_, _, _, _, resPktBytes, err := testPacketV4(eth, &ipv4Nat, &udpNat, payload)
		Expect(err).NotTo(HaveOccurred())

		// expect them to be the same
		Expect(res.dataOut).To(Equal(resPktBytes))

		pktBytes = res.dataOut
	})

	expectMark(tcdefs.MarkSeen | tcdefs.MarkSeenFromNatIfaceOut)

	dumpCTMap(ctMap)

	// Out via host iface. We should use an L3 tunnel, but that is not supported
	// by the test infra. Host interface does pretty much the same for what we
	// need. It creates extra CT entries of type 0.
	runBpfTest(t, "calico_to_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		Expect(res.dataOut).To(Equal(pktBytes))
	})

	dumpCTMap(ctMap)

	// Second packet - conntrack hit

	ipHdr.Id = 2
	eth, ipv4, _, payload, pktBytes, err = testPacketV4(nil, ipHdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0

	runBpfTest(t, "calico_from_nat_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4Nat := *ipv4
		ipv4Nat.DstIP = natIP
		ipv4Nat.SrcIP = ipv4.SrcIP

		udpNat := *udp
		udpNat.DstPort = layers.UDPPort(natPort)

		// created the expected packet after NAT, with recalculated csums
		_, _, _, _, resPktBytes, err := testPacketV4(eth, &ipv4Nat, &udpNat, payload)
		Expect(err).NotTo(HaveOccurred())

		// expect them to be the same
		Expect(res.dataOut).To(Equal(resPktBytes))

		pktBytes = res.dataOut
	})

	// Out via wg tunnel (to introduce ct entries)

	expectMark(tcdefs.MarkSeen | tcdefs.MarkSeenFromNatIfaceOut)

	var hostConflictPkt []byte

	runBpfTest(t, "calico_to_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		Expect(res.dataOut).To(Equal(pktBytes))

		hostConflictPkt = res.dataOut
	})

	// Return path

	skbMark = 0

	runBpfTest(t, "calico_from_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		respPkt := udpResponseRaw(pktBytes)
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipResp := *ipHdr
		ipResp.SrcIP, ipResp.DstIP = ipResp.DstIP, ipResp.SrcIP

		udpResp := *udp
		udpResp.DstPort, udpResp.SrcPort = udpResp.SrcPort, udpResp.DstPort

		ethResp := *eth
		ethResp.SrcMAC, ethResp.DstMAC = ethResp.DstMAC, ethResp.SrcMAC

		// created the expected packet after NAT, with recalculated csums
		_, _, _, _, resPktBytes, err := testPacketV4(&ethResp, &ipResp, &udpResp, payload)
		Expect(err).NotTo(HaveOccurred())

		// expect them to be the same
		Expect(res.dataOut).To(Equal(resPktBytes))
	})

	dumpCTMap(ctMap)

	// A packet from host that conflicts with the SNATed connection via service.

	var hostConflictPktAfterSNAT []byte

	skbMark = 0
	runBpfTest(t, "calico_to_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(hostConflictPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Or(Equal(resTC_ACT_UNSPEC), Equal(resTC_ACT_REDIRECT)))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)

		Expect(udpR.SrcPort).To(Equal(layers.UDPPort(22222)))

		hostConflictPktAfterSNAT = res.dataOut
	}, withPSNATPorts(22222, 22222), withHostNetworked())

	dumpCTMap(ctMap)

	// A follow up packet

	skbMark = 0
	runBpfTest(t, "calico_to_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(hostConflictPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Or(Equal(resTC_ACT_UNSPEC), Equal(resTC_ACT_REDIRECT)))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(hostConflictPktAfterSNAT))
	}, withPSNATPorts(22222, 22222), withHostNetworked())

	// Return path

	skbMark = 0

	runBpfTest(t, "calico_from_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		respPkt := udpResponseRaw(hostConflictPktAfterSNAT)
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)

		Expect(udpR.SrcPort).To(Equal(layers.UDPPort(natPort)))
		Expect(udpR.DstPort).To(Equal(udpDefault.SrcPort))
	}, withPSNATPorts(22222, 22222))
}

// TestSNATHostRecycledNATReverseNoConflict checks that a host SYN that recycles
// a closed service connection's reverse entry does not inherit its VIA_NAT_IF
// flag, which would send it through host source-port conflict resolution.
func TestSNATHostRecycledNATReverseNoConflict(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "SNRc"
	defer func() { bpfIfaceName = "" }()

	ctMap := conntrack.Map()
	Expect(ctMap.EnsureExists()).NotTo(HaveOccurred())
	resetCTMap(ctMap)
	defer resetCTMap(ctMap)

	hostIP = node1ip
	natIP := net.IPv4(8, 8, 8, 8).To4()
	natPort := uint16(666)
	srcPort := uint16(54321)

	destCIDR := net.IPNet{IP: natIP, Mask: net.IPv4Mask(255, 255, 255, 0)}
	defer resetRTMap(rtMap)
	Expect(rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&destCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload|routes.FlagTunneled,
			ip.FromNetIP(node2ip).(ip.V4Addr)).AsBytes(),
	)).NotTo(HaveOccurred())

	// A closed host->service connection that went via the NAT interface.
	revKey := conntrack.NewKey(conntrack.ProtoTCP, srcIP, srcPort, natIP, natPort)
	closedRev := conntrack.NewValueNATReverse(0, ctv4.FlagViaNATIf,
		conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true, Opener: true, Approved: true},
		conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true, Approved: true},
		nil, net.IPv4(10, 96, 0, 1), 80)
	Expect(ctMap.Update(revKey.AsBytes(), closedRev.AsBytes())).NotTo(HaveOccurred())

	// The host now connects straight to the backend from the same port.
	ipHdr := *ipv4Default
	ipHdr.DstIP = natIP
	ipHdr.Protocol = layers.IPProtocolTCP
	tcpSyn := &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(natPort),
		SYN:        true,
		DataOffset: 5,
	}
	_, _, _, _, synPkt, err := testPacketV4(nil, &ipHdr, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_to_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Or(Equal(resTC_ACT_UNSPEC), Equal(resTC_ACT_REDIRECT)))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())
		Expect(tcpL.(*layers.TCP).SrcPort).To(Equal(layers.TCPPort(srcPort)),
			"a new connection must not be source-NATed around the connection it replaced")
	}, withPSNATPorts(22222, 22222), withHostNetworked())

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveKey(revKey))
	Expect(ct[revKey].Type()).To(Equal(conntrack.TypeNormal))
}
