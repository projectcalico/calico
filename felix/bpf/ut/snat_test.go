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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
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
	eth, ipv4, l4, payload, pktBytes, err := testPacket(nil, ipHdr, nil, nil)
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

	// From host via bpfnat - first packet - conntrack miss
	runBpfTest(t, "calico_from_nat_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4Nat := *ipv4
		ipv4Nat.DstIP = natIP
		ipv4Nat.SrcIP = hostIP

		udpNat := *udp
		udpNat.DstPort = layers.UDPPort(natPort)
		udpNat.SrcPort = layers.UDPPort(10101)

		// created the expected packet after NAT, with recalculated csums
		_, _, _, _, resPktBytes, err := testPacket(eth, &ipv4Nat, &udpNat, payload)
		Expect(err).NotTo(HaveOccurred())

		// expect them to be the same
		Expect(res.dataOut).To(Equal(resPktBytes))

		pktBytes = res.dataOut
	})

	skbMark = tcdefs.MarkSeen | tcdefs.MarkSeenFromNatIfaceOut | tcdefs.MarkSeenBypassSkipRPF

	dumpCTMap(ctMap)

	// Out via host iface. We shoul duse a L3 tunnel, but that is not supported
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
	eth, ipv4, l4, payload, pktBytes, err = testPacket(nil, ipHdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0

	runBpfTest(t, "calico_from_nat_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4Nat := *ipv4
		ipv4Nat.DstIP = natIP
		ipv4Nat.SrcIP = hostIP

		udpNat := *udp
		udpNat.DstPort = layers.UDPPort(natPort)
		udpNat.SrcPort = layers.UDPPort(10101)

		// created the expected packet after NAT, with recalculated csums
		_, _, _, _, resPktBytes, err := testPacket(eth, &ipv4Nat, &udpNat, payload)
		Expect(err).NotTo(HaveOccurred())

		// expect them to be the same
		Expect(res.dataOut).To(Equal(resPktBytes))

		pktBytes = res.dataOut
	})

	// Out via wg tunnel (to intruduce ct entries)

	skbMark = tcdefs.MarkSeen | tcdefs.MarkSeenFromNatIfaceOut | tcdefs.MarkSeenBypassSkipRPF

	runBpfTest(t, "calico_to_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		Expect(res.dataOut).To(Equal(pktBytes))
	})

	// Return path

	skbMark = 0

	runBpfTest(t, "calico_from_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		respPkt := udpResponseRaw(pktBytes)
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipResp := *ipHdr
		ipResp.SrcIP, ipResp.DstIP = ipResp.DstIP, ipResp.SrcIP

		udpResp := *udp
		udpResp.DstPort, udpResp.SrcPort = udpResp.SrcPort, udpResp.DstPort

		ethResp := *eth
		ethResp.SrcMAC, ethResp.DstMAC = ethResp.DstMAC, ethResp.SrcMAC

		// created the expected packet after NAT, with recalculated csums
		_, _, _, _, resPktBytes, err := testPacket(&ethResp, &ipResp, &udpResp, payload)
		Expect(err).NotTo(HaveOccurred())

		// expect them to be the same
		Expect(res.dataOut).To(Equal(resPktBytes))
	})
}
