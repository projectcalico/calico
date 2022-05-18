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

	"github.com/projectcalico/calico/felix/bpf/nat"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

func TestICMPPortUnreachable(t *testing.T) {
	RegisterTestingT(t)

	_, ipv4, _, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())

	runBpfUnitTest(t, "icmp_port_unreachable.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(0))

		Expect(res.dataOut).To(HaveLen(134)) // eth + ip + 64 + udp + ip + icmp

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPPortUnreachable(pktR, ipv4)
	})

}

func TestNATNoBackendFromHEP(t *testing.T) {
	RegisterTestingT(t)

	iphdr := *ipv4Default

	_, ipv4, l4, _, pktBytes, err := testPacket(nil, &iphdr, nil, nil)
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
