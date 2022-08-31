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
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

func TestICMPttlExceeded(t *testing.T) {
	RegisterTestingT(t)

	_, ipv4, _, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())

	runBpfUnitTest(t, "icmp_ttl_exceeded.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(0))

		Expect(res.dataOut).To(HaveLen(134)) // eth + ip + 64 + udp + ip + icmp

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPttlExceeded(pktR, ipv4)
	})

}

func TestICMPttlExceededFromHEP(t *testing.T) {
	RegisterTestingT(t)

	iphdr := *ipv4Default
	iphdr.TTL = 1

	_, ipv4, l4, _, pktBytes, err := testPacket(nil, &iphdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	udp := l4.(*layers.UDP)

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

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_UNSPEC"), "expected program to return TC_ACT_UNSPEC")

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPttlExceeded(pktR, ipv4)
	})
	expectMark(tcdefs.MarkSeenBypassForward)

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		// Insert a reverse route for the source workload.
		rtKey := routes.NewKey(srcV4CIDR).AsBytes()
		rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
		err = rtMap.Update(rtKey, rtVal)
		defer func() {
			err := rtMap.Delete(rtKey)
			Expect(err).NotTo(HaveOccurred())
		}()
		Expect(err).NotTo(HaveOccurred())

		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_UNSPEC"), "expected program to return TC_ACT_UNSPEC")

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPttlExceeded(pktR, ipv4)
	})
	expectMark(tcdefs.MarkSeenBypassForward)
}

func checkICMPttlExceeded(pktR gopacket.Packet, ipv4 *layers.IPv4) {
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
			layers.ICMPv4TypeTimeExceeded,
			layers.ICMPv4CodeTTLExceeded,
		)))
}
