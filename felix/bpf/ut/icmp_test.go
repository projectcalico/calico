// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

func TestICMPCTPlain(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()

	bpfIfaceName = "ICCT"

	icmpEcho := makeICMPEcho(node1ip, srcIP, 8 /* Echo Request*/) // ping

	// Workload route for RPF check
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	defer resetRTMap(rtMap)
	err := rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	dumpRTMap(rtMap)

	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpEcho)
		Expect(err).NotTo(HaveOccurred())
		// there is no normal CT record yet, must be denied
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		dumpCTMap(ctMap)

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		for k := range ct {
			Expect(k.PortA()).To(Equal(uint16(0)))
			Expect(k.PortB()).To(Equal(uint16(0)))
		}
	})

	icmpEcho = makeICMPEcho(srcIP, node1ip, 0 /* Echo Reply */) // pong

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpEcho)
		Expect(err).NotTo(HaveOccurred())
		// there is no normal CT record yet, must be denied
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		dumpCTMap(ctMap)

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		for k := range ct {
			Expect(k.PortA()).To(Equal(uint16(0)))
			Expect(k.PortB()).To(Equal(uint16(0)))
		}
	})
	expectMark(tcdefs.MarkSeen)
}

func makeICMPEcho(src, dst net.IP, icmpType uint8) []byte {
	payload := make([]byte, 64)

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
		SrcIP:    src,
		DstIP:    dst,
		Protocol: layers.IPProtocolICMPv4,
		Length:   uint16(20 + 8 + len(payload)),
	}

	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(icmpType, 0),
	}

	pkt := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
		eth, ipv4, icmp, gopacket.Payload(payload))
	Expect(err).NotTo(HaveOccurred())

	return pkt.Bytes()
}
