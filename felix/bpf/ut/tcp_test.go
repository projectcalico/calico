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
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

func TestTCPRecycleClosedConn(t *testing.T) {
	RegisterTestingT(t)

	defer func() { bpfIfaceName = "" }()
	bpfIfaceName = "REC1"

	resetCTMap(ctMap) // ensure it is clean

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        true,
		DataOffset: 5,
	}

	_, _, _, _, synPkt, err := testPacket(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})
	expectMark(tcdefs.MarkSeen)

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(1))

	var (
		ctKey conntrack.Key
		ctVal conntrack.Value
	)

	for ctKey, ctVal = range ct {
		// Get the only k,v in the map
	}

	v := ctVal.Data()
	v.A2B.FinSeen = true
	v.A2B.AckSeen = true
	v.A2B.Opener = true
	ctVal.SetLegA2B(v.A2B)
	v.B2A.FinSeen = true
	v.B2A.AckSeen = true
	v.B2A.Opener = true
	ctVal.SetLegB2A(v.B2A)

	fmt.Printf("ctVal = %+v\n", ctVal)

	_ = ctMap.Update(ctKey.AsBytes(), ctVal.AsBytes())

	bpfIfaceName = "REC2"
	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})
	expectMark(tcdefs.MarkSeen)

	ct, err = conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(1))

	for ctKey, ctVal = range ct {
		// Get the only k,v in the map
	}

	v = ctVal.Data()
	Expect(v.A2B.FinSeen).To(BeFalse())
	Expect(v.B2A.FinSeen).To(BeFalse())
}

func TestTCPRecycleClosedConnNAT(t *testing.T) {
	RegisterTestingT(t)

	defer func() { bpfIfaceName = "" }()
	bpfIfaceName = "Rec1"

	resetCTMap(ctMap) // ensure it is clean

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        true,
		DataOffset: 5,
	}

	_, ipv4, l4, _, synPkt, err := testPacket(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())
	tcp := l4.(*layers.TCP)

	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(tcp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
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
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})
	expectMark(tcdefs.MarkSeen)

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(2))

	var (
		ctKey conntrack.Key
		ctVal conntrack.Value
	)

	for ctKey, ctVal = range ct {
		if ctVal.Type() == conntrack.TypeNATReverse {
			break
		}
	}

	v := ctVal.Data()
	v.A2B.FinSeen = true
	v.A2B.AckSeen = true
	v.A2B.Opener = true
	ctVal.SetLegA2B(v.A2B)
	v.B2A.FinSeen = true
	v.B2A.AckSeen = true
	v.B2A.Opener = true
	ctVal.SetLegB2A(v.B2A)

	fmt.Printf("ctVal = %+v\n", ctVal)

	_ = ctMap.Update(ctKey.AsBytes(), ctVal.AsBytes())

	skbMark = 0
	bpfIfaceName = "Rec2"
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})
	expectMark(tcdefs.MarkSeen)

	ct, err = conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveLen(2))

	for ctKey, ctVal = range ct {
		if ctVal.Type() == conntrack.TypeNATReverse {
			break
		}
	}

	v = ctVal.Data()
	Expect(v.A2B.FinSeen).To(BeFalse())
	Expect(v.B2A.FinSeen).To(BeFalse())
}
