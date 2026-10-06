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

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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

	_, _, _, _, synPkt, err := testPacketV4(nil, nil, tcpSyn, nil)
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
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
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
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
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

	_, ipv4, l4, _, synPkt, err := testPacketV4(nil, nil, tcpSyn, nil)
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
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
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
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
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

// TestTCPRecycleClosedNATReverse covers a SYN that reaches a closed NAT reverse
// entry without passing its forward entry: the pod connects straight to the
// backend from the same source port it used for a closed service connection.
func TestTCPRecycleClosedNATReverse(t *testing.T) {
	RegisterTestingT(t)

	defer func() { bpfIfaceName = "" }()
	bpfIfaceName = "RcR1"

	resetCTMap(ctMap)
	defer resetCTMap(ctMap)

	natIP := net.IPv4(8, 8, 8, 8).To4()
	natPort := uint16(666)

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        true,
		DataOffset: 5,
	}

	_, ipv4, l4, _, svcSynPkt, err := testPacketV4(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())
	tcp := l4.(*layers.TCP)
	svcIP := ipv4.DstIP

	err = natMap.Update(
		nat.NewNATKey(svcIP, uint16(tcp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0, 1, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	defer resetMap(natMap)
	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	defer resetMap(natBEMap)

	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	defer resetRTMap(rtMap)
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())

	fwdKey := conntrack.NewKey(uint8(ipv4.Protocol), srcIP, 54321, svcIP, 7890)
	revKey := conntrack.NewKey(uint8(ipv4.Protocol), srcIP, 54321, natIP, natPort)

	// Open the service connection, then close it in both directions.
	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(svcSynPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
	})

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveKey(fwdKey))
	Expect(ct).To(HaveKey(revKey))
	revVal := ct[revKey]
	Expect(revVal.Type()).To(Equal(conntrack.TypeNATReverse))

	v := revVal.Data()
	v.A2B.FinSeen = true
	v.A2B.AckSeen = true
	revVal.SetLegA2B(v.A2B)
	v.B2A.FinSeen = true
	v.B2A.AckSeen = true
	revVal.SetLegB2A(v.B2A)
	Expect(ctMap.Update(revKey.AsBytes(), revVal.AsBytes())).NotTo(HaveOccurred())

	// A new SYN straight to the backend recycles the closed reverse entry.
	directIP := *ipv4Default
	directIP.DstIP = natIP
	directSyn := *tcpSyn
	directSyn.DstPort = layers.TCPPort(natPort)
	_, _, _, _, directSynPkt, err := testPacketV4(nil, &directIP, &directSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	bpfIfaceName = "RcR2"
	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(directSynPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
	})

	ct, err = conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(HaveKey(revKey))
	Expect(ct[revKey].Type()).To(Equal(conntrack.TypeNormal),
		"the SYN must open a new connection, not reuse the closed NAT reverse entry")
	Expect(ct[revKey].Data().FINsSeen()).To(BeFalse())
	newConn := ct[revKey]

	// The old forward entry now names the new connection's key. A packet on the
	// old service tuple must drop it rather than be tracked as the new connection.
	svcAck := *tcpSyn
	svcAck.SYN = false
	svcAck.ACK = true
	_, _, _, _, svcAckPkt, err := testPacketV4(nil, nil, &svcAck, nil)
	Expect(err).NotTo(HaveOccurred())

	bpfIfaceName = "RcR3"
	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(svcAckPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	ct, err = conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).NotTo(HaveKey(fwdKey))
	Expect(ct).To(HaveKeyWithValue(revKey, newConn))
}
