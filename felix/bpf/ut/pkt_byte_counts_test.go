// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
	"testing"

	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

func TestCountsPodPodXNode(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "CNT1"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, udpL, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := udpL.(*layers.UDP)

	resetCTMap(ctMap) // ensure it is clean
	resetMap(natMap)

	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	var pktOut []byte

	countTX := 3
	countRX := 5

	k := conntrack.NewKey(17, ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))

	for i := 1; i <= countTX; i++ {
		skbMark = 0
		// Leaving workload
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktOut = res.dataOut
		})

		dumpCTMap(ctMap)

		// Check that the values are set correctly.
		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v := ct[k]
		e := v.Data()

		Expect(e.A2B.Packets).To(Equal(uint32(i)))
		Expect(e.A2B.Bytes).To(Equal(uint64(i * len(pktBytes))))
		Expect(e.B2A.Packets).To(Equal(uint32(0)))
		Expect(e.B2A.Bytes).To(Equal(uint64(0)))

		// Leaving node 1
		skbMark = tcdefs.MarkSeen // CALI_SKB_MARK_SEEN

		runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktOut)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktOut = res.dataOut
		})

		dumpCTMap(ctMap)

		// Now check the the second program did not change the values - accounted for just once!
		ct, err = conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v = ct[k]
		e = v.Data()

		Expect(e.A2B.Packets).To(Equal(uint32(i)))
		Expect(e.A2B.Bytes).To(Equal(uint64(i * len(pktBytes))))
		Expect(e.B2A.Packets).To(Equal(uint32(0)))
		Expect(e.B2A.Bytes).To(Equal(uint64(0)))
	}

	respPkt := udpResponseRaw(pktBytes)

	for i := 1; i <= countRX; i++ {
		skbMark = 0
		// Response arriving on the node
		runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(respPkt)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktOut = res.dataOut
		})

		dumpCTMap(ctMap)

		// Check that the values are set correctly.
		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v := ct[k]
		e := v.Data()

		Expect(e.A2B.Packets).To(Equal(uint32(countTX)))
		Expect(e.A2B.Bytes).To(Equal(uint64(countTX * len(pktBytes))))
		Expect(e.B2A.Packets).To(Equal(uint32(i)))
		Expect(e.B2A.Bytes).To(Equal(uint64(i * len(respPkt))))

		// Response arriving at the workload
		skbMark = tcdefs.MarkSeen // CALI_SKB_MARK_SEEN

		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktOut)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktOut = res.dataOut
		})

		dumpCTMap(ctMap)

		// Now check the the second program did not change the values - accounted for just once!
		ct, err = conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v = ct[k]
		e = v.Data()

		Expect(e.A2B.Packets).To(Equal(uint32(countTX)))
		Expect(e.A2B.Bytes).To(Equal(uint64(countTX * len(pktBytes))))
		Expect(e.B2A.Packets).To(Equal(uint32(i)))
		Expect(e.B2A.Bytes).To(Equal(uint64(i * len(respPkt))))
	}
}

func TestCountsPodPodSameNode(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "CNT2"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, udpL, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := udpL.(*layers.UDP)

	resetCTMap(ctMap) // ensure it is clean
	resetMap(natMap)

	defer resetRTMap(rtMap)

	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	var pktOut []byte

	countTX := 3
	countRX := 5

	k := conntrack.NewKey(17, ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))

	for i := 1; i <= countTX; i++ {
		skbMark = 0
		// Leaving workload
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktOut = res.dataOut
		})

		dumpCTMap(ctMap)

		// Check that the values are set correctly.
		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v := ct[k]
		e := v.Data()

		Expect(e.A2B.Packets).To(Equal(uint32(i)))
		Expect(e.A2B.Bytes).To(Equal(uint64(i * len(pktBytes))))
		Expect(e.B2A.Packets).To(Equal(uint32(0)))
		Expect(e.B2A.Bytes).To(Equal(uint64(0)))

		// Leaving node 1
		skbMark = tcdefs.MarkSeen // CALI_SKB_MARK_SEEN

		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktOut)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktOut = res.dataOut
		})

		dumpCTMap(ctMap)

		// Now check the the second program did not change the values - accounted for just once!
		ct, err = conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v = ct[k]
		e = v.Data()

		Expect(e.A2B.Packets).To(Equal(uint32(i)))
		Expect(e.A2B.Bytes).To(Equal(uint64(i * len(pktBytes))))
		Expect(e.B2A.Packets).To(Equal(uint32(0)))
		Expect(e.B2A.Bytes).To(Equal(uint64(0)))
	}

	respPkt := udpResponseRaw(pktBytes)

	for i := 1; i <= countRX; i++ {
		skbMark = 0
		// Response arriving on the node
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(respPkt)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktOut = res.dataOut
		})

		dumpCTMap(ctMap)

		// Check that the values are set correctly.
		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v := ct[k]
		e := v.Data()

		Expect(e.A2B.Packets).To(Equal(uint32(countTX)))
		Expect(e.A2B.Bytes).To(Equal(uint64(countTX * len(pktBytes))))
		Expect(e.B2A.Packets).To(Equal(uint32(i)))
		Expect(e.B2A.Bytes).To(Equal(uint64(i * len(respPkt))))

		// Response arriving at the workload
		skbMark = tcdefs.MarkSeen // CALI_SKB_MARK_SEEN

		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktOut)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktOut = res.dataOut
		})

		dumpCTMap(ctMap)

		// Now check the the second program did not change the values - accounted for just once!
		ct, err = conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v = ct[k]
		e = v.Data()

		Expect(e.A2B.Packets).To(Equal(uint32(countTX)))
		Expect(e.A2B.Bytes).To(Equal(uint64(countTX * len(pktBytes))))
		Expect(e.B2A.Packets).To(Equal(uint32(i)))
		Expect(e.B2A.Bytes).To(Equal(uint64(i * len(respPkt))))
	}
}

func TestCountsHostPodSameNode(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "CNT3"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, udpL, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := udpL.(*layers.UDP)

	resetCTMap(ctMap) // ensure it is clean
	resetMap(natMap)

	defer resetRTMap(rtMap)

	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalHost, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	countTX := 3
	countRX := 5

	k := conntrack.NewKey(17, ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))

	for i := 1; i <= countTX; i++ {
		skbMark = 0
		// Leaving workload
		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		}, withFromHost())

		dumpCTMap(ctMap)

		// Check that the values are set correctly.
		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v := ct[k]
		e := v.Data()

		Expect(e.A2B.Packets).To(Equal(uint32(i)))
		Expect(e.A2B.Bytes).To(Equal(uint64(i * len(pktBytes))))
		Expect(e.B2A.Packets).To(Equal(uint32(0)))
		Expect(e.B2A.Bytes).To(Equal(uint64(0)))
	}

	respPkt := udpResponseRaw(pktBytes)

	for i := 1; i <= countRX; i++ {
		skbMark = 0
		// Response arriving on the node
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(respPkt)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		})

		dumpCTMap(ctMap)

		// Check that the values are set correctly.
		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v := ct[k]
		e := v.Data()

		Expect(e.A2B.Packets).To(Equal(uint32(countTX)))
		Expect(e.A2B.Bytes).To(Equal(uint64(countTX * len(pktBytes))))
		Expect(e.B2A.Packets).To(Equal(uint32(i)))
		Expect(e.B2A.Bytes).To(Equal(uint64(i * len(respPkt))))
	}
}

func TestCountsHostToOutside(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "CNT4"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, udpL, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := udpL.(*layers.UDP)

	resetCTMap(ctMap) // ensure it is clean
	resetMap(natMap)

	defer resetRTMap(rtMap)

	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalHost, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	countTX := 3
	countRX := 5

	k := conntrack.NewKey(17, ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))

	for i := 1; i <= countTX; i++ {
		skbMark = 0
		// Leaving workload
		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC), "BPF program returned unexpected result")
		}, withFromHost()) // XXX temp fix to make it pass until BPF-1887 gets fixed

		dumpCTMap(ctMap)

		// Check that the values are set correctly.
		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v := ct[k]
		e := v.Data()

		Expect(e.A2B.Packets).To(Equal(uint32(i)), "Incorrect A->B packet count")
		Expect(e.A2B.Bytes).To(Equal(uint64(i*len(pktBytes))), "Incorrect A->B bytes count")
		Expect(e.B2A.Packets).To(Equal(uint32(0)), "Incorrect B->A packet count")
		Expect(e.B2A.Bytes).To(Equal(uint64(0)), "Incorrect B->A bytes count")
	}

	respPkt := udpResponseRaw(pktBytes)

	for i := 1; i <= countRX; i++ {
		skbMark = 0
		// Response arriving on the node
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(respPkt)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC), "BPF program returned unexpected result")
		})

		dumpCTMap(ctMap)

		// Check that the values are set correctly.
		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v := ct[k]
		e := v.Data()

		Expect(e.A2B.Packets).To(Equal(uint32(countTX)))
		Expect(e.A2B.Bytes).To(Equal(uint64(countTX * len(pktBytes))))
		Expect(e.B2A.Packets).To(Equal(uint32(i)))
		Expect(e.B2A.Bytes).To(Equal(uint64(i * len(respPkt))))
	}
}
