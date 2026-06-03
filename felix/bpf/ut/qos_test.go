// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	ctv4 "github.com/projectcalico/calico/felix/bpf/conntrack/v4"
	"github.com/projectcalico/calico/felix/bpf/qos"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

// TestQoSPacketRate tests the BPF implementation of packet rate QoS controls. It
// sets ingress and egress limits of 1 packet per second and attempts to send/receive
// 2 packets, expecting one to be successful and one to be dropped.
func TestQoSPacketRate(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWvwl"
	defer func() { bpfIfaceName = "" }()
	_, _, _, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())

	ctMap := conntrack.Map()
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean
	defer resetCTMap(ctMap)

	ifIndex := 1

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)

	// Populate QoS map
	resetQoSMap(qosMap)
	defer resetQoSMap(qosMap)
	key1 := qos.NewKey(uint32(ifIndex), 1, qos.IPFamilyV4)
	key2 := qos.NewKey(uint32(ifIndex), 0, qos.IPFamilyV4)
	value := qos.NewValue(1, 1, -1, 0, 0, 0)

	err = qosMap.Update(
		key1.AsBytes(),
		value.AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = qosMap.Update(
		key2.AsBytes(),
		value.AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Ingress, allow first packet, drop second (because of 1/sec limit)
	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		res, err = bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	}, withIngressQoSPacketRate())

	resetCTMap(ctMap) // ensure it is clean

	// Egress, allow first packet, drop second (because of 1/sec limit)
	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		res, err = bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	}, withEgressQoSPacketRate())
}

type dscpTestCase struct {
	progName        string
	expectedSKBMark uint32
	srcAddr         net.IP
	dstAddr         net.IP
	expectedRet     int
	inDSCP          int8
	expectedOutDSCP int8
}

func TestDSCPv4_WEP(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWvwl"
	defer func() { bpfIfaceName = "" }()

	ctMap := conntrack.Map()
	err := ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean
	defer resetCTMap(ctMap)

	ifIndex := 1

	externalAddr := net.IPv4(3, 3, 3, 3) // a new address that, based on route map, is outside cluster.

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)

	for _, tc := range []dscpTestCase{
		// Dest outside cluster.
		{"calico_from_workload_ep", 0, srcIP, externalAddr, resTC_ACT_REDIRECT, 16, 16},
		{"calico_to_workload_ep", tcdefs.MarkSeen, srcIP, externalAddr, resTC_ACT_UNSPEC, 20, -1},

		// Src outside cluster.
		{"calico_to_workload_ep", tcdefs.MarkSeen, externalAddr, dstIP, resTC_ACT_UNSPEC, 20, -1},

		// Src and dest both inside cluster.
		{"calico_from_workload_ep", 0, srcIP, dstIP, resTC_ACT_REDIRECT, 16, -1},
	} {
		skbMark = tc.expectedSKBMark
		runBpfTest(t, tc.progName, rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			testDSCP(bpfrun, tc, false)
		}, withEgressDSCP(tc.inDSCP))
		resetCTMap(ctMap) // ensure it is clean
	}
}

func TestDSCPv4_HEP(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWvwl"
	defer func() { bpfIfaceName = "" }()

	ctMap := conntrack.Map()
	err := ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean
	defer resetCTMap(ctMap)

	ifIndex := 1

	externalAddr := net.IPv4(3, 3, 3, 3) // a new address that, based on route map, is outside cluster.

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalHost, ifIndex).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsRemoteHost, ifIndex).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)

	for _, tc := range []dscpTestCase{
		// Dest outside cluster.
		{"calico_to_host_ep", tcdefs.MarkSeen, srcIP, externalAddr, resTC_ACT_UNSPEC, 8, 8},
		{"calico_from_host_ep", 0, dstIP, externalAddr, resTC_ACT_UNSPEC, 40, -1},

		// Src outside cluster.
		{"calico_to_host_ep", tcdefs.MarkSeen, externalAddr, srcIP, resTC_ACT_UNSPEC, 8, -1},
		{"calico_from_host_ep", 0, externalAddr, dstIP, resTC_ACT_UNSPEC, 40, -1},

		// Src and dest are both hosts.
		{"calico_to_host_ep", tcdefs.MarkSeen, srcIP, dstIP, resTC_ACT_UNSPEC, 8, 8},
	} {
		skbMark = tc.expectedSKBMark
		runBpfTest(t, tc.progName, rulesAllowUDP, func(bpfrun bpfProgRunFn) {
			testDSCP(bpfrun, tc, false)
		}, withEgressDSCP(tc.inDSCP))
		resetCTMap(ctMap) // ensure it is clean
	}
}

func TestDSCPv6_WEP(t *testing.T) {
	RegisterTestingT(t)
	hostIP = node1ipV6

	bpfIfaceName = "HWvwl"
	defer func() { bpfIfaceName = "" }()

	ctMap := conntrack.Map()
	err := ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean
	defer resetCTMap(ctMap)

	ifIndex := 1

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKeyV6(srcV6CIDR).AsBytes()
	rtVal := routes.NewValueV6WithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	err = rtMapV6.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	rtKey = routes.NewKeyV6(dstV6CIDR).AsBytes()
	rtVal = routes.NewValueV6WithIfIndex(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	err = rtMapV6.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMapV6)

	externalAddr := net.ParseIP("dead:cafe::1") // a new address that, based on route map, is outside cluster.

	for _, tc := range []dscpTestCase{
		// Dest outside cluster.
		{"calico_from_workload_ep", 0, srcIPv6, externalAddr, resTC_ACT_REDIRECT, 16, 16},
		{"calico_to_workload_ep", tcdefs.MarkSeen, srcIPv6, externalAddr, resTC_ACT_UNSPEC, 20, -1},

		// Src outside cluster.
		{"calico_to_workload_ep", tcdefs.MarkSeen, externalAddr, dstIPv6, resTC_ACT_UNSPEC, 20, -1},

		// Src and dest both inside cluster.
		{"calico_from_workload_ep", 0, srcIPv6, dstIPv6, resTC_ACT_REDIRECT, 16, -1},
	} {
		skbMark = tc.expectedSKBMark
		runBpfTest(t, tc.progName, rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			testDSCP(bpfrun, tc, true)
		}, withEgressDSCP(tc.inDSCP), withIPv6())
		resetCTMap(ctMap) // ensure it is clean
	}
}

func TestDSCPv6_HEP(t *testing.T) {
	RegisterTestingT(t)
	hostIP = node1ipV6

	bpfIfaceName = "HWvwl"
	defer func() { bpfIfaceName = "" }()

	ctMap := conntrack.Map()
	err := ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean
	defer resetCTMap(ctMap)

	ifIndex := 1

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKeyV6(srcV6CIDR).AsBytes()
	rtVal := routes.NewValueV6WithIfIndex(routes.FlagsLocalHost, ifIndex).AsBytes()
	err = rtMapV6.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	rtKey = routes.NewKeyV6(dstV6CIDR).AsBytes()
	rtVal = routes.NewValueV6WithIfIndex(routes.FlagsRemoteHost, ifIndex).AsBytes()
	err = rtMapV6.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMapV6)

	externalAddr := net.ParseIP("dead:cafe::1") // a new address that, based on route map, is outside cluster.

	for _, tc := range []dscpTestCase{
		// Dest outside cluster.
		{"calico_to_host_ep", tcdefs.MarkSeen, srcIPv6, externalAddr, resTC_ACT_UNSPEC, 8, 8},
		{"calico_from_host_ep", 0, dstIPv6, externalAddr, resTC_ACT_UNSPEC, 40, -1},

		// Src outside cluster.
		{"calico_to_host_ep", tcdefs.MarkSeen, externalAddr, dstIPv6, resTC_ACT_UNSPEC, 8, -1},
		{"calico_from_host_ep", 0, externalAddr, dstIPv6, resTC_ACT_UNSPEC, 40, -1},

		// Src and dest both hosts.
		{"calico_to_host_ep", tcdefs.MarkSeen, srcIPv6, dstIPv6, resTC_ACT_UNSPEC, 8, 8},
	} {
		skbMark = tc.expectedSKBMark
		runBpfTest(t, tc.progName, rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			testDSCP(bpfrun, tc, true)
		}, withEgressDSCP(tc.inDSCP), withIPv6())
		resetCTMap(ctMap) // ensure it is clean
	}
}

func testDSCP(bpfrun bpfProgRunFn, tc dscpTestCase, forIPv6 bool) {
	var (
		inPktBytes, expPktBytes []byte
		err                     error
	)

	if forIPv6 {
		ipv6Hdr := *ipv6Default
		ipv6Hdr.DstIP = tc.dstAddr
		ipv6Hdr.SrcIP = tc.srcAddr
		_, _, _, _, inPktBytes, err = testPacketV6(nil, &ipv6Hdr, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		if tc.expectedOutDSCP >= 0 {
			ipv6Hdr.TrafficClass = uint8(tc.expectedOutDSCP << 2) // DSCP (6bits) + ECN (2bits)
		}
		_, _, _, _, expPktBytes, err = testPacketV6(nil, &ipv6Hdr, nil, nil)
		Expect(err).NotTo(HaveOccurred())
	} else {
		ipv4Hdr := *ipv4Default
		ipv4Hdr.DstIP = tc.dstAddr
		ipv4Hdr.SrcIP = tc.srcAddr
		_, _, _, _, inPktBytes, err = testPacketV4(nil, &ipv4Hdr, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		if tc.expectedOutDSCP >= 0 {
			ipv4Hdr.TOS = uint8(tc.expectedOutDSCP) << 2 // DSCP (6bits) + ECN (2bits)
		}
		_, _, _, _, expPktBytes, err = testPacketV4(nil, &ipv4Hdr, nil, nil)
		Expect(err).NotTo(HaveOccurred())
	}

	res, err := bpfrun(inPktBytes)
	Expect(err).NotTo(HaveOccurred())

	Expect(res.Retval).To(Equal(tc.expectedRet))
	Expect(res.dataOut).To(HaveLen(len(expPktBytes)))
	Expect(res.dataOut).To(Equal(expPktBytes))
}

// TestQoSConnLimitEgressRecycleNotDoubleCounted verifies that when the BPF
// conntrack lookup recycles an existing CT entry (tcp_recycled path) and
// treats the new SYN as CT_NEW, the egress connection-limit counter does not
// double-count.
//
// Sub-case A exercises the "well-behaved" path where the close-time
// decrement already fired (CONNLIMIT_DEC set on the old entry): the recycle
// helper bails idempotently, the new SYN increments — net delta 0.
//
// Sub-case B exercises the "decrement-was-missed" path where the old entry
// was counted (CONNLIMIT_EGRESS set) but never decremented (CONNLIMIT_DEC
// NOT set): without the fix the counter would drift from 1 → 2, with the
// fix the recycle helper decrements (1 → 0) and then the new SYN
// re-increments (0 → 1).
func TestQoSConnLimitEgressRecycleNotDoubleCounted(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWcr"
	defer func() { bpfIfaceName = "" }()

	const (
		// ifIndex must match the BPF UT's default skb ifindex so the
		// workload RPF check (route iface vs skb iface) passes.
		// TestQoSPacketRate uses 1; same here.
		ifIndex               = 1
		maxConnections        = 3
		srcPort        uint16 = 12345
		dstPort        uint16 = 8055
	)

	// Routes (same shape as TestQoSPacketRate): local workload source,
	// remote workload destination.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())
	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)

	ctMap := conntrack.Map()
	Expect(ctMap.EnsureExists()).NotTo(HaveOccurred())

	// preloadCTEntry installs a recyclable NORMAL CT entry for the
	// (srcIP, srcPort, dstIP, dstPort) tuple this test uses. Both legs
	// carry fin_seen so tcp_recycled() returns true. The leg ifindex is
	// set on the opener leg (a) to match our pod interface, which is
	// where qos_connlimit_decrement_for_ct will read it from.
	preloadCTEntry := func(flags uint32) {
		legA := ctv4.Leg{SynSeen: true, AckSeen: true, FinSeen: true, Opener: true, Ifindex: ifIndex}
		legB := ctv4.Leg{SynSeen: true, AckSeen: true, FinSeen: true}
		// The CT key normalizes the A/B ordering; we use NewKey with
		// proto/IPs/ports in our tuple's source-first order — internal
		// normalization picks A and B based on src_lt_dest. The keys
		// the BPF program looks up must match exactly, so we use the
		// same constructor here that the BPF lookup uses logically.
		k := ctv4.NewKey(6, srcIP, srcPort, dstIP, dstPort)
		v := ctv4.NewValueNormal(time.Duration(0), flags, legA, legB)
		Expect(ctMap.Update(k.AsBytes(), v.AsBytes()[:])).NotTo(HaveOccurred())
	}

	// seedQoSCount populates the egress QoS map entry for ifIndex with
	// max=maxConnections and the given current_count.
	seedQoSCount := func(current uint32) {
		key := qos.NewKey(uint32(ifIndex), 0 /* egress */, qos.IPFamilyV4)
		// Packet-rate fields zero; max=maxConnections; current=current.
		v := qos.NewValue(0, 0, 0, 0, maxConnections, current)
		Expect(qosMap.Update(key.AsBytes(), v.AsBytes())).NotTo(HaveOccurred())
	}

	readQoSCount := func() uint32 {
		key := qos.NewKey(uint32(ifIndex), 0, qos.IPFamilyV4)
		b, err := qosMap.Get(key.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return qos.ValueFromBytes(b).CurrentCount()
	}

	// SYN packet from srcIP:srcPort → dstIP:dstPort.
	_, _, _, _, pktBytes, err := testPacketTCPV4WithPayload(dstIP, srcPort, dstPort, true /* syn */, nil)
	Expect(err).NotTo(HaveOccurred())

	t.Run("recycle of properly-closed entry: counter stays at 1", func(t *testing.T) {
		RegisterTestingT(t)
		resetCTMap(ctMap)
		resetQoSMap(qosMap)
		defer resetCTMap(ctMap)
		defer resetQoSMap(qosMap)

		// Close-time decrement already fired on the old entry, leaving
		// CONNLIMIT_DEC set and the QoS counter at 0.
		preloadCTEntry(ctv4.FlagConnLimitOut | ctv4.FlagConnLimitDec)
		seedQoSCount(0)

		// Run the from_wep program. Because there's a matching CT
		// entry in the "fin both sides" state, calico_ct_lookup hits
		// tcp_recycled, deletes the entry, and falls through to
		// CT_NEW; new_flow_entrypoint then runs and increments.
		skbMark = 0
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
		}, withEgressQoSConnLimit())

		// Net delta: 0 → 1. Recycle helper bails on CONNLIMIT_DEC; new
		// SYN increments to 1.
		Expect(readQoSCount()).To(Equal(uint32(1)))
	})

	t.Run("recycle of never-decremented entry: counter stays at 1, not 2", func(t *testing.T) {
		RegisterTestingT(t)
		resetCTMap(ctMap)
		resetQoSMap(qosMap)
		defer resetCTMap(ctMap)
		defer resetQoSMap(qosMap)

		// Old entry was counted at SYN time (CONNLIMIT_EGRESS set) but
		// never decremented (CONNLIMIT_DEC NOT set). QoS counter is at
		// 1, reflecting the leaked count.
		preloadCTEntry(ctv4.FlagConnLimitOut)
		seedQoSCount(1)

		skbMark = 0
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
		}, withEgressQoSConnLimit())

		// With the fix: recycle helper sets CONNLIMIT_DEC and
		// decrements 1 → 0; new_flow_entrypoint then increments 0 → 1.
		// Without the fix: 1 + 1 = 2 (drift).
		Expect(readQoSCount()).To(Equal(uint32(1)))
	})
}

// TestQoSConnLimitIngressRetransmissionOfRejectedStillOverLimit verifies that
// when a SYN retransmission arrives at to-wep for a connection that was
// previously rejected (CT entry carries CONNLIMIT_INGRESS_REJECTED) AND the
// counter is still at the limit, the BPF dataplane:
//
//   - re-runs qos_connlimit_check_and_increment, which fails because the
//     counter is saturated;
//   - rejects the retransmission with TCP RST (same diagnostic path as the
//     first-SYN reject); and
//   - leaves the QoS counter at the limit (the failed check does not
//     increment).
//
// The relevant logic lives in tc.c:~1421 (calico_to_workload_ep ingress
// connlimit handling). The branch fires when CONNLIMIT_INGRESS_REJECTED is
// propagated to result.flags (but not CONNLIMIT_INGRESS) — the "second
// chance" path. The companion test
// TestQoSConnLimitIngressRetransmissionOfRejectedSecondChance covers the
// case where the second chance succeeds (counter has dipped below the
// limit).
func TestQoSConnLimitIngressRetransmissionOfRejectedStillOverLimit(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWretxR"
	defer func() { bpfIfaceName = "" }()

	const (
		// ifIndex must match the BPF UT's default skb ifindex so the
		// to-wep program's RPF check passes (route iface == skb iface).
		ifIndex               = 1
		maxConnections        = 3
		srcPort        uint16 = 23456 // remote opener
		dstPort        uint16 = 8055  // workload listening port
	)

	// Routes (same shape as TestQoSPacketRate's ingress test).
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())
	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)

	ctMap := conntrack.Map()
	Expect(ctMap.EnsureExists()).NotTo(HaveOccurred())
	defer resetCTMap(ctMap)
	resetCTMap(ctMap)

	// Pre-populate the CT entry for the 5-tuple that was rejected on its
	// first SYN. State: opener (srcIP) sent SYN; responder (dstIP) never
	// responded. Flag: CONNLIMIT_INGRESS_REJECTED only — under the new
	// semantics, CONNLIMIT_INGRESS is set only on a successful count, so a
	// rejected entry carries REJECTED alone. No FIN/RST on either side, so
	// tcp_recycled() returns false and the existing entry is used.
	legA := ctv4.Leg{SynSeen: true, Opener: true}
	legB := ctv4.Leg{Ifindex: ifIndex}
	k := ctv4.NewKey(6, srcIP, srcPort, dstIP, dstPort)
	v := ctv4.NewValueNormal(time.Duration(0),
		ctv4.FlagConnLimitInRej,
		legA, legB)
	Expect(ctMap.Update(k.AsBytes(), v.AsBytes()[:])).NotTo(HaveOccurred())

	// Pre-populate the ingress QoS map entry with the counter AT the
	// limit. The retransmission's second-chance check should re-run and
	// fail (current_count >= max_connections), keeping the rejection.
	defer resetQoSMap(qosMap)
	resetQoSMap(qosMap)
	qosKey := qos.NewKey(uint32(ifIndex), 1 /* ingress */, qos.IPFamilyV4)
	Expect(qosMap.Update(qosKey.AsBytes(),
		qos.NewValue(0, 0, 0, 0, maxConnections, maxConnections).AsBytes())).
		NotTo(HaveOccurred())

	readQoSCount := func() uint32 {
		b, err := qosMap.Get(qosKey.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return qos.ValueFromBytes(b).CurrentCount()
	}

	// Retransmitted SYN matching the same 5-tuple as the rejected entry.
	_, _, _, _, pktBytes, err := testPacketTCPV4WithPayload(dstIP, srcPort, dstPort, true /* syn */, nil)
	Expect(err).NotTo(HaveOccurred())

	// Ingress program: skb already marked seen (the packet passed through
	// from-hep earlier).
	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		// Reject path tail-calls into PROG_INDEX_TCP_RST. TCP_RST
		// constructs the RST and forwards it back to the source via
		// forward_or_drop; the final BPF return is TC_ACT_UNSPEC,
		// signalling "kernel takes the modified skb from here." In
		// production this means the client sees an RST instead of a
		// drop-and-retry.
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	}, withIngressQoSConnLimit())

	// Counter must be unchanged — qos_connlimit_check_and_increment fails
	// (current_count >= max_connections) without incrementing.
	Expect(readQoSCount()).To(Equal(uint32(maxConnections)))

	// CT entry's flags must be unchanged: REJECTED still set, INGRESS not
	// set (the retransmission didn't successfully count).
	ctValBytes, err := ctMap.Get(k.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	ctVal := ctv4.ValueFromBytes(ctValBytes)
	Expect(ctVal.Flags() & ctv4.FlagConnLimitInRej).To(Equal(ctv4.FlagConnLimitInRej))
	Expect(ctVal.Flags() & ctv4.FlagConnLimitIn).To(Equal(uint32(0)))
}

// TestQoSConnLimitIngressRetransmissionOfRejectedSecondChance verifies the
// "second-chance accept" path: a SYN retransmission for a previously-rejected
// CT entry succeeds when the counter has dipped below the limit since the
// original rejection (e.g. another connection closed in the meantime).
//
// On success the BPF dataplane:
//
//   - increments the QoS counter (current_count → maxConnections);
//   - sets CONNLIMIT_INGRESS on the CT entry;
//   - clears CONNLIMIT_INGRESS_REJECTED on the CT entry (mandatory — the
//     cleanup-time decrement gates on INGRESS && !INGRESS_REJECTED, so
//     leaving REJECTED set would leak the slot upward at close time);
//   - allows the SYN through (no TCP RST).
func TestQoSConnLimitIngressRetransmissionOfRejectedSecondChance(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWretxS"
	defer func() { bpfIfaceName = "" }()

	const (
		ifIndex               = 1
		maxConnections        = 3
		srcPort        uint16 = 23456
		dstPort        uint16 = 8055
	)

	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())
	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)

	ctMap := conntrack.Map()
	Expect(ctMap.EnsureExists()).NotTo(HaveOccurred())
	defer resetCTMap(ctMap)
	resetCTMap(ctMap)

	// CT entry from the original rejection — REJECTED only, no INGRESS.
	legA := ctv4.Leg{SynSeen: true, Opener: true}
	legB := ctv4.Leg{Ifindex: ifIndex}
	k := ctv4.NewKey(6, srcIP, srcPort, dstIP, dstPort)
	v := ctv4.NewValueNormal(time.Duration(0),
		ctv4.FlagConnLimitInRej,
		legA, legB)
	Expect(ctMap.Update(k.AsBytes(), v.AsBytes()[:])).NotTo(HaveOccurred())

	// QoS counter is one below the limit — slot has freed since the
	// original rejection. The retransmission's second-chance check
	// should re-run and succeed.
	defer resetQoSMap(qosMap)
	resetQoSMap(qosMap)
	qosKey := qos.NewKey(uint32(ifIndex), 1 /* ingress */, qos.IPFamilyV4)
	Expect(qosMap.Update(qosKey.AsBytes(),
		qos.NewValue(0, 0, 0, 0, maxConnections, maxConnections-1).AsBytes())).
		NotTo(HaveOccurred())

	readQoSCount := func() uint32 {
		b, err := qosMap.Get(qosKey.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return qos.ValueFromBytes(b).CurrentCount()
	}

	_, _, _, _, pktBytes, err := testPacketTCPV4WithPayload(dstIP, srcPort, dstPort, true /* syn */, nil)
	Expect(err).NotTo(HaveOccurred())

	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		// Accepted path: no TCP_RST tail call. The packet proceeds
		// through forward_or_drop; BPF returns TC_ACT_UNSPEC, kernel
		// forwards the SYN to the workload normally.
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	}, withIngressQoSConnLimit())

	// Counter incremented from maxConnections-1 to maxConnections.
	Expect(readQoSCount()).To(Equal(uint32(maxConnections)))

	// CT entry flags now have INGRESS set and REJECTED cleared.
	ctValBytes, err := ctMap.Get(k.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	ctVal := ctv4.ValueFromBytes(ctValBytes)
	Expect(ctVal.Flags() & ctv4.FlagConnLimitIn).To(Equal(ctv4.FlagConnLimitIn))
	Expect(ctVal.Flags() & ctv4.FlagConnLimitInRej).To(Equal(uint32(0)))
}

// TestQoSConnLimitIngressRetransmissionOfAccepted verifies that when a SYN
// retransmission arrives at to-wep for a connection that was previously
// *accepted* (CT entry carries CONNLIMIT_INGRESS), the BPF dataplane:
//
//   - allows the retransmission (the connection already exists); and
//   - does NOT re-increment the QoS counter (the entry was already counted
//     on its first SYN).
//
// This pins the new "INGRESS-precedes-REJECTED" precedence in tc.c — even
// if a concurrent-SYN race left both flags on the same entry, the presence
// of CONNLIMIT_INGRESS wins and the retransmission is allowed.
func TestQoSConnLimitIngressRetransmissionOfAccepted(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWretxa"
	defer func() { bpfIfaceName = "" }()

	const (
		ifIndex               = 1
		maxConnections        = 3
		srcPort        uint16 = 23457
		dstPort        uint16 = 8055
	)

	// Routes (same shape as the rejected-retransmission test).
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())
	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)

	ctMap := conntrack.Map()
	Expect(ctMap.EnsureExists()).NotTo(HaveOccurred())
	defer resetCTMap(ctMap)
	resetCTMap(ctMap)

	// Pre-populate the CT entry for an accepted connection. Flag:
	// CONNLIMIT_INGRESS only — the entry contributed to the counter on
	// its first SYN. No FIN/RST.
	legA := ctv4.Leg{SynSeen: true, Opener: true}
	legB := ctv4.Leg{Ifindex: ifIndex}
	k := ctv4.NewKey(6, srcIP, srcPort, dstIP, dstPort)
	v := ctv4.NewValueNormal(time.Duration(0),
		ctv4.FlagConnLimitIn,
		legA, legB)
	Expect(ctMap.Update(k.AsBytes(), v.AsBytes()[:])).NotTo(HaveOccurred())

	// QoS map: max=3, current=1 (this entry was already counted).
	defer resetQoSMap(qosMap)
	resetQoSMap(qosMap)
	qosKey := qos.NewKey(uint32(ifIndex), 1 /* ingress */, qos.IPFamilyV4)
	Expect(qosMap.Update(qosKey.AsBytes(),
		qos.NewValue(0, 0, 0, 0, maxConnections, 1).AsBytes())).
		NotTo(HaveOccurred())

	readQoSCount := func() uint32 {
		b, err := qosMap.Get(qosKey.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return qos.ValueFromBytes(b).CurrentCount()
	}

	// Retransmitted SYN matching the accepted entry's 5-tuple.
	_, _, _, _, pktBytes, err := testPacketTCPV4WithPayload(dstIP, srcPort, dstPort, true /* syn */, nil)
	Expect(err).NotTo(HaveOccurred())

	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		// Retransmission allowed: program returns TC_ACT_UNSPEC (no
		// reject, no special verdict — packet proceeds normally).
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	}, withIngressQoSConnLimit())

	// Counter must be unchanged at 1 — the "already counted" arm of the
	// ingress check does NOT call qos_connlimit_check_and_increment.
	Expect(readQoSCount()).To(Equal(uint32(1)))
}
