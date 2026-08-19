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
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
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
	value := qos.NewValue(1, 1, -1, 0)

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

	// seedQoSCount populates the egress connlimit map entry for ifIndex
	// with max=maxConnections and the given current_count.
	seedQoSCount := func(current uint32) {
		key := qos.NewKey(uint32(ifIndex), 0 /* egress */, qos.IPFamilyV4)
		v := qos.NewConnValue(maxConnections, current)
		Expect(qosConnMap.Update(key.AsBytes(), v.AsBytes())).NotTo(HaveOccurred())
	}

	readQoSCount := func() uint32 {
		key := qos.NewKey(uint32(ifIndex), 0, qos.IPFamilyV4)
		b, err := qosConnMap.Get(key.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return qos.ConnValueFromBytes(b).CurrentCount()
	}

	// SYN packet from srcIP:srcPort → dstIP:dstPort.
	_, _, _, _, pktBytes, err := testPacketTCPV4WithPayload(dstIP, srcPort, dstPort, true /* syn */, nil)
	Expect(err).NotTo(HaveOccurred())

	t.Run("recycle of properly-closed entry: counter stays at 1", func(t *testing.T) {
		RegisterTestingT(t)
		resetCTMap(ctMap)
		resetQoSMap(qosConnMap)
		defer resetCTMap(ctMap)
		defer resetQoSMap(qosConnMap)

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
		resetQoSMap(qosConnMap)
		defer resetCTMap(ctMap)
		defer resetQoSMap(qosConnMap)

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

	// Pre-populate the ingress connlimit map entry with the counter AT
	// the limit. The retransmission's second-chance check should re-run
	// and fail (current_count >= max_connections), keeping the rejection.
	defer resetQoSMap(qosConnMap)
	resetQoSMap(qosConnMap)
	qosKey := qos.NewKey(uint32(ifIndex), 1 /* ingress */, qos.IPFamilyV4)
	Expect(qosConnMap.Update(qosKey.AsBytes(),
		qos.NewConnValue(maxConnections, maxConnections).AsBytes())).
		NotTo(HaveOccurred())

	readQoSCount := func() uint32 {
		b, err := qosConnMap.Get(qosKey.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return qos.ConnValueFromBytes(b).CurrentCount()
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
	defer resetQoSMap(qosConnMap)
	resetQoSMap(qosConnMap)
	qosKey := qos.NewKey(uint32(ifIndex), 1 /* ingress */, qos.IPFamilyV4)
	Expect(qosConnMap.Update(qosKey.AsBytes(),
		qos.NewConnValue(maxConnections, maxConnections-1).AsBytes())).
		NotTo(HaveOccurred())

	readQoSCount := func() uint32 {
		b, err := qosConnMap.Get(qosKey.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return qos.ConnValueFromBytes(b).CurrentCount()
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

	// Connlimit map: max=3, current=1 (this entry was already counted).
	defer resetQoSMap(qosConnMap)
	resetQoSMap(qosConnMap)
	qosKey := qos.NewKey(uint32(ifIndex), 1 /* ingress */, qos.IPFamilyV4)
	Expect(qosConnMap.Update(qosKey.AsBytes(),
		qos.NewConnValue(maxConnections, 1).AsBytes())).
		NotTo(HaveOccurred())

	readQoSCount := func() uint32 {
		b, err := qosConnMap.Get(qosKey.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return qos.ConnValueFromBytes(b).CurrentCount()
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

// TestQoSConnLimitEgressSpuriousRSTSlotRestoredByRecount verifies that a
// spurious RST on a live connection costs its egress connlimit slot only until
// the next recount, rather than permanently.
//
// calico_ct_lookup decrements on any RST: conntrack.h tests tcp_header->rst
// directly, with no sequence validation anywhere on the path (the entry is
// stamped for any RST matching the 4-tuple, and ct_tcp_entry_update's seqno
// checks cover only SYN+ACK and bare ACK). The spurious-RST reasoning nearby
// can only reach a verdict two minutes later, in hindsight, so it cannot help
// at the moment the RST arrives.
//
// That prompt decrement is deliberate and must stay: felix/fv asserts a
// genuine RST close frees a slot within 5s, and routing RST closes to the
// cleanup path instead made those cases wait for TCPResetSeen (40s).
//
// What made a spurious RST unrecoverable was CONNLIMIT_DEC. The helper claims
// it before decrementing and nothing ever clears it, so while the scanner
// skipped entries carrying it, a still-live connection was excluded from every
// future recount — the one mechanism that can return a slot. The per-leg RST
// bits, by contrast, clear themselves the moment traffic resumes, which is
// what makes recovery possible at all.
//
// So this drives the packet path with an out-of-window RST — the shape a
// peer's stack discards, leaving the connection up while the dataplane counts
// it as a close — then continued traffic, and finally the real scanner, and
// asserts the slot comes back.
func TestQoSConnLimitEgressSpuriousRSTSlotRestoredByRecount(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWrst"
	defer func() { bpfIfaceName = "" }()

	const (
		// ifIndex must match the BPF UT's default skb ifindex so the
		// workload RPF check (route iface vs skb iface) passes.
		ifIndex               = 1
		maxConnections        = 3
		srcPort        uint16 = 12346 // local workload, the opener
		dstPort        uint16 = 8055
	)

	// Routes: local workload source, remote workload destination (same shape
	// as TestQoSConnLimitEgressRecycleNotDoubleCounted).
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

	// A fully-established egress connection that was counted against the
	// egress limit on its first SYN (CONNLIMIT_EGRESS set, CONNLIMIT_DEC
	// clear). No FIN and no RST on either leg. The opener leg carries the
	// pod ifindex, which is where qos_connlimit_decrement_for_ct reads it.
	//
	// Approved must be set on both legs: from_wep is CALI_F_TO_HOST, so
	// calico_ct_lookup checks src_to_dst->approved (conntrack.h:1041) and
	// would otherwise return CALI_CT_INVALID for these non-SYN packets and
	// drop them before they demonstrate anything.
	legA := ctv4.Leg{SynSeen: true, AckSeen: true, Approved: true, Opener: true, Ifindex: ifIndex}
	legB := ctv4.Leg{SynSeen: true, AckSeen: true, Approved: true}
	k := ctv4.NewKey(6, srcIP, srcPort, dstIP, dstPort)
	v := ctv4.NewValueNormal(time.Duration(0), ctv4.FlagConnLimitOut, legA, legB)
	Expect(ctMap.Update(k.AsBytes(), v.AsBytes()[:])).NotTo(HaveOccurred())

	// Egress connlimit map: max=3, current=1 — this one live connection.
	defer resetQoSMap(qosConnMap)
	resetQoSMap(qosConnMap)
	qosKey := qos.NewKey(uint32(ifIndex), 0 /* egress */, qos.IPFamilyV4)
	Expect(qosConnMap.Update(qosKey.AsBytes(),
		qos.NewConnValue(maxConnections, 1).AsBytes())).
		NotTo(HaveOccurred())

	readQoSCount := func() uint32 {
		b, err := qosConnMap.Get(qosKey.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return qos.ConnValueFromBytes(b).CurrentCount()
	}

	readCTVal := func() ctv4.ValueInterface {
		b, err := ctMap.Get(k.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return ctv4.ValueFromBytes(b)
	}

	ip := *ipv4Default
	ip.DstIP = dstIP

	// An RST on the live connection's 5-tuple. Nothing in the BPF path
	// checks its sequence number, which is what lets a peer's stack discard
	// it (leaving the connection up) while the dataplane treats it as a
	// close.
	rstPkt, dataPkt := spuriousRSTThenTrafficPackets(&ip, srcPort, dstPort)

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(rstPkt)
		Expect(err).NotTo(HaveOccurred())
		// The RST must actually reach the conntrack path — if it were
		// dropped the counter would be untouched and this test would
		// pass vacuously.
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	}, withEgressQoSConnLimit())

	// Guard, not the behaviour under test: a non-zero RST timestamp proves
	// the RST branch at conntrack.h:1079 executed, so the assertions below
	// are meaningful rather than vacuous.
	Expect(readCTVal().RSTSeen()).NotTo(BeZero(),
		"RST was not recorded on the CT entry; the packet never reached the RST path")

	// The fast path releases the slot immediately. That promptness is
	// required — felix/fv asserts a genuine RST close frees a slot within
	// 5s — and is why the RST decrement stays. On a spurious RST it is an
	// under-count, which the recount below is expected to repair.
	Expect(readQoSCount()).To(Equal(uint32(0)),
		"fast path should have decremented on the RST")

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(dataPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	}, withEgressQoSConnLimit())

	// The connection is demonstrably still live: traffic flowed after the
	// RST, and the dataplane itself has withdrawn the per-leg RST marks.
	Expect(readCTVal().Data().RSTSeen()).To(BeFalse(),
		"per-leg rst_seen should have been cleared by the continued traffic")

	// CONNLIMIT_DEC is still set and never will be cleared. The recount has
	// to restore the slot in spite of it -- that is the whole fix.
	Expect(readCTVal().Flags()&ctv4.FlagConnLimitDec).NotTo(Equal(uint32(0)),
		"expected the fast path to have claimed CONNLIMIT_DEC")

	// Run the real ConnLimitScanner over the real CT entry, exactly as the
	// CT scan loop does. This is the seam the bug lived in: the packet path
	// and the scanner were each locally reasonable, and only their
	// composition was wrong, so assert the composition.
	runConnLimitRecount(k, readCTVal(), srcIP, conntrack.ConnLimitPodInfo{
		IfIndex: ifIndex, HasEgressLimit: true,
	})

	Expect(readQoSCount()).To(Equal(uint32(1)),
		"recount did not restore the slot of a live connection after a spurious RST")
}

// TestQoSConnLimitSpuriousRSTReleasesStaleDecClaim verifies that once
// calico_ct_lookup concludes an RST was spurious, it also releases the
// CONNLIMIT_DEC claim that RST caused, so the connection's genuine close still
// decrements on the fast path.
//
// A spurious RST decrements the counter and latches CONNLIMIT_DEC. The recount
// restores the slot, but nothing released the latch, so when the connection
// eventually closed for real qos_connlimit_decrement_for_ct bailed and the slot
// came back only at recount speed (~30s) instead of immediately. The latch
// describes a decrement that the recount has since rebased away, so it has to
// be released at the same point the dataplane already decides the RST was
// spurious — two minutes of continued traffic, where it clears v->rst_seen.
//
// The entry is staged in its post-recount state rather than replayed packet by
// packet: established and approved, counted against the egress limit,
// CONNLIMIT_DEC still latched from the earlier spurious RST, per-leg RST bits
// already cleared by resumed traffic, and the peer's FIN seen. A single FIN
// from the pod then has to do three things in one pass through
// calico_ct_lookup: release the stale latch, complete the FIN exchange, and
// decrement.
func TestQoSConnLimitSpuriousRSTReleasesStaleDecClaim(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWrstD"
	defer func() { bpfIfaceName = "" }()

	const (
		ifIndex               = 1
		maxConnections        = 3
		srcPort        uint16 = 12347
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

	// The pod is the opener; the peer has already sent its FIN, so the pod's
	// FIN below completes the exchange. CONNLIMIT_DEC is latched from the
	// spurious RST; the per-leg RST bits are not set, because traffic resumed
	// and conntrack.h:571-576 cleared them.
	legA := ctv4.Leg{SynSeen: true, AckSeen: true, Approved: true, Opener: true, Ifindex: ifIndex}
	legB := ctv4.Leg{SynSeen: true, AckSeen: true, Approved: true, FinSeen: true}
	k := ctv4.NewKey(6, srcIP, srcPort, dstIP, dstPort)
	v := ctv4.NewValueNormal(time.Duration(0),
		ctv4.FlagConnLimitOut|ctv4.FlagConnLimitDec, legA, legB)

	// Backdate the value's RST timestamp so the two-minute window has already
	// elapsed. bpf_ktime_get_ns() counts from boot, so 1ns is effectively
	// "at boot" — any host that has been up longer than 2 minutes satisfies
	// the check, and the assertion on RSTSeen below catches it if not.
	vb := v.AsBytes()
	binary.LittleEndian.PutUint64(vb[ctv4.VoRSTSeen:ctv4.VoRSTSeen+8], 1)
	Expect(ctMap.Update(k.AsBytes(), vb[:])).NotTo(HaveOccurred())

	// The recount has already restored this connection's slot.
	defer resetQoSMap(qosConnMap)
	resetQoSMap(qosConnMap)
	qosKey := qos.NewKey(uint32(ifIndex), 0 /* egress */, qos.IPFamilyV4)
	Expect(qosConnMap.Update(qosKey.AsBytes(),
		qos.NewConnValue(maxConnections, 1).AsBytes())).
		NotTo(HaveOccurred())

	readQoSCount := func() uint32 {
		b, err := qosConnMap.Get(qosKey.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return qos.ConnValueFromBytes(b).CurrentCount()
	}

	readCTVal := func() ctv4.ValueInterface {
		b, err := ctMap.Get(k.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return ctv4.ValueFromBytes(b)
	}

	ip := *ipv4Default
	ip.DstIP = dstIP

	// The pod's FIN, completing the bilateral close.
	_, _, _, _, finPkt, err := testPacketV4(nil, &ip, &layers.TCP{
		FIN:        true,
		ACK:        true,
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		DataOffset: 5,
	}, nil)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(finPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	}, withEgressQoSConnLimit())

	// Guard, not the behaviour under test: a cleared RST timestamp proves the
	// two-minute branch actually ran. Without this a host up for less than
	// 2 minutes would fail the real assertion below for the wrong reason.
	Expect(readCTVal().RSTSeen()).To(BeZero(),
		"two-minute spurious-RST branch did not run; the rest of this test proves nothing")

	// The real close decremented on the fast path, despite the stale latch.
	Expect(readQoSCount()).To(Equal(uint32(0)),
		"stale CONNLIMIT_DEC claim suppressed the decrement on a genuine close")
}

// runConnLimitRecount drives the real ConnLimitScanner over a single CT entry
// the way the conntrack scan loop does — IterationStart, one Check, then
// IterationEnd, which is where the recounted value is written back to the
// cali_qos_conn map. podIP is the limited pod's address; the scanner resolves
// an entry to a pod by matching the CT key's addresses against its pod map.
func runConnLimitRecount(k ctv4.Key, val ctv4.ValueInterface, podIP net.IP, info conntrack.ConnLimitPodInfo) {
	scanner := conntrack.NewConnLimitScanner(qosConnMap,
		func() map[string]conntrack.ConnLimitPodInfo {
			return map[string]conntrack.ConnLimitPodInfo{
				string(podIP.To4()): info,
			}
		}, qos.IPFamilyV4)

	scanner.IterationStart()
	scanner.Check(k, val, nil)
	scanner.IterationEnd()
}

// TestQoSConnLimitIngressSpuriousRSTSlotRestoredByRecount is the ingress twin
// of TestQoSConnLimitEgressSpuriousRSTSlotRestoredByRecount. The defect is
// shared — the RST decrement is direction-agnostic — but the accounting is
// not: the ingress arm of qos_connlimit_decrement_for_ct resolves the pod
// ifindex from the *non-opener* leg and additionally gates on
// CONNLIMIT_INGRESS_REJECTED, and the scanner picks the direction from the
// opener bit, so egress passing is not evidence that ingress does.
//
// The threat model differs too. On egress the pod can defeat its own limit
// knowing only its own 4-tuples; on ingress the RST arrives from outside, so a
// third party needs the 4-tuple — but still not a valid sequence number, since
// nothing in the BPF path validates one. The more common trigger here is not an
// attacker at all but a genuinely spurious RST (a late reset for a recycled
// tuple, or a middlebox), which is the case conntrack.h:1083-1091 already
// concedes happens.
func TestQoSConnLimitIngressSpuriousRSTSlotRestoredByRecount(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWrstI"
	defer func() { bpfIfaceName = "" }()

	const (
		ifIndex               = 1
		maxConnections        = 3
		srcPort        uint16 = 23458 // remote opener
		dstPort        uint16 = 8055  // workload listening port
	)

	// Routes: same shape as the other ingress connlimit tests.
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

	// An established inbound connection counted against the ingress limit:
	// CONNLIMIT_INGRESS set, CONNLIMIT_DEC clear, and crucially
	// CONNLIMIT_INGRESS_REJECTED clear (with it set, the ingress arm of the
	// decrement is skipped and this test could not distinguish the bug from
	// correct behaviour).
	//
	// The remote is the opener on leg A, so the pod is the responder on leg B
	// and leg B carries the pod ifindex — that is the leg the ingress arm of
	// qos_connlimit_decrement_for_ct reads. Approved is needed on both legs
	// for the same reason as the egress twin: to_wep is CALI_F_FROM_HOST and
	// checks dst_to_src->approved (conntrack.h:1054), so unapproved non-SYN
	// packets would be dropped as CALI_CT_INVALID.
	legA := ctv4.Leg{SynSeen: true, AckSeen: true, Approved: true, Opener: true}
	legB := ctv4.Leg{SynSeen: true, AckSeen: true, Approved: true, Ifindex: ifIndex}
	k := ctv4.NewKey(6, srcIP, srcPort, dstIP, dstPort)
	v := ctv4.NewValueNormal(time.Duration(0), ctv4.FlagConnLimitIn, legA, legB)
	Expect(ctMap.Update(k.AsBytes(), v.AsBytes()[:])).NotTo(HaveOccurred())

	// Ingress connlimit map: max=3, current=1 — this one live connection.
	defer resetQoSMap(qosConnMap)
	resetQoSMap(qosConnMap)
	qosKey := qos.NewKey(uint32(ifIndex), 1 /* ingress */, qos.IPFamilyV4)
	Expect(qosConnMap.Update(qosKey.AsBytes(),
		qos.NewConnValue(maxConnections, 1).AsBytes())).
		NotTo(HaveOccurred())

	readQoSCount := func() uint32 {
		b, err := qosConnMap.Get(qosKey.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return qos.ConnValueFromBytes(b).CurrentCount()
	}

	readCTVal := func() ctv4.ValueInterface {
		b, err := ctMap.Get(k.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return ctv4.ValueFromBytes(b)
	}

	ip := *ipv4Default
	ip.DstIP = dstIP

	// Inbound RST on the live connection's 5-tuple, then inbound traffic
	// that proves the connection survived it.
	rstPkt, dataPkt := spuriousRSTThenTrafficPackets(&ip, srcPort, dstPort)

	// Ingress program: skb already marked seen (the packet passed through
	// from-hep earlier), matching the other ingress connlimit tests.
	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(rstPkt)
		Expect(err).NotTo(HaveOccurred())
		// The RST must actually reach the conntrack path — if it were
		// dropped the counter would be untouched and this test would
		// pass vacuously.
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	}, withIngressQoSConnLimit())

	// Guard, not the behaviour under test: proves the RST branch executed.
	Expect(readCTVal().RSTSeen()).NotTo(BeZero(),
		"RST was not recorded on the CT entry; the packet never reached the RST path")

	// Prompt release on the fast path, as on egress.
	Expect(readQoSCount()).To(Equal(uint32(0)),
		"fast path should have decremented on the RST")

	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(dataPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	}, withIngressQoSConnLimit())

	// The connection is demonstrably still live.
	Expect(readCTVal().Data().RSTSeen()).To(BeFalse(),
		"per-leg rst_seen should have been cleared by the continued traffic")

	Expect(readCTVal().Flags()&ctv4.FlagConnLimitDec).NotTo(Equal(uint32(0)),
		"expected the fast path to have claimed CONNLIMIT_DEC")

	// The pod is the responder here, so it is the CT key's dst address.
	runConnLimitRecount(k, readCTVal(), dstIP, conntrack.ConnLimitPodInfo{
		IfIndex: ifIndex, HasIngressLimit: true,
	})

	Expect(readQoSCount()).To(Equal(uint32(1)),
		"recount did not restore the slot of a live connection after a spurious RST")
}

// spuriousRSTThenTrafficPackets builds the two packets the spurious-RST tests
// replay over a live connection, in order:
//
//   - an RST on the connection's 5-tuple, carrying no valid sequence number.
//     Nothing in the BPF path validates one (conntrack.h:1079 stamps the entry
//     for any RST matching the tuple, and ct_tcp_entry_update's seqno checks
//     cover only SYN+ACK and bare ACK), which is what lets a real peer's stack
//     discard this while the dataplane counts it as a close.
//   - continued traffic: a normal ACK-bearing data packet. With both legs
//     already ACKed this takes the "Normal packet" arm of ct_tcp_entry_update
//     and clears the per-leg rst_seen bits (conntrack.h:571-576), so the
//     dataplane itself withdraws its own close signal.
//
// Both directions use the same builder: which leg the RST lands on is decided
// by the CT entry's opener bit and the program under test, not by the packet.
func spuriousRSTThenTrafficPackets(ip *layers.IPv4, srcPort, dstPort uint16) (rstPkt, dataPkt []byte) {
	_, _, _, _, rstPkt, err := testPacketV4(nil, ip, &layers.TCP{
		RST:        true,
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		DataOffset: 5,
	}, nil)
	Expect(err).NotTo(HaveOccurred())

	_, _, _, _, dataPkt, err = testPacketV4(nil, ip, &layers.TCP{
		ACK:        true,
		PSH:        true,
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		DataOffset: 5,
	}, []byte("hello"))
	Expect(err).NotTo(HaveOccurred())

	return rstPkt, dataPkt
}

// TestQoSConnLimitEgressGatedOnConfiguredFlag verifies that the egress
// connection-limit check is gated on EGRESS_CONN_LIMIT_CONFIGURED, matching
// the ingress check and the egress CT stamp.
//
// The egress check ran on every from-WEP TCP SYN and fired whenever a
// cali_qos_conn entry with max_connections > 0 existed, while the stamp that
// marks the CT entry CONNLIMIT_EGRESS was gated on the global. Felix writes
// the map entry and sets ap.EgressConnLimitConfigured in the same pass
// (bpf_ep_mgr.go), but the program only picks the global up when it is
// reattached, so a connection opened in that window was counted without being
// flagged — and qos_connlimit_decrement_for_ct returns early for an entry
// carrying neither CONNLIMIT_INGRESS nor _EGRESS, so neither the close path
// nor the cleanup path could decrement it.
//
// ConnLimitScanner rebases current_count on pod identity rather than on those
// flags, so the drift was transient rather than a leak. The asymmetry is still
// worth removing: gating both on the global closes the window and skips the
// map lookup entirely for endpoints with no egress limit, which is what the
// design doc already describes — "the per-direction ... flags gate the BPF
// connlimit code path entirely when no limit is configured for that attach
// point".
func TestQoSConnLimitEgressGatedOnConfiguredFlag(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWegg"
	defer func() { bpfIfaceName = "" }()

	const (
		// ifIndex must match the BPF UT's default skb ifindex so the
		// workload RPF check passes.
		ifIndex               = 1
		maxConnections        = 3
		srcPort        uint16 = 12348
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

	qosKey := qos.NewKey(uint32(ifIndex), 0 /* egress */, qos.IPFamilyV4)

	readQoSCount := func() uint32 {
		b, err := qosConnMap.Get(qosKey.AsBytes())
		Expect(err).NotTo(HaveOccurred())
		return qos.ConnValueFromBytes(b).CurrentCount()
	}

	// A configured limit with the counter at zero -- the map entry Felix has
	// already written. Whether it is enforced is what the two cases differ on.
	seed := func() {
		resetCTMap(ctMap)
		resetQoSMap(qosConnMap)
		Expect(qosConnMap.Update(qosKey.AsBytes(),
			qos.NewConnValue(maxConnections, 0).AsBytes())).NotTo(HaveOccurred())
	}

	_, _, _, _, synPkt, err := testPacketTCPV4WithPayload(dstIP, srcPort, dstPort, true /* syn */, nil)
	Expect(err).NotTo(HaveOccurred())

	// Positive control. Without it the case below would pass for any reason
	// the SYN failed to reach the check at all.
	t.Run("global set: SYN is counted", func(t *testing.T) {
		RegisterTestingT(t)
		seed()
		defer resetQoSMap(qosConnMap)

		skbMark = 0
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(synPkt)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
		}, withEgressQoSConnLimit())

		Expect(readQoSCount()).To(Equal(uint32(1)))
	})

	t.Run("global clear: SYN is not counted", func(t *testing.T) {
		RegisterTestingT(t)
		seed()
		defer resetQoSMap(qosConnMap)

		// No withEgressQoSConnLimit(): the program as it is attached before
		// Felix reattaches it with the new global, while the map entry
		// seeded above is already in place.
		skbMark = 0
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(synPkt)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
		})

		Expect(readQoSCount()).To(Equal(uint32(0)),
			"egress connlimit check ran without EGRESS_CONN_LIMIT_CONFIGURED; "+
				"the connection is counted but the CT stamp is gated, "+
				"so nothing can decrement it")
	})
}
