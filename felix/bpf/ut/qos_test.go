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

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
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
	key1 := qos.NewKey(uint32(ifIndex), 1)
	key2 := qos.NewKey(uint32(ifIndex), 0)
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

		// Src and dest both inside cluster.
		{"calico_to_host_ep", tcdefs.MarkSeen, srcIP, dstIP, resTC_ACT_UNSPEC, 8, -1},
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
		{"calico_from_workload_ep", 0, srcIPv6, externalAddr, resTC_ACT_UNSPEC, 16, 16},
		{"calico_to_workload_ep", tcdefs.MarkSeen, srcIPv6, externalAddr, resTC_ACT_UNSPEC, 20, -1},

		// Src outside cluster.
		{"calico_to_workload_ep", tcdefs.MarkSeen, externalAddr, dstIPv6, resTC_ACT_UNSPEC, 20, -1},

		// Src and dest both inside cluster.
		{"calico_from_workload_ep", 0, srcIPv6, dstIPv6, resTC_ACT_UNSPEC, 16, -1},
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
	rtVal = routes.NewValueV6WithIfIndex(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
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

		// Src and dest both inside cluster.
		{"calico_to_host_ep", tcdefs.MarkSeen, srcIPv6, dstIPv6, resTC_ACT_UNSPEC, 8, -1},
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
