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

func TestDSCPV4(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "HWvwl"
	defer func() { bpfIfaceName = "" }()

	ctMap := conntrack.Map()
	err := ctMap.EnsureExists()
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

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		_, _, _, _, pktBytes, err := testPacketV4(nil, ipv4Default, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.dataOut).To(HaveLen(len(pktBytes)))
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		ipv4Hdr := *ipv4Default
		ipv4Hdr.TOS = 0x10 << 2 // DSCP (6bits) = 16 + ECN (2bits) = 0
		_, _, _, _, pktBytes, err = testPacketV4(nil, &ipv4Hdr, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		Expect(res.dataOut).To(Equal(pktBytes))
	}, withEgressDSCP(16))

	resetCTMap(ctMap) // ensure it is clean

	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		_, _, _, _, pktBytes, err := testPacketV4(nil, ipv4Default, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.dataOut).To(HaveLen(len(pktBytes)))
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ipv4Hdr := *ipv4Default
		ipv4Hdr.TOS = 0x08 << 2 // DSCP (6bits) = 8 + ECN (2bits) = 0
		_, _, _, _, pktBytes, err = testPacketV4(nil, &ipv4Hdr, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		Expect(res.dataOut).To(Equal(pktBytes))
	}, withEgressDSCP(8))
}

func TestDSCPV6(t *testing.T) {
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
	rtVal := routes.NewValueV6WithIfIndex(routes.FlagsLocalWorkload, ifIndex).AsBytes()
	err = rtMapV6.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	rtKey = routes.NewKeyV6(dstV6CIDR).AsBytes()
	rtVal = routes.NewValueV6WithIfIndex(routes.FlagsRemoteWorkload, ifIndex).AsBytes()
	err = rtMapV6.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMapV6)

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		_, _, _, _, pktBytes, err := testPacketV6(nil, ipv6Default, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.dataOut).To(HaveLen(len(pktBytes)))
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ipv6Hdr := *ipv6Default
		ipv6Hdr.TrafficClass = 0x10 << 2 // DSCP (6bits) = 16 + ECN (2bits) = 0
		_, _, _, _, pktBytes, err = testPacketV6(nil, &ipv6Hdr, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		Expect(res.dataOut).To(Equal(pktBytes))
	}, withEgressDSCP(16), withIPv6())

	resetCTMap(ctMap) // ensure it is clean

	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_host_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		_, _, _, _, pktBytes, err := testPacketV6(nil, ipv6Default, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.dataOut).To(HaveLen(len(pktBytes)))
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		ipv6Hdr := *ipv6Default
		ipv6Hdr.TrafficClass = 0x08 << 2 // DSCP (6bits) = 8 + ECN (2bits) = 0
		_, _, _, _, pktBytes, err = testPacketV6(nil, &ipv6Hdr, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		Expect(res.dataOut).To(Equal(pktBytes))
	}, withEgressDSCP(8), withIPv6())
}
