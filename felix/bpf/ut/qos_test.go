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

	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
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

	// Populate ifstate map (for QoS state)
	key1 := ifstate.NewKey(uint32(ifIndex)).AsBytes()
	value1 := ifstate.NewValue(ifstate.FlgIPv4Ready|ifstate.FlgWEP, bpfIfaceName,
		-1, 0, 2, -1, -1, -1, 3, 4, -1, -1, 0, 0)

	bpfmaps, err := bpfmap.CreateBPFMaps(false)
	Expect(err).NotTo(HaveOccurred())
	err = bpfmaps.CommonMaps.IfStateMap.Update(
		key1,
		value1.AsBytes(),
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
	}, withIngressQoSPacketRate(1, 1))

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
	}, withEgressQoSPacketRate(1, 1))
}
