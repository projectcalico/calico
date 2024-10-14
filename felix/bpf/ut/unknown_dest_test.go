// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

func TestUnknownEnterHostNoRoute(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "noRt"
	defer func() { bpfIfaceName = "" }()

	_, _, _, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())

	resetCTMap(ctMap) // ensure it is clean

	hostIP = node1ip

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValue(routes.FlagsRemoteWorkload | routes.FlagInIPAMPool).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	expectMark(tcdefs.MarkSeenSkipFIB) // It must have skip FIB set as we did not know what to do with the packet.
}

func TestUnknownEnterHostRouteNotLocal(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "noLo"
	defer func() { bpfIfaceName = "" }()

	_, _, _, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())

	resetCTMap(ctMap) // ensure it is clean

	hostIP = node1ip

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValue(routes.FlagsRemoteWorkload | routes.FlagInIPAMPool).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)

	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	expectMark(tcdefs.MarkSeenSkipFIB) // It must have skip FIB set as we did not know what to do with the packet.

	// Next packet will follow conntrack, but must skip FIB as well.
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	expectMark(tcdefs.MarkSeenSkipFIB) // It must have skip FIB set as we did not know what to do with the packet.

	// Next packet will follow conntrack, but must skip FIB as well.
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	expectMark(tcdefs.MarkSeenSkipFIB) // It must have skip FIB set as we did not know what to do with the packet.

	resetCTMap(ctMap)

	rtVal = routes.NewValueWithIfIndex(routes.FlagsRemoteHost|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	expectMark(tcdefs.MarkSeenSkipFIB) // It must have skip FIB set as we did not know what to do with the packet.
}
