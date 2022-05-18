// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/felix/ip"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/routes"
)

var (
	rtKeySrc        = routes.NewKey(srcV4CIDR).AsBytes()
	rtValGood       = routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	rtValWrongIface = routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 2).AsBytes()
	rtValWrongType  = routes.NewValueWithNextHop(routes.FlagsRemoteWorkload, ip.V4Addr{1, 0, 0, 0}).AsBytes()
)

func TestWorkloadSpoof(t *testing.T) {
	RegisterTestingT(t)
	cleanUpMaps()
	defer cleanUpMaps()

	t.Log("Missing return route -> DROP")
	runSpoofTest(t, resTC_ACT_SHOT)
	cleanUpMaps()

	t.Log("Correct return route -> ALLOW")
	err := rtMap.Update(rtKeySrc, rtValGood)
	Expect(err).NotTo(HaveOccurred())
	runSpoofTest(t, resTC_ACT_UNSPEC)
	cleanUpMaps()

	t.Log("Incorrect if_index -> DROP")
	err = rtMap.Update(rtKeySrc, rtValWrongIface)
	Expect(err).NotTo(HaveOccurred())
	runSpoofTest(t, resTC_ACT_SHOT)
	cleanUpMaps()

	t.Log("Incorrect type -> DROP")
	err = rtMap.Update(rtKeySrc, rtValWrongType)
	Expect(err).NotTo(HaveOccurred())
	runSpoofTest(t, resTC_ACT_SHOT)
	cleanUpMaps()
}

func runSpoofTest(t *testing.T, expRC int) {
	_, _, _, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(expRC))
	})
}
