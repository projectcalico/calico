// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"testing"

	. "github.com/onsi/gomega"
)

func BenchmarkHEP(b *testing.B) {
	RegisterTestingT(b)

	_, _, _, _, pktBytes, err := testPacketUDPDefaultNP(node1ip)
	Expect(err).NotTo(HaveOccurred())

	cleanUpMaps()
	defer cleanUpMaps()

	ctxIn := make([]byte, 18*4)

	// Run once to create conntrack entry
	setupAndRun(b, "no_log", "calico_from_host_ep", nil, func(progName string) {
		res, err := bpftoolProgRun(progName, pktBytes, ctxIn)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	setupAndRun(b, "no_log", "calico_from_host_ep", nil, func(progName string) {
		b.ResetTimer()
		res, err := bpftoolProgRunN(progName, pktBytes, ctxIn, b.N)
		b.StopTimer()
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		fmt.Printf("%7d iterations avg %d\n", b.N, res.Duration)
	})
}
