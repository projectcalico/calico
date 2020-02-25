// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"
)

func TestIpDecTTL(t *testing.T) {
	RegisterTestingT(t)

	runBpfUnitTest(t, "ip_dec_ttl.c", func(bpfrun bpfProgRunFn) {
		ip36 := *ipv4Default
		ip36.TTL = 36
		_, _, _, _, pktBytes, err := testPacket(nil, &ip36, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(0))

		Expect(res.dataOut).To(HaveLen(len(pktBytes)))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ip35 := *ipv4Default
		ip35.TTL = 35
		_, _, _, _, pktBytes, err = testPacket(nil, &ip35, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		Expect(res.dataOut).To(Equal(pktBytes))
	})
}
