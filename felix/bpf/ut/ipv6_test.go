// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/felix/bpf/polprog"
)

type ipv6Test struct {
	Description string
	Section     string
	Rules       *polprog.Rules
	pkt         Packet
	Drop        bool
}

var ipTestCases = []ipv6Test{
	{
		Description: "1 - A packet from host, must accept",
		Section:     "calico_from_host_ep",
		Rules:       nil,
		pkt: Packet{
			l3: ipv6Default,
			l4: &layers.UDP{
				DstPort: 53,
				SrcPort: 54321,
			},
		},
		Drop: false,
	},
	{
		Description: "2 - A packet from workload, must drop",
		Section:     "calico_from_workload_ep",
		Rules:       nil,
		pkt: Packet{
			l3: ipv6Default,
			l4: &layers.UDP{
				DstPort: 53,
				SrcPort: 54321,
			},
		},
		Drop: true,
	},
}

func TestIPv6Parsing(t *testing.T) {
	RegisterTestingT(t)

	t.Skip("ipv6 not supported")

	defer resetBPFMaps()

	for _, tc := range ipTestCases {
		skbMark = 0
		runBpfTest(t, tc.Section, tc.Rules, func(bpfrun bpfProgRunFn) {
			err := tc.pkt.Generate()
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(tc.pkt.bytes)
			Expect(err).NotTo(HaveOccurred())
			result := "TC_ACT_UNSPEC"
			if tc.Drop {
				result = "TC_ACT_SHOT"
			}
			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)
			Expect(res.RetvalStr()).To(Equal(result), fmt.Sprintf("expected the program to return %s", result))
			Expect(res.dataOut).To(HaveLen(len(tc.pkt.bytes)))
			Expect(res.dataOut).To(Equal(tc.pkt.bytes))
		}, withIPv6(), withDescription(tc.Description))
	}
}
