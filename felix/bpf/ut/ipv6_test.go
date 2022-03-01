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
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/projectcalico/calico/felix/bpf/polprog"

	. "github.com/onsi/gomega"
)

type ipv6Test struct {
	Description string
	Section     string
	Rules       *polprog.Rules
	IPv6Header  *layers.IPv6
	NextHeader  gopacket.Layer
	Drop        bool
}

var ipTestCases = []ipv6Test{
	{
		Description: "1 - A packet from host, must accept",
		Section:     "calico_from_host_ep",
		Rules:       nil,
		IPv6Header: &layers.IPv6{
			Version:  6,
			HopLimit: 64,
			SrcIP:    net.IP([]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
			DstIP:    net.IP([]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}),
		},
		NextHeader: &layers.UDP{
			DstPort: 53,
			SrcPort: 54321,
		},
		Drop: false,
	},
	{
		Description: "2 - A packet from workload, must drop",
		Section:     "calico_from_workload_ep",
		Rules:       nil,
		IPv6Header: &layers.IPv6{
			Version:  6,
			HopLimit: 64,
			SrcIP:    net.IP([]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
			DstIP:    net.IP([]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}),
		},
		NextHeader: &layers.UDP{
			DstPort: 53,
			SrcPort: 54321,
		},
		Drop: true,
	},
}

func TestIPv6Parsing(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()

	for _, tc := range ipTestCases {
		runBpfTest(t, tc.Section, tc.Rules, func(bpfrun bpfProgRunFn) {
			_, _, _, _, pktBytes, err := testPacketv6(nil, tc.IPv6Header, tc.NextHeader, nil)
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			result := "TC_ACT_UNSPEC"
			if tc.Drop {
				result = "TC_ACT_SHOT"
			}
			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)
			Expect(res.RetvalStr()).To(Equal(result), fmt.Sprintf("expected the program to return %s", result))
			Expect(res.dataOut).To(HaveLen(len(pktBytes)))
			Expect(res.dataOut).To(Equal(pktBytes))
		})
	}
}
