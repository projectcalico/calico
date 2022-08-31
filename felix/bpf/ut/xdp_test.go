// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/failsafes"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/proto"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"
)

func MapForTest(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(bpf.MapParameters{
		Filename:   "/sys/fs/bpf/cali_jump_xdp",
		Type:       "prog_array",
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 16,
		Name:       bpf.JumpMapName(),
	})
}

const (
	TOS_BYTE   = 15
	TOS_NOTSET = 0
	TOS_SET    = 128
)

var denyAllRulesXDP = polprog.Rules{
	ForXDP:           true,
	ForHostInterface: true,
	HostNormalTiers: []polprog.Tier{{
		Policies: []polprog.Policy{{
			Name: "deny all",
			Rules: []polprog.Rule{{Rule: &proto.Rule{
				Action: "Deny",
			}}},
		}},
	}},
}

var allowAllRulesXDP = polprog.Rules{
	ForXDP:           true,
	ForHostInterface: true,
	HostNormalTiers: []polprog.Tier{{
		Policies: []polprog.Policy{{
			Name: "Allow all",
			Rules: []polprog.Rule{{Rule: &proto.Rule{
				Action: "allow",
			}}},
		}},
	}},
}

var oneXDPRule = polprog.Rules{
	ForXDP:           true,
	ForHostInterface: true,
	HostNormalTiers: []polprog.Tier{{
		EndAction: "pass",
		Policies: []polprog.Policy{{
			Name: "Allow some",
			Rules: []polprog.Rule{{
				Rule: &proto.Rule{
					SrcNet: []string{"9.8.2.1/32"},
					DstNet: []string{"1.2.8.9/32"},
					Action: "Deny",
				}}, {
				Rule: &proto.Rule{
					DstNet: []string{"1.2.0.0/16"},
					Action: "Allow",
				}}, {
				Rule: &proto.Rule{
					SrcNet: []string{"9.8.7.0/24"},
					Action: "Deny",
				}},
			}}},
	}},
}

type xdpTest struct {
	Description string
	Rules       *polprog.Rules
	IPv4Header  *layers.IPv4
	NextHeader  gopacket.Layer
	Drop        bool
	Metadata    bool
}

var xdpTestCases = []xdpTest{
	{
		Description: "1 - A malformed packet, must drop",
		Rules:       &allowAllRulesXDP,
		IPv4Header: &layers.IPv4{
			Version: 4,
			IHL:     4,
			TTL:     64,
			Flags:   layers.IPv4DontFragment,
			SrcIP:   net.IPv4(4, 4, 4, 4),
			DstIP:   net.IPv4(1, 1, 1, 1),
		},
		NextHeader: &layers.UDP{
			DstPort: 53,
			SrcPort: 54321,
		},
		Drop:     true,
		Metadata: false,
	},
	{
		Description: "2 - Packets not matched, must pass without metadata",
		Rules:       nil,
		IPv4Header:  ipv4Default,
		Drop:        false,
		Metadata:    false,
	},
	{
		Description: "3 - Deny all rule, packet must drop",
		Rules:       &denyAllRulesXDP,
		IPv4Header:  ipv4Default,
		Drop:        true,
		Metadata:    false,
	},
	{
		Description: "4 - Allow all rule, packet must pass with metada",
		Rules:       &allowAllRulesXDP,
		IPv4Header:  ipv4Default,
		Drop:        false,
		Metadata:    true,
	},
	{
		Description: "5 - Match with failsafe, must pass without metadata",
		Rules:       nil,
		IPv4Header: &layers.IPv4{
			Version: 4,
			IHL:     5,
			TTL:     64,
			Flags:   layers.IPv4DontFragment,
			SrcIP:   net.IPv4(4, 4, 4, 4),
			DstIP:   net.IPv4(1, 1, 1, 1),
		},
		NextHeader: &layers.UDP{
			DstPort: 53,
			SrcPort: 54321,
		},
		Drop:     false,
		Metadata: false,
	},
	{
		Description: "6 - Match against a deny policy, must drop",
		Rules:       &oneXDPRule,
		IPv4Header: &layers.IPv4{
			Version: 4,
			IHL:     5,
			TTL:     64,
			Flags:   layers.IPv4DontFragment,
			SrcIP:   net.IPv4(9, 8, 7, 6),
			DstIP:   net.IPv4(10, 0, 0, 10),
		},
		NextHeader: &layers.TCP{
			DstPort: 80,
			SrcPort: 55555,
		},
		Drop:     true,
		Metadata: false,
	},
	{
		Description: "7 - Match against a deny policy, must drop",
		Rules:       &oneXDPRule,
		IPv4Header: &layers.IPv4{
			Version: 4,
			IHL:     5,
			TTL:     64,
			Flags:   layers.IPv4DontFragment,
			SrcIP:   net.IPv4(9, 8, 2, 1),
			DstIP:   net.IPv4(1, 2, 8, 9),
		},
		NextHeader: &layers.TCP{
			DstPort: 80,
			SrcPort: 55555,
		},
		Drop:     true,
		Metadata: false,
	},
	{
		Description: "8 - Match against an allow policy, must pass with metadata",
		Rules:       &oneXDPRule,
		IPv4Header: &layers.IPv4{
			Version: 4,
			IHL:     5,
			TTL:     64,
			Flags:   layers.IPv4DontFragment,
			SrcIP:   net.IPv4(3, 3, 3, 3),
			DstIP:   net.IPv4(1, 2, 3, 4),
		},
		NextHeader: &layers.TCP{
			DstPort: 80,
			SrcPort: 55555,
		},
		Drop:     false,
		Metadata: true,
	},
	{
		Description: "9 - Unmatched packet against failsafe and a policy",
		Rules:       &oneXDPRule,
		IPv4Header: &layers.IPv4{
			Version: 4,
			IHL:     5,
			TTL:     64,
			Flags:   layers.IPv4DontFragment,
			SrcIP:   net.IPv4(8, 8, 8, 8),
			DstIP:   net.IPv4(9, 9, 9, 9),
		},
		NextHeader: &layers.UDP{
			DstPort: 8080,
			SrcPort: 54321,
		},
		Drop:     false,
		Metadata: false,
	},
}

func TestXDPPrograms(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()
	err := fsafeMap.Update(
		failsafes.MakeKey(17, 53, false, "4.4.4.4", 16).ToSlice(),
		failsafes.Value(),
	)
	Expect(err).NotTo(HaveOccurred())

	for _, tc := range xdpTestCases {
		runBpfTest(t, "xdp_calico_entrypoint", tc.Rules, func(bpfrun bpfProgRunFn) {
			_, _, _, _, pktBytes, err := testPacket(nil, tc.IPv4Header, tc.NextHeader, nil)
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			result := "XDP_PASS"
			if tc.Drop {
				result = "XDP_DROP"
			}
			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)
			Expect(res.RetvalStrXDP()).To(Equal(result), fmt.Sprintf("expected the program to return %s", result))
			Expect(res.dataOut).To(HaveLen(len(pktBytes)))
			if tc.Metadata {
				Expect(res.dataOut[TOS_BYTE]).To(Equal(uint8(TOS_SET)))
				res.dataOut[TOS_BYTE] = TOS_NOTSET
			} else {
				Expect(res.dataOut[TOS_BYTE]).To(Equal(uint8(TOS_NOTSET)))
			}
			Expect(res.dataOut).To(Equal(pktBytes))
		}, withXDP())
	}
}
