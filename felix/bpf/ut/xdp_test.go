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

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/failsafes"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/proto"
)

const (
	TOS_BYTE   = 15
	FLOW_BYTE  = 17
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
					SrcNet: []string{"9.8.2.1/32", "6::6/128"},
					DstNet: []string{"1.2.8.9/32", "3::3/128"},
					Action: "Deny",
				}}, {
				Rule: &proto.Rule{
					DstNet: []string{"1.2.0.0/16", "1::2/64"},
					Action: "Allow",
				}}, {
				Rule: &proto.Rule{
					SrcNet: []string{"9.8.7.0/24", "5::8/64"},
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

type xdpTestV6 struct {
	Description string
	Rules       *polprog.Rules
	IPv6Header  *layers.IPv6
	NextHeader  gopacket.Layer
	Drop        bool
	Metadata    bool
	IPProto     layers.IPProtocol
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
		Description: "4 - Allow all rule, packet must pass with metadata",
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

	defer func() { bpfIfaceName = "" }()

	for i, tc := range xdpTestCases {
		bpfIfaceName = fmt.Sprintf("XDP-%d", i)
		runBpfTest(t, "xdp_calico_entrypoint", tc.Rules, func(bpfrun bpfProgRunFn) {
			_, _, _, _, pktBytes, err := testPacketV4(nil, tc.IPv4Header, tc.NextHeader, nil)
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

var xdpV6TestCases = []xdpTestV6{
	{
		Description: "2 - Packets not matched, must pass without metadata",
		Rules:       nil,
		IPv6Header:  ipv6Default,
		Drop:        false,
		Metadata:    false,
	},
	{
		Description: "3 - Deny all rule, packet must drop",
		Rules:       &denyAllRulesXDP,
		IPv6Header:  ipv6Default,
		Drop:        true,
		Metadata:    false,
	},
	{
		Description: "4 - Allow all rule, packet must pass with metadata",
		Rules:       &allowAllRulesXDP,
		IPv6Header:  ipv6Default,
		Drop:        false,
		Metadata:    true,
	},
	{
		Description: "5 - Match with failsafe, must pass without metadata",
		Rules:       nil,
		IPv6Header: &layers.IPv6{
			Version:  6,
			HopLimit: 64,
			SrcIP:    net.IP([]byte{0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}),
			DstIP:    net.IP([]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
		},
		NextHeader: &layers.UDP{
			DstPort: 53,
			SrcPort: 54321,
		},
		Drop:     false,
		Metadata: false,
		IPProto:  layers.IPProtocolUDP,
	},
	{
		Description: "6 - Match against a deny policy, must drop",
		Rules:       &oneXDPRule,
		IPv6Header: &layers.IPv6{
			Version:  6,
			HopLimit: 64,
			SrcIP:    net.IP([]byte{0x00, 06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6}),
			DstIP:    net.IP([]byte{0x00, 03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}),
		},
		NextHeader: &layers.TCP{
			DstPort: 80,
			SrcPort: 55555,
		},
		Drop:     true,
		Metadata: false,
		IPProto:  layers.IPProtocolTCP,
	},
	{
		Description: "7 - Match against a deny policy, must drop",
		Rules:       &oneXDPRule,
		IPv6Header: &layers.IPv6{
			Version:  6,
			HopLimit: 64,
			SrcIP:    net.IP([]byte{0x00, 05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6}),
			DstIP:    net.IP([]byte{0x00, 03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
		},
		NextHeader: &layers.TCP{
			DstPort: 80,
			SrcPort: 55555,
		},
		Drop:     true,
		Metadata: false,
		IPProto:  layers.IPProtocolTCP,
	},
	{
		Description: "8 - Match against an allow policy, must pass with metadata",
		Rules:       &oneXDPRule,
		IPv6Header: &layers.IPv6{
			Version:  6,
			HopLimit: 64,
			SrcIP:    net.IP([]byte{0x00, 02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
			DstIP:    net.IP([]byte{0x00, 01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
		},
		NextHeader: &layers.TCP{
			DstPort: 80,
			SrcPort: 55555,
		},
		Drop:     false,
		Metadata: true,
		IPProto:  layers.IPProtocolTCP,
	},
	{
		Description: "9 - Unmatched packet against failsafe and a policy",
		Rules:       &oneXDPRule,
		IPv6Header: &layers.IPv6{
			Version:  6,
			HopLimit: 64,
			SrcIP:    net.IP([]byte{0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8}),
			DstIP:    net.IP([]byte{0x00, 07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}),
		},
		NextHeader: &layers.UDP{
			DstPort: 8080,
			SrcPort: 54321,
		},
		Drop:     false,
		Metadata: false,
		IPProto:  layers.IPProtocolUDP,
	},
}

func TestXDPV6Programs(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()
	err := fsafeMapV6.Update(
		failsafes.MakeKeyV6(17, 53, false, "4::4", 16).ToSlice(),
		failsafes.ValueV6(),
	)
	Expect(err).NotTo(HaveOccurred())

	defer func() { bpfIfaceName = "" }()

	for i, tc := range xdpV6TestCases {
		bpfIfaceName = fmt.Sprintf("XDPV6-%d", i)
		runBpfTest(t, "xdp_calico_entrypoint", tc.Rules, func(bpfrun bpfProgRunFn) {

			var pktBytes []byte
			var err error
			if tc.NextHeader != nil {
				hop := ipv6HopByHopExt()
				hop.(*layers.IPv6HopByHop).NextHeader = tc.IPProto
				_, _, _, _, pktBytes, err = testPacketV6(nil, tc.IPv6Header, tc.NextHeader, nil, hop)
			} else {
				_, _, _, _, pktBytes, err = testPacketV6(nil, tc.IPv6Header, tc.NextHeader, nil)
			}
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
				Expect(res.dataOut[FLOW_BYTE]).To(Equal(uint8(TOS_SET)))
				res.dataOut[FLOW_BYTE] = TOS_NOTSET
			} else {
				Expect(res.dataOut[FLOW_BYTE]).To(Equal(uint8(TOS_NOTSET)))
			}
			Expect(res.dataOut).To(Equal(pktBytes))
		}, withXDP(), withIPv6())
	}
}
