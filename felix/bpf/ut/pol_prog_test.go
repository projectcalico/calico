// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

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
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/state"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/proto"
)

func TestPolicyLoadAllowAllProgram(t *testing.T) {
	RegisterTestingT(t)

	b := asm.NewBlock(false)
	b.MovImm32(asm.R0, -1)
	b.Exit()
	insns, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())

	fd, err := bpf.LoadBPFProgramFromInsns(insns, "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
	Expect(err).NotTo(HaveOccurred())
	Expect(fd).NotTo(BeZero())
	defer func() {
		Expect(fd.Close()).NotTo(HaveOccurred())
	}()

	rc, err := bpf.RunBPFProgram(fd, make([]byte, 500), 1)
	Expect(err).NotTo(HaveOccurred())
	Expect(rc.RC).To(BeNumerically("==", -1))
}

func TestPolicyLoadProgramWithMapAccess(t *testing.T) {
	RegisterTestingT(t)

	ipsMap := ipsets.Map()
	Expect(ipsMap.EnsureExists()).NotTo(HaveOccurred())
	Expect(ipsMap.MapFD()).NotTo(BeZero())

	b := asm.NewBlock(false)
	b.MovImm64(asm.R1, 0)
	b.StoreStack64(asm.R1, -8)
	b.StoreStack64(asm.R1, -16)
	b.StoreStack64(asm.R1, -24)
	b.StoreStack64(asm.R1, -32)
	b.Mov64(asm.R2, asm.R10)
	b.AddImm64(asm.R2, -32)
	b.LoadMapFD(asm.R1, uint32(ipsMap.MapFD()))
	b.Call(asm.HelperMapLookupElem)
	b.MovImm32(asm.R0, -1)
	b.Exit()
	insns, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())

	fd, err := bpf.LoadBPFProgramFromInsns(insns, "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
	Expect(err).NotTo(HaveOccurred())
	Expect(fd).NotTo(BeZero())
	defer func() {
		Expect(fd.Close()).NotTo(HaveOccurred())
	}()

	rc, err := bpf.RunBPFProgram(fd, make([]byte, 500), 1)
	Expect(err).NotTo(HaveOccurred())
	Expect(rc.RC).To(BeNumerically("==", -1))
}

func makeRulesSingleTier(protoRules []*proto.Rule) polprog.Rules {

	polRules := make([]polprog.Rule, len(protoRules))

	for i, r := range protoRules {
		polRules[i].Rule = r
	}

	return polprog.Rules{
		Tiers: []polprog.Tier{{
			Name: "base tier",
			Policies: []polprog.Policy{{
				Name:  "test policy",
				Rules: polRules,
			}},
		}},
	}
}

func TestPolicyLoadKitchenSinkPolicy(t *testing.T) {
	RegisterTestingT(t)
	alloc := idalloc.New()
	allocID := func(id string) string {
		alloc.GetOrAlloc(id)
		return id
	}

	cleanIPSetMap()

	pg := polprog.NewBuilder(alloc, ipsMap.MapFD(), stateMap.MapFD(), policyJumpMap[hook.Ingress].MapFD(), 0,
		polprog.WithAllowDenyJumps(tcdefs.ProgIndexAllowed, tcdefs.ProgIndexDrop))
	insns, err := pg.Instructions(polprog.Rules{
		Tiers: []polprog.Tier{{
			Name: "base tier",
			Policies: []polprog.Policy{{
				Name: "test policy",
				Rules: []polprog.Rule{{Rule: &proto.Rule{
					Action:                  "Allow",
					IpVersion:               4,
					Protocol:                &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}},
					SrcNet:                  []string{"10.0.0.0/8"},
					SrcPorts:                []*proto.PortRange{{First: 80, Last: 81}, {First: 8080, Last: 8081}},
					SrcNamedPortIpSetIds:    []string{allocID("n:abcdef1234567890")},
					DstNet:                  []string{"11.0.0.0/8"},
					DstPorts:                []*proto.PortRange{{First: 3000, Last: 3001}},
					DstNamedPortIpSetIds:    []string{allocID("n:foo1234567890")},
					Icmp:                    nil,
					SrcIpSetIds:             []string{allocID("s:sbcdef1234567890")},
					DstIpSetIds:             []string{allocID("s:dbcdef1234567890")},
					NotProtocol:             &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "UDP"}},
					NotSrcNet:               []string{"12.0.0.0/8"},
					NotSrcPorts:             []*proto.PortRange{{First: 5000, Last: 5000}},
					NotDstNet:               []string{"13.0.0.0/8"},
					NotDstPorts:             []*proto.PortRange{{First: 4000, Last: 4000}},
					NotIcmp:                 nil,
					NotSrcIpSetIds:          []string{allocID("s:abcdef1234567890")},
					NotDstIpSetIds:          []string{allocID("s:abcdef123456789l")},
					NotSrcNamedPortIpSetIds: []string{allocID("n:0bcdef1234567890")},
					NotDstNamedPortIpSetIds: []string{allocID("n:0bcdef1234567890")},
				}}},
			}},
		}}})

	Expect(err).NotTo(HaveOccurred())
	Expect(insns).To(HaveLen(1))
	fd, err := bpf.LoadBPFProgramFromInsns(insns[0], "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
	Expect(err).NotTo(HaveOccurred())
	Expect(fd).NotTo(BeZero())
	Expect(fd.Close()).NotTo(HaveOccurred())
}

func TestPolicyLoadGarbageProgram(t *testing.T) {
	RegisterTestingT(t)

	var insns asm.Insns
	for i := 0; i < 256; i++ {
		i := uint8(i)
		insns = append(insns, asm.Insn{Instruction: [8]uint8{i, i, i, i, i, i, i, i}})
	}

	fd, err := bpf.LoadBPFProgramFromInsns(insns, "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
	Expect(err).To(HaveOccurred())
	Expect(fd).To(BeZero())
}

const (
	RCAllowedReached = 123
	RCDropReached    = 124
	XDPPass          = 2
)

func packetWithPorts(proto int, src, dst string) packet {
	// Just using ResolveUDPAddr to parse a string to ip and port
	srcAddr, err := net.ResolveUDPAddr("udp", src)
	if err != nil {
		panic(err)
	}
	dstAddr, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		panic(err)
	}
	return packet{
		protocol: proto,
		srcAddr:  srcAddr.IP.String(),
		srcPort:  srcAddr.Port,
		dstAddr:  dstAddr.IP.String(),
		dstPort:  dstAddr.Port,
	}
}

func tcpPkt(src, dst string) packet {
	return packetWithPorts(6, src, dst)
}

func udpPkt(src, dst string) packet {
	return packetWithPorts(17, src, dst)
}

func icmpPkt(src, dst string) packet {
	return packetWithPorts(1, src+":0", dst+":0")
}

func icmpPktWithTypeCode(src, dst string, icmpType, icmpCode int) packet {
	return packet{
		protocol: 1,
		srcAddr:  src,
		srcPort:  0,
		dstAddr:  dst,
		dstPort:  (icmpCode << 8) | (icmpType),
	}
}

func packetNoPorts(proto int, src, dst string) packet {
	// Just using ResolveUDPAddr to parse a string to ip and port
	srcAddr := net.ParseIP(src)
	if srcAddr == nil {
		panic(fmt.Errorf("failed to parse src addr %v", src))
	}
	dstAddr := net.ParseIP(dst)
	if dstAddr == nil {
		panic(fmt.Errorf("failed to parse dst addr %v", dst))
	}
	return packet{
		protocol: proto,
		srcAddr:  srcAddr.String(),
		dstAddr:  dstAddr.String(),
	}
}

var polProgramTests = []polProgramTest{
	// Tests of actions and flow control.
	{
		PolicyName: "no tiers",
		DroppedPackets: []packet{
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			icmpPkt("10.0.0.1", "10.0.0.2"),
			packetNoPorts(253, "10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "no tiers-v6",
		ForIPv6:    true,
		DroppedPackets: []packet{
			tcpPkt("[1001::1]:31245", "[1001::2]:80"),
			tcpPkt("[1001::1]:80", "[1001::2]:31245"),
			icmpPkt("[1001::1]", "[1001::2]"),
			packetNoPorts(253, "1001::1", "1002::2")},
	},
	{
		PolicyName: "empty tier has no impact",
		Policy: polprog.Rules{
			Tiers: []polprog.Tier{
				{
					Name:      "empty tier",
					EndAction: polprog.TierEndPass, // this would be set by the caller
				},
				{
					Name: "allow",
					Policies: []polprog.Policy{{
						Name: "allow all",
						Rules: []polprog.Rule{{Rule: &proto.Rule{
							Action: "Allow",
						}}},
					}},
				},
			},
		},
		AllowedPackets: []packet{
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			icmpPkt("10.0.0.1", "10.0.0.2"),
			packetNoPorts(253, "10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "empty tier has no impact-v6",
		ForIPv6:    true,
		Policy: polprog.Rules{
			Tiers: []polprog.Tier{
				{
					Name:      "empty tier",
					EndAction: polprog.TierEndPass, // this would be set by the caller
				},
				{
					Name: "allow",
					Policies: []polprog.Policy{{
						Name: "allow all",
						Rules: []polprog.Rule{{Rule: &proto.Rule{
							Action: "Allow",
						}}},
					}},
				},
			},
		},
		AllowedPackets: []packet{
			tcpPkt("[ffff::abcd:2]:31245", "[eeee::abcd:1]:80"),
			tcpPkt("[ffff::abcd:2]:80", "[eeee::abcd:1]:31245"),
			icmpPkt("[ffff::abcd:2]", "[eeee::abcd:1]"),
			packetNoPorts(253, "ffff::abcd:2", "eeee::abcd:1")},
	},
	{
		PolicyName: "unreachable tier",
		Policy: polprog.Rules{
			Tiers: []polprog.Tier{
				{
					Name: "allow all",
					Policies: []polprog.Policy{{
						Name: "allow all",
						Rules: []polprog.Rule{{Rule: &proto.Rule{
							Action: "Allow",
						}}},
					}},
				},
				{
					Name: "unreachable",
					Policies: []polprog.Policy{{
						Name: "deny all",
						Rules: []polprog.Rule{{Rule: &proto.Rule{
							Action: "Deny",
						}}},
					}},
				},
			},
		},
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "unreachable tier-v6",
		ForIPv6:    true,
		Policy: polprog.Rules{
			Tiers: []polprog.Tier{
				{
					Name: "allow all",
					Policies: []polprog.Policy{{
						Name: "allow all",
						Rules: []polprog.Rule{{Rule: &proto.Rule{
							Action: "Allow",
						}}},
					}},
				},
				{
					Name: "unreachable",
					Policies: []polprog.Policy{{
						Name: "deny all",
						Rules: []polprog.Rule{{Rule: &proto.Rule{
							Action: "Deny",
						}}},
					}},
				},
			},
		},
		AllowedPackets: []packet{
			tcpPkt("[1001::1]:31245", "[1001::2]:80"),
			tcpPkt("[1001::1]:80", "[1001::2]:31245"),
			icmpPkt("[1001::1]", "[1001::2]"),
			packetNoPorts(253, "1001::1", "1002::2")},
	},
	{
		PolicyName: "pass to nowhere",
		Policy: polprog.Rules{
			Tiers: []polprog.Tier{
				{
					Name: "pass",
					Policies: []polprog.Policy{{
						Name:  "pass rule",
						Rules: []polprog.Rule{{Rule: &proto.Rule{Action: "Pass"}}},
					}},
				},
			},
		},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "pass to nowhere-v6",
		ForIPv6:    true,
		Policy: polprog.Rules{
			Tiers: []polprog.Tier{
				{
					Name: "pass",
					Policies: []polprog.Policy{{
						Name:  "pass rule",
						Rules: []polprog.Rule{{Rule: &proto.Rule{Action: "Pass"}}},
					}},
				},
			},
		},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			tcpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "pass to allow",
		Policy: polprog.Rules{
			Tiers: []polprog.Tier{
				{
					Name: "pass",
					Policies: []polprog.Policy{{
						Name: "pass through",
						Rules: []polprog.Rule{
							{Rule: &proto.Rule{Action: "Pass"}},
							{Rule: &proto.Rule{Action: "Deny"}},
						},
					}},
				},
				{
					Name: "allow",
					Policies: []polprog.Policy{{
						Name: "allow all",
						Rules: []polprog.Rule{{Rule: &proto.Rule{
							Action: "Allow",
						}}},
					}},
				},
			},
		},
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "pass to allow-v6",
		ForIPv6:    true,
		Policy: polprog.Rules{
			Tiers: []polprog.Tier{
				{
					Name: "pass",
					Policies: []polprog.Policy{{
						Name: "pass through",
						Rules: []polprog.Rule{
							{Rule: &proto.Rule{Action: "Pass"}},
							{Rule: &proto.Rule{Action: "Deny"}},
						},
					}},
				},
				{
					Name: "allow",
					Policies: []polprog.Policy{{
						Name: "allow all",
						Rules: []polprog.Rule{{Rule: &proto.Rule{
							Action: "Allow",
						}}},
					}},
				},
			},
		},
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			tcpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "pass to deny",
		Policy: polprog.Rules{
			Tiers: []polprog.Tier{
				{
					Name: "pass",
					Policies: []polprog.Policy{{
						Name: "pass through",
						Rules: []polprog.Rule{
							{Rule: &proto.Rule{Action: "Pass"}},
							{Rule: &proto.Rule{Action: "Allow"}},
						},
					}},
				},
				{
					Name: "allow",
					Policies: []polprog.Policy{{
						Name: "deny all",
						Rules: []polprog.Rule{{Rule: &proto.Rule{
							Action: "Deny",
						}}},
					}},
				},
			},
		},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "pass to deny-v6",
		ForIPv6:    true,
		Policy: polprog.Rules{
			Tiers: []polprog.Tier{
				{
					Name: "pass",
					Policies: []polprog.Policy{{
						Name: "pass through",
						Rules: []polprog.Rule{
							{Rule: &proto.Rule{Action: "Pass"}},
							{Rule: &proto.Rule{Action: "Allow"}},
						},
					}},
				},
				{
					Name: "allow",
					Policies: []polprog.Policy{{
						Name: "deny all",
						Rules: []polprog.Rule{{Rule: &proto.Rule{
							Action: "Deny",
						}}},
					}},
				},
			},
		},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			tcpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "explicit allow",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "explicit allow-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			tcpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			udpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "explicit deny",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Deny",
		}}),
		DroppedPackets: []packet{
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "explicit deny-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Deny",
		}}),
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			tcpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			udpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},

	// Protocol match tests.
	{
		PolicyName: "allow tcp",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "allow tcp - v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			tcpPkt("[ff02::1]:80", "[ff02::2]:31245")},
		DroppedPackets: []packet{
			udpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "allow !tcp",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:      "Allow",
			NotProtocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
		DroppedPackets: []packet{
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245")},
	},
	{
		PolicyName: "allow !tcp-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:      "Allow",
			NotProtocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
		}}),
		AllowedPackets: []packet{
			udpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			tcpPkt("[ff02::1]:80", "[ff02::2]:31245")},
	},
	{
		PolicyName: "allow udp",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "udp"}},
		}}),
		AllowedPackets: []packet{
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "allow udp-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "udp"}},
		}}),
		AllowedPackets: []packet{
			udpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			tcpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},

	// CIDR tests.
	{
		PolicyName: "allow 10.0.0.1/32",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			SrcNet: []string{"10.0.0.1/32"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.2"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245")},
	},
	{
		PolicyName: "allow ff01::1/128",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			SrcNet: []string{"ff02::1/128"},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::3]:31245", "[ff02::2]:80"),
			udpPkt("[ff02::3]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::3]", "[ff02::2]"),
			packetNoPorts(253, "ff02::3", "ff02::2")},
	},
	{
		PolicyName: "allow from 10.0.0.0/8",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			SrcNet: []string{"10.0.0.0/8"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245")},
		DroppedPackets: []packet{
			packetNoPorts(253, "11.0.0.1", "10.0.0.2"),
			icmpPkt("11.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "allow ffe2::1/16",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			SrcNet: []string{"ffe2::1/16"},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ffe2::1]:31245", "[ffe2::2]:80"),
			udpPkt("[ffe2::1]:80", "[ffe2::2]:31245"),
			icmpPkt("[ffe2::1]", "[ffe2::2]"),
			packetNoPorts(253, "ffe2::1", "ffe2::2")},
		DroppedPackets: []packet{
			tcpPkt("[ffe1::3]:31245", "[ffe2::2]:80"),
			udpPkt("[ffe1::3]:80", "[ffe2::2]:31245"),
			icmpPkt("[ffe1::3]", "[ffe2::2]"),
			packetNoPorts(253, "ffe1::3", "ffe2::2")},
	},
	{
		PolicyName: "allow from CIDRs",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			SrcNet: []string{"102.0.0.0/8", "10.0.0.1/32", "11.0.0.1/32"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			icmpPkt("11.0.0.1", "10.0.0.2"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.2"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245")},
	},
	{
		PolicyName: "allow from CIDRs-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			SrcNet: []string{"ffee::1/16", "ffe2:0000:1111::1/64", "ffe2:0000:2222::1/80", "ffe2::f/128"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "ffee::1", "ffee::2"),
			icmpPkt("[ffe2:0000:1111::1]", "[ffff::2]"),
			udpPkt("[ffe2:0000:2222::1]:1024", "[ffe2::1]:80"),
			tcpPkt("[ffe2::f]:31245", "[::2]:80")},
		DroppedPackets: []packet{
			tcpPkt("[ffe0::2]:31245", "[ff01::2]:80"),
			udpPkt("[ffe2:0000:1112::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ffe2:0000:2222:0010::1]", "[ff02::2]"),
			packetNoPorts(253, "ffe2::e", "ff02::2")},
	},
	{
		PolicyName: "allow from !CIDRs",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:    "Allow",
			NotSrcNet: []string{"102.0.0.0/8", "10.0.0.1/32", "11.0.0.1/32"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.2"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			icmpPkt("11.0.0.1", "10.0.0.2"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80")},
	},
	{
		PolicyName: "allow from !CIDRs-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:    "Allow",
			NotSrcNet: []string{"ffee::1/16", "ffe2:0000:1111::1/64", "ffe2:0000:2222::1/80", "ffe2::f/128"},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ffe0::2]:31245", "[ff01::2]:80"),
			udpPkt("[ffe2:0000:1112::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ffe2:0000:2222:0010::1]", "[ff02::2]"),
			packetNoPorts(253, "ffe2::e", "ff02::2")},
		DroppedPackets: []packet{
			packetNoPorts(253, "ffee::1", "ffee::2"),
			icmpPkt("[ffe2:0000:1111::1]", "[ffff::2]"),
			udpPkt("[ffe2:0000:2222::1]:1024", "[ffe2::1]:80"),
			tcpPkt("[ffe2::f]:31245", "[::2]:80")},
	},
	{
		PolicyName: "allow to CIDRs",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			DstNet: []string{"102.0.0.0/8", "10.0.0.1/32", "11.0.0.1/32"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			udpPkt("10.0.0.2:12345", "123.0.0.1:1024")},
	},
	{
		PolicyName: "allow to CIDRs-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			DstNet: []string{"ffee::1/16", "ffe2:0000:1111::1/64", "ffe2:0000:2222::1/80", "ffe2::f/128"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "ffee::2", "ffee::1"),
			icmpPkt("[ffff::2]", "[ffe2:0000:1111::1]"),
			udpPkt("[ffe2::1]:80", "[ffe2:0000:2222::1]:1024"),
			tcpPkt("[::2]:80", "[ffe2::f]:31245")},
		DroppedPackets: []packet{
			tcpPkt("[ff01::2]:80", "[ffe0::2]:31245"),
			udpPkt("[ff02::2]:31245", "[ffe2:0000:1112::1]:80"),
			icmpPkt("[ff02::2]", "[ffe2:0000:2222:0010::1]"),
			packetNoPorts(253, "ff02::2", "ffe2::e")},
	},
	{
		PolicyName: "allow to !CIDRs",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:    "Allow",
			NotDstNet: []string{"102.0.0.0/8", "10.0.0.1/32", "11.0.0.1/32"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "123.0.0.1"),
			udpPkt("10.0.0.2:12345", "123.0.0.1:1024"),
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245")},
	},
	{
		PolicyName: "allow to !CIDRs-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:    "Allow",
			NotDstNet: []string{"ffee::1/16", "ffe2:0000:1111::1/64", "ffe2:0000:2222::1/80", "ffe2::f/128"},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff01::2]:80", "[ffe0::2]:31245"),
			udpPkt("[ff02::2]:31245", "[ffe2:0000:1112::1]:80"),
			icmpPkt("[ff02::2]", "[ffe2:0000:2222:0010::1]"),
			packetNoPorts(253, "ff02::2", "ffe2::e")},
		DroppedPackets: []packet{
			packetNoPorts(253, "ffee::2", "ffee::1"),
			icmpPkt("[ffff::2]", "[ffe2:0000:1111::1]"),
			udpPkt("[ffe2::1]:80", "[ffe2:0000:2222::1]:1024"),
			tcpPkt("[::2]:80", "[ffe2::f]:31245")},
	},
	{
		PolicyName: "allow from !10.0.0.0/8",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:    "Allow",
			NotSrcNet: []string{"10.0.0.0/8"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "10.0.0.1"),
			icmpPkt("11.0.0.1", "10.0.0.2")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245")},
	},
	{
		PolicyName: "allow to 10.0.0.1/32",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			DstNet: []string{"10.0.0.1/32"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2"),
			udpPkt("10.0.0.2:12345", "123.0.0.1:1024")},
	},
	{
		PolicyName: "allow to 10.0.0.0/8",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			DstNet: []string{"10.0.0.0/8"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			icmpPkt("11.0.0.1", "10.0.0.2")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "123.0.0.2"),
			udpPkt("10.0.0.2:12345", "123.0.0.1:1024")},
	},
	{
		PolicyName: "allow to !10.0.0.0/8",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:    "Allow",
			NotDstNet: []string{"10.0.0.0/8"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "123.0.0.2"),
			udpPkt("10.0.0.2:12345", "123.0.0.1:1024")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245")},
	},
	{
		PolicyName: "allow to 0.0.0.0/0",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			DstNet: []string{"0.0.0.0/0"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "192.168.0.1", "123.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			udpPkt("1.1.1.1:31245", "2.2.2.2:80"),
			icmpPkt("172.16.1.1", "172.17.2.2")},
		DroppedPackets: []packet{},
	},
	{
		PolicyName: "allow to !0.0.0.0/0",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:    "Allow",
			NotDstNet: []string{"0.0.0.0/0"},
		}}),
		AllowedPackets: []packet{},
		DroppedPackets: []packet{
			packetNoPorts(253, "192.168.0.1", "123.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			udpPkt("1.1.1.1:31245", "2.2.2.2:80"),
			icmpPkt("172.16.1.1", "172.17.2.2")},
	},
	{
		PolicyName: "allow from !ffe2::1/8",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:    "Allow",
			NotSrcNet: []string{"ffe2::/8"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "2::1", "::1"),
			icmpPkt("[ee00:2345::2]", "[::2]"),
			tcpPkt("[f002::1]:31245", "[ff02::2]:80"),
			udpPkt("[fa02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[::1]", "[ff01::2]"),
			packetNoPorts(253, "f002::1", "ff02::2")},
		DroppedPackets: []packet{
			packetNoPorts(253, "ff02::1", "::1"),
			icmpPkt("[ff00:2345::2]", "[::2]"),
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff01::1]", "[ff01::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "allow from !ffe2::/112",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:    "Allow",
			NotSrcNet: []string{"ffe2::1:0/112"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "2::1", "::1"),
			icmpPkt("[ee00:2345::2]", "[::2]"),
			tcpPkt("[f002::2:1]:31245", "[ff02::2]:80"),
			udpPkt("[fa02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[::1]", "[ff01::2]"),
			packetNoPorts(253, "ffe2::2:1", "ff02::2")},
		DroppedPackets: []packet{
			tcpPkt("[ffe2::1:1]:31245", "[ff02::2]:80"),
			packetNoPorts(253, "ffe2::1:1", "ff02::2")},
	},
	{
		PolicyName: "allow to ff00::1/128",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			DstNet: []string{"ff00::1/128"},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[f002::2:1]:31245", "[ff00::1]:80"),
			udpPkt("[fa02::1]:80", "[ff00::1]:31245"),
			icmpPkt("[::1]", "[ff00::1]"),
			packetNoPorts(253, "ffe2::2:1", "ff00::1")},
		DroppedPackets: []packet{
			tcpPkt("[ffe2::1:1]:31245", "[ff02::2]:80"),
			packetNoPorts(253, "ffe2::1:1", "ff00::2")},
	},
	{
		PolicyName: "allow to ff00::/64",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			DstNet: []string{"ff00::/64"},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[f002::2:1]:31245", "[ff00::1]:80"),
			udpPkt("[fa02::1]:80", "[ff00::2]:31245"),
			icmpPkt("[::1]", "[ff00::ffff:1]"),
			packetNoPorts(253, "ffe2::2:1", "ff00:0:0:0:f::1:2")},
		DroppedPackets: []packet{
			tcpPkt("[ffe2::1:1]:31245", "[ff00:0:0:1:f::1:2]:80"),
			packetNoPorts(253, "ffe2::1:1", "ff01::2")},
	},
	{
		PolicyName: "allow to !ff00::1/64",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:    "Allow",
			NotDstNet: []string{"ff00::/64"},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ffe2::1:1]:31245", "[ff00:0:0:1:f::1:2]:80"),
			packetNoPorts(253, "ffe2::1:1", "ff01::2")},
		DroppedPackets: []packet{
			tcpPkt("[f002::2:1]:31245", "[ff00::1]:80"),
			udpPkt("[fa02::1]:80", "[ff00::2]:31245"),
			icmpPkt("[::1]", "[ff00::ffff:1]"),
			packetNoPorts(253, "ffe2::2:1", "ff00:0:0:0:f::1:2")},
	},
	{
		PolicyName: "allow to !ff00::1/16",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:    "Allow",
			NotDstNet: []string{"ff00::/16"},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ffe2::1:1]:31245", "[ff10::1:2]:80"),
			packetNoPorts(253, "ffe2::1:1", "ff01::2")},
		DroppedPackets: []packet{
			tcpPkt("[f002::2:1]:31245", "[ff00::1]:80"),
			udpPkt("[fa02::1]:80", "[ff00::2]:31245"),
			icmpPkt("[::1]", "[ff00::ffff:1]"),
			packetNoPorts(253, "ffe2::2:1", "ff00:0:0:0:f::1:2")},
	},
	{
		PolicyName: "allow to ::/0",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			DstNet: []string{"::/0"},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ffe2::1:1]:31245", "[ff10::1:2]:80"),
			udpPkt("[fa02::1]:80", "[ff00::2]:31245"),
			icmpPkt("[::1]", "[ff00::ffff:1]"),
			packetNoPorts(253, "ffe2::1:1", "ff01::2")},
		DroppedPackets: []packet{},
	},
	{
		PolicyName: "allow to !::/0",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:    "Allow",
			NotDstNet: []string{"::/0"},
		}}),
		AllowedPackets: []packet{},
		DroppedPackets: []packet{
			tcpPkt("[ffe2::1:1]:31245", "[ff10::1:2]:80"),
			udpPkt("[fa02::1]:80", "[ff00::2]:31245"),
			icmpPkt("[::1]", "[ff00::ffff:1]"),
			packetNoPorts(253, "ffe2::1:1", "ff01::2")},
	},

	// Port tests.
	{
		PolicyName: "allow from tcp:80",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			SrcPorts: []*proto.PortRange{{
				First: 80,
				Last:  80,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "allow from tcp:80-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			SrcPorts: []*proto.PortRange{{
				First: 80,
				Last:  80,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:80", "[ff02::2]:31245")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "allow from tcp:80-81",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			SrcPorts: []*proto.PortRange{{
				First: 80,
				Last:  81,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			tcpPkt("10.0.0.2:81", "10.0.0.1:31245")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.2:79", "10.0.0.1:31245"),
			tcpPkt("10.0.0.2:82", "10.0.0.1:31245"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245")},
	},
	{
		PolicyName: "allow from tcp:80-81-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			SrcPorts: []*proto.PortRange{{
				First: 80,
				Last:  81,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:80", "[ff02::2]:12345"),
			tcpPkt("[ff02::1]:81", "[ff02::2]:23456")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "allow from tcp:0-80",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			SrcPorts: []*proto.PortRange{{
				First: 0,
				Last:  80,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("10.0.0.2:0", "10.0.0.1:31245"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.2:81", "10.0.0.1:31245")},
	},
	{
		PolicyName: "allow from tcp:0-80-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			SrcPorts: []*proto.PortRange{{
				First: 0,
				Last:  80,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:0", "[ff02::2]:12345"),
			tcpPkt("[ff02::1]:30", "[ff02::2]:12345"),
			tcpPkt("[ff02::1]:80", "[ff02::2]:23456")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:81", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "allow to tcp:80-65535",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			DstPorts: []*proto.PortRange{{
				First: 80,
				Last:  65535,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:65535")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:79")},
	},
	{
		PolicyName: "allow to tcp:80-65535-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			DstPorts: []*proto.PortRange{{
				First: 80,
				Last:  65535,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:81", "[ff02::2]:80"),
			tcpPkt("[ff02::1]:81", "[ff02::2]:65535")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:81", "[ff02::2]:79"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "allow to tcp:ranges",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			DstPorts: []*proto.PortRange{
				{First: 80, Last: 81},
				{First: 90, Last: 90},
			},
		}}),
		AllowedPackets: []packet{
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:81"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:90")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.1", "10.0.0.2"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:79"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:82"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:89"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:91"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80")},
	},
	{
		PolicyName: "allow to tcp:ranges-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			DstPorts: []*proto.PortRange{
				{First: 80, Last: 81},
				{First: 90, Last: 90},
			},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			tcpPkt("[ff02::1]:31245", "[ff02::2]:81"),
			tcpPkt("[ff02::1]:31245", "[ff02::2]:90")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:1001", "[ff02::2]:79"),
			tcpPkt("[ff02::1]:1001", "[ff02::2]:82"),
			tcpPkt("[ff02::1]:1001", "[ff02::2]:89"),
			tcpPkt("[ff02::1]:1001", "[ff02::2]:91"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "allow to tcp:!ranges",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			NotDstPorts: []*proto.PortRange{
				{First: 80, Last: 81},
				{First: 90, Last: 90},
			},
		}}),
		AllowedPackets: []packet{
			tcpPkt("10.0.0.1:31245", "10.0.0.2:79"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:82"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:89"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:91")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:81"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:90"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80")},
	},
	{
		PolicyName: "allow to tcp:!ranges-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			NotDstPorts: []*proto.PortRange{
				{First: 80, Last: 81},
				{First: 90, Last: 90},
			},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:1001", "[ff02::2]:79"),
			tcpPkt("[ff02::1]:1001", "[ff02::2]:82"),
			tcpPkt("[ff02::1]:1001", "[ff02::2]:89"),
			tcpPkt("[ff02::1]:1001", "[ff02::2]:91")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:1001", "[ff02::2]:80"),
			tcpPkt("[ff02::1]:1001", "[ff02::2]:81"),
			tcpPkt("[ff02::1]:1001", "[ff02::2]:90"),
			udpPkt("[ff02::1]:80", "[ff02::2]:90"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "allow from tcp:!80",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			NotSrcPorts: []*proto.PortRange{{
				First: 80,
				Last:  80,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "allow from tcp:!80-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			NotSrcPorts: []*proto.PortRange{{
				First: 80,
				Last:  80,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:80", "[ff02::2]:90"),
			udpPkt("[ff02::1]:80", "[ff02::2]:90"),
			udpPkt("[ff02::1]:31245", "[ff02::2]:90"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "allow to tcp:80",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			DstPorts: []*proto.PortRange{{
				First: 80,
				Last:  80,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "allow to tcp:80-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			DstPorts: []*proto.PortRange{{
				First: 80,
				Last:  80,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:80")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:80", "[ff02::2]:90"),
			udpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:90"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		// BPF immediate values are signed, check that we don't get tripped up by a sign extension.
		PolicyName: "allow to tcp:65535",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			DstPorts: []*proto.PortRange{{
				First: 65535,
				Last:  65535,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("10.0.0.1:31245", "10.0.0.2:65535")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245")},
	},
	{
		// BPF immediate values are signed, check that we don't get tripped up by a sign extension.
		PolicyName: "allow to tcp:65535-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			DstPorts: []*proto.PortRange{{
				First: 65535,
				Last:  65535,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:31245", "[ff02::2]:65535")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},
	{
		PolicyName: "allow to tcp:!80",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			NotDstPorts: []*proto.PortRange{{
				First: 80,
				Last:  80,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
	},
	{
		PolicyName: "allow to tcp:!80-v6",
		ForIPv6:    true,
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			NotDstPorts: []*proto.PortRange{{
				First: 80,
				Last:  80,
			}},
		}}),
		AllowedPackets: []packet{
			tcpPkt("[ff02::1]:80", "[ff02::2]:31245")},
		DroppedPackets: []packet{
			tcpPkt("[ff02::1]:80", "[ff02::2]:80"),
			udpPkt("[ff02::1]:80", "[ff02::2]:31245"),
			udpPkt("[ff02::1]:31245", "[ff02::2]:80"),
			icmpPkt("[ff02::1]", "[ff02::2]"),
			packetNoPorts(253, "ff02::1", "ff02::2")},
	},

	// IP set tests.
	// TODO: Add test cases for IPv6
	{
		PolicyName: "allow from empty IP set",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:      "Allow",
			Protocol:    &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			SrcIpSetIds: []string{"setA"},
		}}),
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
		IPSets: map[string][]string{
			"setA": {},
		},
	},
	{
		PolicyName: "allow from !empty IP set",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:         "Allow",
			Protocol:       &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			NotSrcIpSetIds: []string{"setA"},
		}}),
		AllowedPackets: []packet{
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
		IPSets: map[string][]string{
			"setA": {},
		},
	},
	{
		PolicyName: "allow from IP set",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:      "Allow",
			SrcIpSetIds: []string{"setA"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.2:12345", "123.0.0.1:1024"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
		DroppedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "10.0.0.1"),
			tcpPkt("11.0.0.1:12345", "10.0.0.2:8080")},
		IPSets: map[string][]string{
			"setA": {"10.0.0.0/8"},
		},
	},
	{
		PolicyName: "allow from IP set - v6",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:      "Allow",
			SrcIpSetIds: []string{"setA"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "10::2", "10::1"),
			tcpPkt("[10::2]:80", "[10::1]:31245"),
			udpPkt("[10::2]:12345", "[123::1]:1024"),
			udpPkt("[10::2]:80", "[10::1]:31245"),
			udpPkt("[10::1]:31245", "[10::2]:80"),
			//			icmpPkt("10::1", "10::2"),
		},
		DroppedPackets: []packet{
			packetNoPorts(253, "11::2", "10::1"),
			tcpPkt("[11::1]:12345", "[10::2]:8080")},
		IPSets: map[string][]string{
			"setA": {"10::0/16"},
		},
		ForIPv6: true,
	},
	{
		PolicyName: "allow to IP set",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:      "Allow",
			DstIpSetIds: []string{"setA"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "11.0.0.1"),
			udpPkt("10.0.0.2:12345", "123.0.0.1:1024")},
		DroppedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "10.0.0.1"),
			tcpPkt("11.0.0.1:12345", "10.0.0.2:8080"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80")},
		IPSets: map[string][]string{
			"setA": {"11.0.0.0/8", "123.0.0.1/32"},
		},
	},
	{
		PolicyName: "allow to IP set - v6",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:      "Allow",
			DstIpSetIds: []string{"setA"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "11::2", "11::1"),
			udpPkt("[10::2]:12345", "[123::1]:1024")},
		DroppedPackets: []packet{
			packetNoPorts(253, "11::2", "10::1"),
			tcpPkt("[11::1]:12345", "[10::2]:8080"),
			udpPkt("[10::1]:31245", "[10::2]:80")},
		IPSets: map[string][]string{
			"setA": {"11::0/16", "123::1/128"},
		},
		ForIPv6: true,
	},
	{
		PolicyName: "allow from !IP set",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:         "Allow",
			NotSrcIpSetIds: []string{"setA"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "10.0.0.1"),
			tcpPkt("11.0.0.1:12345", "10.0.0.2:8080")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.1"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.2:12345", "123.0.0.1:1024"),
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			icmpPkt("10.0.0.1", "10.0.0.2")},
		IPSets: map[string][]string{
			"setA": {"10.0.0.0/8"},
		},
	},
	{
		PolicyName: "allow to !IP set",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:         "Allow",
			NotDstIpSetIds: []string{"setA"},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "10.0.0.1"),
			tcpPkt("11.0.0.1:12345", "10.0.0.2:8080"),
			udpPkt("10.0.0.1:31245", "10.0.0.2:80")},
		DroppedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "11.0.0.1"),
			udpPkt("10.0.0.2:12345", "123.0.0.1:1024")},
		IPSets: map[string][]string{
			"setA": {"11.0.0.0/8", "123.0.0.1/32"},
		},
	},
	{
		PolicyName: "allow to named port",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:               "Allow",
			DstNamedPortIpSetIds: []string{"setA"},
		}}),
		AllowedPackets: []packet{
			udpPkt("10.0.0.2:12345", "123.0.0.1:1024"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80")},
		DroppedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "10.0.0.2"), // Wrong proto, no ports
			tcpPkt("11.0.0.1:12345", "10.0.0.2:8080"),  // Wrong port
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),    // Wrong proto
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),    // Src/dest confusion
			tcpPkt("10.0.0.2:31245", "10.0.0.1:80"),    // Wrong dest
		},
		IPSets: map[string][]string{
			"setA": {"10.0.0.2/32,tcp:80", "123.0.0.1/32,udp:1024"},
		},
	},
	{
		PolicyName: "allow to named ports",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:               "Allow",
			DstNamedPortIpSetIds: []string{"setA", "setB"},
		}}),
		AllowedPackets: []packet{
			udpPkt("10.0.0.2:12345", "123.0.0.1:1024"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80")},
		DroppedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "10.0.0.2"), // Wrong proto, no ports
			tcpPkt("11.0.0.1:12345", "10.0.0.2:8080"),  // Wrong port
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),    // Wrong proto
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),    // Src/dest confusion
			tcpPkt("10.0.0.2:31245", "10.0.0.1:80"),    // Wrong dest
		},
		IPSets: map[string][]string{
			"setA": {"10.0.0.2/32,tcp:80"},
			"setB": {"123.0.0.1/32,udp:1024"},
		},
	},
	{
		PolicyName: "allow to named ports - v6",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:               "Allow",
			DstNamedPortIpSetIds: []string{"setA", "setB"},
		}}),
		AllowedPackets: []packet{
			udpPkt("[10::2]:12345", "[123::1]:1024"),
			tcpPkt("[10::1]:31245", "[10::2]:80")},
		DroppedPackets: []packet{
			packetNoPorts(253, "11::2", "10::2"),    // Wrong proto, no ports
			tcpPkt("[11::1]:12345", "[10::2]:8080"), // Wrong port
			udpPkt("[10::1]:31245", "[10::2]:80"),   // Wrong proto
			tcpPkt("[10::2]:80", "[10::1]:31245"),   // Src/dest confusion
			tcpPkt("[10::2]:31245", "[10::1]:80"),   // Wrong dest
		},
		IPSets: map[string][]string{
			"setA": {"10::2/128,tcp:80"},
			"setB": {"123::1/128,udp:1024"},
		},
		ForIPv6: true,
	},
	{
		PolicyName: "allow to mixed ports",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			// Should match either port or named port
			DstPorts: []*proto.PortRange{
				{First: 81, Last: 82},
				{First: 90, Last: 90},
			},
			DstNamedPortIpSetIds: []string{"setA", "setB"},
		}}),
		AllowedPackets: []packet{
			udpPkt("10.0.0.2:12345", "123.0.0.1:1024"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:90"),
			tcpPkt("10.0.0.1:31245", "10.0.0.2:82")},
		DroppedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "10.0.0.2"), // Wrong proto, no ports
			tcpPkt("11.0.0.1:12345", "10.0.0.2:8080"),  // Wrong port
			udpPkt("10.0.0.1:31245", "10.0.0.2:80"),    // Wrong proto
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245"),    // Src/dest confusion
			tcpPkt("10.0.0.2:31245", "10.0.0.1:80"),    // Wrong dest
		},
		IPSets: map[string][]string{
			"setA": {"10.0.0.2/32,tcp:80"},
			"setB": {"123.0.0.1/32,udp:1024"},
		},
	},
	{
		PolicyName: "allow from named port",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:               "Allow",
			SrcNamedPortIpSetIds: []string{"setA"},
		}}),
		AllowedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.2"), // Wrong proto, no ports
			tcpPkt("10.0.0.2:8080", "11.0.0.1:12345"),  // Wrong port
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),    // Wrong proto
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),    // Src/dest confusion
			tcpPkt("10.0.0.1:80", "10.0.0.2:31245"),    // Wrong src
		},
		IPSets: map[string][]string{
			"setA": {"10.0.0.2/32,tcp:80", "123.0.0.1/32,udp:1024"},
		},
	},
	{
		PolicyName: "allow from named ports",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:               "Allow",
			SrcNamedPortIpSetIds: []string{"setA", "setB"},
		}}),
		AllowedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345"),
			tcpPkt("10.0.0.2:80", "10.0.0.1:31245")},
		DroppedPackets: []packet{
			packetNoPorts(253, "10.0.0.2", "10.0.0.2"), // Wrong proto, no ports
			tcpPkt("10.0.0.2:8080", "11.0.0.1:12345"),  // Wrong port
			udpPkt("10.0.0.2:80", "10.0.0.1:31245"),    // Wrong proto
			tcpPkt("10.0.0.1:31245", "10.0.0.2:80"),    // Src/dest confusion
			tcpPkt("10.0.0.1:80", "10.0.0.2:31245"),    // Wrong src
		},
		IPSets: map[string][]string{
			"setA": {"10.0.0.2/32,tcp:80"},
			"setB": {"123.0.0.1/32,udp:1024"},
		},
	},
	// ICMP tests
	// TODO: Add test cases for IPv6
	{
		PolicyName: "allow icmp packet with type 8",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			Icmp:   &proto.Rule_IcmpType{IcmpType: 8},
		}}),
		AllowedPackets: []packet{
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 8, 0)},
		DroppedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "10.0.0.2"), // Wrong proto
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 10, 0)},
	},
	{
		PolicyName: "allow icmp packet with type 8 and code 3",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action: "Allow",
			Icmp:   &proto.Rule_IcmpTypeCode{IcmpTypeCode: &proto.IcmpTypeAndCode{Type: 8, Code: 3}},
		}}),
		AllowedPackets: []packet{
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 8, 3)},
		DroppedPackets: []packet{
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 10, 0),
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 10, 3),
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 8, 4)},
	},
	{
		PolicyName: "allow icmp packet with type not equal to 8",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:  "Allow",
			NotIcmp: &proto.Rule_NotIcmpType{NotIcmpType: 8},
		}}),
		AllowedPackets: []packet{
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 10, 0)},
		DroppedPackets: []packet{
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 8, 0)},
	},
	{
		PolicyName: "allow icmp packet with type not equal to 8 and code not equal to 3",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:  "Allow",
			NotIcmp: &proto.Rule_NotIcmpTypeCode{NotIcmpTypeCode: &proto.IcmpTypeAndCode{Type: 8, Code: 3}},
		}}),
		AllowedPackets: []packet{
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 10, 0),
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 8, 4),
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 10, 3)},
		DroppedPackets: []packet{
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 8, 3)},
	},
	// Generic protocol tests.
	{
		PolicyName: "Protocol match",
		Policy: makeRulesSingleTier([]*proto.Rule{{
			Action:   "Allow",
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 253}},
		}}),
		AllowedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "10.0.0.2"),
		},
		DroppedPackets: []packet{
			icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 10, 0),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
			packetNoPorts(254, "11.0.0.2", "10.0.0.2"),
		},
	},
}

var hostPolProgramTests = []polProgramTest{
	{
		PolicyName: "no policy",
		Policy: polprog.Rules{
			ForHostInterface: true,
		},
		AllowedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.10:53"),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.11:53"),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").preNAT("10.0.0.2:12345"),
			udpPkt("123.0.0.1:1024", "10.96.0.11:53"),
		},
		DroppedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.10:53").fromHost(),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").fromHost(),
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.11:53").toHost(),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").preNAT("10.0.0.2:12345").toHost(),
			udpPkt("123.0.0.1:1024", "10.96.0.11:53").toHost(),
		},
	},
	{
		PolicyName: "pre-DNAT",
		Policy: polprog.Rules{
			ForHostInterface: true,
			HostPreDnatTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDestElseDeny("p1", "10.96.0.10/32"),
			}},
		},
		AllowedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "10.96.0.10"),
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.10:53"),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
		},
		DroppedPackets: []packet{
			packetNoPorts(253, "11.0.0.2", "10.0.0.10"),
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.11:53"),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").preNAT("10.0.0.2:12345"),
			udpPkt("123.0.0.1:1024", "10.96.0.11:53"),
		},
	},
	{
		PolicyName: "apply-on-forward",
		Policy: polprog.Rules{
			ForHostInterface: true,
			HostForwardTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDestElseDeny("p1", "10.96.0.10/32"),
			}},
		},
		AllowedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").preNAT("10.0.0.2:12345"),
		},
		DroppedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.96.0.11:53"),
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.10:53"),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").toHost(),
		},
	},
	{
		PolicyName: "normal host policy",
		Policy: polprog.Rules{
			ForHostInterface: true,
			HostNormalTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDestElseDeny("p1", "10.96.0.10/32"),
			}},
		},
		AllowedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").preNAT("10.0.0.2:12345"),
			udpPkt("123.0.0.1:1024", "10.96.0.11:53"),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").fromHost(),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").preNAT("10.0.0.2:12345").toHost(),
		},
		DroppedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.10:53").fromHost(),
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.11:53").toHost(),
			udpPkt("123.0.0.1:1024", "10.96.0.11:53").toHost(),
		},
	},
	{
		PolicyName: "AoF + normal",
		Policy: polprog.Rules{
			ForHostInterface: true,
			HostForwardTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDestElseDeny("p1", "10.96.0.10/32"),
			}},
			HostNormalTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDestElseDeny("p2", "10.96.5.0/24"),
			}},
		},
		AllowedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
			udpPkt("123.0.0.1:1024", "10.96.5.10:53").toHost(),
			udpPkt("123.0.0.1:1024", "10.96.5.10:53").fromHost(),
		},
		DroppedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.96.5.10:53"),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").toHost(),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").fromHost(),
		},
	},
	{
		PolicyName: "AoF + suppressed normal",
		Policy: polprog.Rules{
			ForHostInterface: false,
			HostForwardTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDestElseDeny("p1", "10.96.0.10/32"),
			}},
			HostNormalTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDestElseDeny("p2", "10.96.5.0/24"),
			}},
			SuppressNormalHostPolicy: true,
			// Workload policy.
			Tiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDestElseDeny("p1", "10.96.0.10/32"),
			}},
		},
		AllowedPackets: []packet{
			// Allowed by workload and AoF host policy.
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
			// Allowed by workload policy, normal host policy suppressed.
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").toHost(),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").fromHost(),
		},
		DroppedPackets: []packet{
			// Denied by workload policy.
			udpPkt("123.0.0.1:1024", "10.96.5.10:53"),
			udpPkt("123.0.0.1:1024", "10.96.5.10:53").toHost(),
			udpPkt("123.0.0.1:1024", "10.96.5.10:53").fromHost(),
		},
	},
	{
		PolicyName: "pre-DNAT policy + normal profiles",
		Policy: polprog.Rules{
			ForHostInterface: true,
			HostPreDnatTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDest("p1", "10.96.0.10/32"),
			}},
			HostProfiles: allowDest("p2", "10.96.5.0/24"),
		},
		AllowedPackets: []packet{
			// Allowed by pre-DNAT policy.
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").toHost(),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").fromHost(),
			// Passed by pre-DNAT policy.  No AoF policy.
			udpPkt("123.0.0.1:1024", "10.96.5.10:53"),
			// Passed by pre-DNAT policy.  Allowed by normal profile.
			udpPkt("123.0.0.1:1024", "10.96.5.10:53").toHost(),
			udpPkt("123.0.0.1:1024", "10.96.5.10:53").fromHost(),
			// Allowed by pre-DNAT policy.
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.10:53").fromHost(),
		},
		DroppedPackets: []packet{
			// Passed by pre-DNAT policy.  Denied by normal profile.
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").preNAT("10.0.0.2:12345").toHost(),
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.11:53").toHost(),
		},
	},
	{
		PolicyName: "pre-DNAT + workload",
		Policy: polprog.Rules{
			ForHostInterface: false,
			HostPreDnatTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDest("p1", "10.96.0.10/31"),
			}},
			// Workload policy.
			Tiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "deny",
				Policies:  allowDest("p1", "10.96.0.10/32"),
			}},
			SuppressNormalHostPolicy: true,
		},
		AllowedPackets: []packet{
			// Allowed by pre-DNAT and workload.
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").toHost(),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").fromHost(),
			// Passed by pre-DNAT.  Allowed by workload.
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").preNAT("10.0.0.2:12345").toHost(),
		},
		DroppedPackets: []packet{
			// Allowed by pre-DNAT.  Denied by workload.
			udpPkt("123.0.0.1:1024", "10.96.0.11:53"),
			udpPkt("123.0.0.1:1024", "10.96.0.11:53").toHost(),
			udpPkt("123.0.0.1:1024", "10.96.0.11:53").fromHost(),
			// Allowed pre-DNAT.  Post-NAT IP denied by workload.
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.10:53").fromHost(),
			// Passed by pre-DNAT.  Post-NAT IP denied by workload.
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.11:53").toHost(),
		},
	},
	{
		PolicyName: "AoF + workload",
		Policy: polprog.Rules{
			ForHostInterface: false,
			HostForwardTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDestElseDeny("p1", "10.96.0.11/32"),
			}},
			// Workload policy.
			Tiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "deny",
				Policies:  allowDest("p1", "10.96.0.10/31"),
			}},
			SuppressNormalHostPolicy: true,
		},
		AllowedPackets: []packet{
			// Allowed by AoF and workload.
			udpPkt("123.0.0.1:1024", "10.96.0.11:53"),
			// Allowed by workload; normal host policy suppressed.
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").toHost(),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").fromHost(),
			udpPkt("123.0.0.1:1024", "10.96.0.10:53").preNAT("10.0.0.2:12345").toHost(),
		},
		DroppedPackets: []packet{
			// Denied by AoF.
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
			// Allowed by AoF.  Denied by workload.
			udpPkt("123.0.0.1:1024", "10.0.0.2:12345").preNAT("10.96.0.11:53").toHost(),
		},
	},
}

var xdpPolProgramTests = []polProgramTest{
	{
		PolicyName: "XDP allow else deny",
		Policy: polprog.Rules{
			ForXDP:           true,
			ForHostInterface: true,
			HostNormalTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDestElseDeny("p1", "10.96.0.10/32"),
			}},
		},
		AllowedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
		},
		DroppedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.96.0.11:53"),
		},
	},
	{
		PolicyName: "XDP allow some",
		Policy: polprog.Rules{
			ForXDP:           true,
			ForHostInterface: true,
			HostNormalTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  allowDest("p1", "10.96.0.10/32"),
			}},
		},
		AllowedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
		},
		UnmatchedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.96.0.11:53"),
		},
	},
	{
		PolicyName: "XDP deny some",
		Policy: polprog.Rules{
			ForXDP:           true,
			ForHostInterface: true,
			HostNormalTiers: []polprog.Tier{{
				Name:      "default",
				EndAction: "pass",
				Policies:  denyDest("p1", "10.96.0.10/32"),
			}},
		},
		DroppedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.96.0.10:53"),
		},
		UnmatchedPackets: []packet{
			udpPkt("123.0.0.1:1024", "10.96.0.11:53"),
		},
	},
}

func allowDestElseDeny(name, dst string) []polprog.Policy {
	return []polprog.Policy{{
		Name: name,
		Rules: []polprog.Rule{{
			Rule: &proto.Rule{
				Action: "Allow",
				DstNet: []string{dst},
			}}, {
			Rule: &proto.Rule{
				Action: "Deny",
			}},
		}},
	}
}

func allowDest(name, dst string) []polprog.Policy {
	return []polprog.Policy{{
		Name: name,
		Rules: []polprog.Rule{{
			Rule: &proto.Rule{
				Action: "Allow",
				DstNet: []string{dst},
			}},
		}},
	}
}

func denyDest(name, dst string) []polprog.Policy {
	return []polprog.Policy{{
		Name: name,
		Rules: []polprog.Rule{{
			Rule: &proto.Rule{
				Action: "Deny",
				DstNet: []string{dst},
			}},
		}},
	}
}

// polProgramTestWrapper allows to keep polProgramTest intact as well as the tests that
// use it. The wrapped object satisfies testPolicy interface that allows to use the same
// algo for testing with different testcase options.
type polProgramTestWrapper struct {
	p polProgramTest
}

func (w polProgramTestWrapper) Policy() polprog.Rules {
	return w.p.Policy
}

func (w polProgramTestWrapper) IPSets() map[string][]string {
	return w.p.IPSets
}

func (w polProgramTestWrapper) AllowedPackets() []testCase {
	ret := make([]testCase, len(w.p.AllowedPackets))
	for i, p := range w.p.AllowedPackets {
		ret[i] = p
	}

	return ret
}

func (w polProgramTestWrapper) DroppedPackets() []testCase {
	ret := make([]testCase, len(w.p.DroppedPackets))
	for i, p := range w.p.DroppedPackets {
		ret[i] = p
	}

	return ret
}

func (w polProgramTestWrapper) UnmatchedPackets() []testCase {
	ret := make([]testCase, len(w.p.UnmatchedPackets))
	for i, p := range w.p.UnmatchedPackets {
		ret[i] = p
	}

	return ret
}

func (w polProgramTestWrapper) XDP() bool {
	return w.p.Policy.ForXDP
}

func (w polProgramTestWrapper) ForIPv6() bool {
	return w.p.ForIPv6
}

func (w polProgramTestWrapper) Setup() error {
	if w.p.SetupCB != nil {
		return w.p.SetupCB()
	}

	return nil
}

func (w polProgramTestWrapper) TearDown() error {
	if w.p.TearDownCB != nil {
		return w.p.TearDownCB()
	}

	return nil
}

func wrap(p polProgramTest) polProgramTestWrapper {
	return polProgramTestWrapper{p}
}

func TestPolicyPrograms(t *testing.T) {
	for i, p := range polProgramTests {
		t.Run(fmt.Sprintf("%d:Policy=%s", i, p.PolicyName), func(t *testing.T) { runTest(t, wrap(p)) })
	}
}

func TestExpandedPolicyPrograms(t *testing.T) {
	RegisterTestingT(t)
	for i, p := range polProgramTests {
		for _, expander := range testExpanders {
			expandedP := expander.Expand(p)
			Expect(expandedP).NotTo(Equal(p))
			t.Run(fmt.Sprintf("%s/%d:Policy=%s", expander.Name, i, p.PolicyName),
				func(t *testing.T) {
					// Expansions result ina  lot of debug output, disable that.
					logLevel := log.GetLevel()
					defer log.SetLevel(logLevel)
					log.SetLevel(log.InfoLevel)

					runTest(t, wrap(expandedP), expandedP.Options...)
				})
		}
	}
}

func execSysctl(param, value string) error {
	cmd := exec.Command("sysctl", "-w", fmt.Sprintf("%s=%s", param, value))
	_, err := cmd.CombinedOutput()
	return err
}

var testExpanders = []testExpander{
	{
		Name: "WithLargePrefixedTier",
		Expand: func(p polProgramTest) polProgramTest {
			out := p
			initExtraTierOnce.Do(initExtraTier)
			out.Policy.Tiers = append([]polprog.Tier{extraTier}, out.Policy.Tiers...)
			return out
		},
	},
}

var extraTier polprog.Tier
var initExtraTierOnce sync.Once

func initExtraTier() {
	const numExtraPols = 250
	const numRulesPerPol = 50
	pols := make([]polprog.Policy, 0, numExtraPols)
	for i := 0; i < numExtraPols; i++ {
		pol := polprog.Policy{
			Name: fmt.Sprintf("pol-%d", i),
		}
		for j := 0; j < numRulesPerPol; j++ {
			pol.Rules = append(pol.Rules, noOpRule(i*numRulesPerPol+j))
		}
		pols = append(pols, pol)
	}
	// Need a pass rule somewhere to send traffic to the tier under
	// test.
	passRule := polprog.Rule{
		Rule: &proto.Rule{
			Action: "pass",
		},
		MatchID: polprog.RuleMatchID(numExtraPols * numRulesPerPol),
	}
	pols[len(pols)-1].Rules = append(pols[len(pols)-1].Rules, passRule)
	extraTier = polprog.Tier{
		Name:     "extra tier",
		Policies: pols,
	}
}
func noOpRule(n int) polprog.Rule {
	actions := []string{
		"allow", "deny", "pass",
	}
	ports := []*proto.PortRange{
		{First: 1, Last: int32(1 + (n % 8000))},
	}
	if n%1000 == 0 {
		// Add lots of ports to a handful of rules.
		for p := 0; p < 2000; p++ {
			ports = append(ports, &proto.PortRange{
				First: int32(p*2 + 10000),
				Last:  int32(p*2 + 10001),
			})
		}
	}
	r := polprog.Rule{
		Rule: &proto.Rule{
			SrcIpSetIds: []string{"setNoOp"},
			Protocol:    &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
			Action:      actions[n%len(actions)],
			DstPorts:    ports,
		},
		MatchID: polprog.RuleMatchID(n),
	}
	return r
}

type testExpander struct {
	Name   string
	Expand func(p polProgramTest) polProgramTest
}

type testFlowLogCase struct {
	packet  packet
	matches []uint64
}

func (tc testFlowLogCase) ForIPv6() bool {
	// We are not supporting IPv6 yet
	return false
}

func (tc testFlowLogCase) StateIn() state.State {
	return tc.packet.StateIn()
}

func (tc testFlowLogCase) String() string {
	return tc.packet.String()
}

func (tc testFlowLogCase) MatchStateOut(stateOut state.State) {
	// Check no other fields got clobbered.
	s := tc.StateIn()

	// We do not record more then state.MaxRuleIDs as we do not have more space
	s.RulesHit = uint32(len(tc.matches))
	if s.RulesHit > state.MaxRuleIDs {
		s.RulesHit = uint32(state.MaxRuleIDs)
	}
	copy(s.RuleIDs[:], tc.matches[:int(s.RulesHit)])

	// Zero parts we do not care about
	s.PolicyRC = 0 // PolicyRC tested by the caller
	stateOut.PolicyRC = 0

	Expect(stateOut).To(Equal(s), "policy program modified unexpected parts of the state")
}

type testFlowLog struct {
	policy         polprog.Rules
	allowedPackets []testFlowLogCase
	droppedPackets []testFlowLogCase
	ipSets         map[string][]string
}

func (t testFlowLog) UnmatchedPackets() []testCase {
	return nil
}

func (t testFlowLog) XDP() bool {
	return false
}

func (t testFlowLog) ForIPv6() bool {
	return false
}

func (t testFlowLog) Policy() polprog.Rules {
	return t.policy
}

func (t testFlowLog) AllowedPackets() []testCase {
	ret := make([]testCase, len(t.allowedPackets))
	for i, p := range t.allowedPackets {
		ret[i] = p
	}

	return ret
}

func (t testFlowLog) DroppedPackets() []testCase {
	ret := make([]testCase, len(t.droppedPackets))
	for i, p := range t.droppedPackets {
		ret[i] = p
	}

	return ret
}

func (t testFlowLog) IPSets() map[string][]string {
	return t.ipSets
}

func (testFlowLog) Setup() error    { return nil }
func (testFlowLog) TearDown() error { return nil }

func TestPolicyProgramsExceedMatchIdSpace(t *testing.T) {
	test := testFlowLog{
		policy: polprog.Rules{},
	}

	pkt := testFlowLogCase{packet: icmpPktWithTypeCode("10.0.0.1", "10.0.0.2", 8, 3)}

	// Fill the Policy with more then state.MaxRuleIDs all with a pass rule
	for i := 0; i <= state.MaxRuleIDs; i++ {
		test.policy.Tiers = append(test.policy.Tiers, polprog.Tier{
			Policies: []polprog.Policy{{
				Rules: []polprog.Rule{{
					Rule:    &proto.Rule{Action: "Pass"},
					MatchID: uint64(i + 1),
				}},
			}},
		})
		pkt.matches = append(pkt.matches, uint64(i+1))
	}

	// The last tier has an Allow rule which we must hit despite the fact that we cannot
	// record anymore rule IDs. This must not break policy enforcement.
	test.policy.Tiers = append(test.policy.Tiers, polprog.Tier{
		Policies: []polprog.Policy{{
			Rules: []polprog.Rule{{
				Rule:    &proto.Rule{Action: "Allow"},
				MatchID: uint64(state.MaxRuleIDs + 1),
			}},
		}},
	})
	pkt.matches = append(pkt.matches, uint64(state.MaxRuleIDs+1))

	test.allowedPackets = []testFlowLogCase{pkt}

	runTest(t, test, polprog.WithFlowLogs())
}

func TestPolicyProgramsFlowLog(t *testing.T) {
	tests := []struct {
		name string
		test testFlowLog
	}{
		{
			name: "no tiers - no profile match",
			test: testFlowLog{
				policy: polprog.Rules{
					NoProfileMatchID: 0xdead0000beef0000,
				},
				droppedPackets: []testFlowLogCase{
					{packet: udpPkt("10.0.0.1:31245", "10.0.0.2:80"), matches: []uint64{0xdead0000beef0000}},
					{packet: tcpPkt("10.0.0.2:80", "10.0.0.1:31245"), matches: []uint64{0xdead0000beef0000}},
					{packet: icmpPkt("10.0.0.1", "10.0.0.2"), matches: []uint64{0xdead0000beef0000}},
				},
			},
		},
		{
			name: "pass to nowhere - pass and no profile matches",
			test: testFlowLog{
				policy: polprog.Rules{
					NoProfileMatchID: 0xdead,
					Tiers: []polprog.Tier{
						{
							Name: "pass",
							Policies: []polprog.Policy{{
								Name:  "pass rule",
								Rules: []polprog.Rule{{Rule: &proto.Rule{Action: "Pass"}, MatchID: 1234}},
							}},
						},
					},
				},
				droppedPackets: []testFlowLogCase{
					{packet: udpPkt("10.0.0.1:31245", "10.0.0.2:80"), matches: []uint64{1234, 0xdead}},
					{packet: tcpPkt("10.0.0.2:80", "10.0.0.1:31245"), matches: []uint64{1234, 0xdead}},
					{packet: icmpPkt("10.0.0.1", "10.0.0.2"), matches: []uint64{1234, 0xdead}},
				},
			},
		},
		{
			name: "different packets match different tiers and rules",
			test: testFlowLog{
				policy: polprog.Rules{
					NoProfileMatchID: 0xdead,
					Tiers: []polprog.Tier{
						{
							Name:      "first",
							EndRuleID: 0xbeef,
							Policies: []polprog.Policy{
								{
									Name: "TCP pass",
									Rules: []polprog.Rule{{
										MatchID: 6,
										Rule: &proto.Rule{
											Action: "Pass",
											Protocol: &proto.Protocol{
												NumberOrName: &proto.Protocol_Name{Name: "tcp"},
											},
										},
									}},
								},
								{
									Name: "UDP allow",
									Rules: []polprog.Rule{{
										MatchID: 17,
										Rule: &proto.Rule{
											Action: "Allow",
											Protocol: &proto.Protocol{
												NumberOrName: &proto.Protocol_Name{Name: "udp"},
											},
										},
									}},
								},
								// Explicit deny rest
							},
						},
						{
							Name:      "tcp",
							EndRuleID: 0xdeadbeef,
							Policies: []polprog.Policy{
								{
									Name: "TCP ports",
									Rules: []polprog.Rule{
										{
											MatchID: 80,
											Rule: &proto.Rule{
												Action:   "Pass",
												DstPorts: []*proto.PortRange{{First: 80, Last: 80}},
											},
										},
										{
											MatchID: 443,
											Rule: &proto.Rule{
												Action:   "Allow",
												DstPorts: []*proto.PortRange{{First: 443, Last: 443}},
											},
										},
									},
								},
								{
									Name: "UDP allow",
									Rules: []polprog.Rule{{
										MatchID: 17,
										Rule: &proto.Rule{
											Action: "Allow",
											Protocol: &proto.Protocol{
												NumberOrName: &proto.Protocol_Name{Name: "udp"},
											},
										},
									}},
								},
								// Explicit deny rest
							},
						},
						{
							Name:      "http",
							EndRuleID: 0xbad,
							Policies: []polprog.Policy{
								{
									Name: "TCP ports",
									Rules: []polprog.Rule{
										{
											MatchID: 10002,
											Rule: &proto.Rule{
												Action:      "Allow",
												SrcIpSetIds: []string{"setFrom"},
											},
										},
									},
								},
								// Explicit deny rest
							},
						},
					},
				},
				ipSets: map[string][]string{
					"setFrom": {"10.0.0.2/32"},
				},
				allowedPackets: []testFlowLogCase{
					{packet: udpPkt("10.0.0.1:53", "10.0.0.2:53"), matches: []uint64{17}},
					{packet: tcpPkt("10.0.0.2:1234", "10.0.0.1:80"), matches: []uint64{6, 80, 10002}},
					{packet: tcpPkt("10.0.0.2:1234", "10.0.0.1:443"), matches: []uint64{6, 443}},
				},
				droppedPackets: []testFlowLogCase{
					{packet: tcpPkt("10.0.0.2:8080", "10.0.0.1:31245"), matches: []uint64{6, 0xdeadbeef}},
					{packet: icmpPkt("10.0.0.1", "10.0.0.2"), matches: []uint64{0xbeef}},
					{packet: tcpPkt("10.0.0.3:1234", "10.0.0.1:80"), matches: []uint64{6, 80, 0xbad}},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("name=%s", test.name), func(t *testing.T) { runTest(t, test.test, polprog.WithFlowLogs()) })
	}
}

func TestPolicyHostPolicyPrograms(t *testing.T) {
	for i, p := range hostPolProgramTests {
		t.Run(fmt.Sprintf("%d:Policy=%s", i, p.PolicyName), func(t *testing.T) { runTest(t, wrap(p)) })
	}
}

func TestPolicyXDPPolicyPrograms(t *testing.T) {
	for i, p := range xdpPolProgramTests {
		t.Run(fmt.Sprintf("%d:Policy=%s", i, p.PolicyName), func(t *testing.T) { runTest(t, wrap(p)) })
	}
}

type polProgramTest struct {
	PolicyName       string
	Policy           polprog.Rules
	AllowedPackets   []packet
	DroppedPackets   []packet
	UnmatchedPackets []packet
	IPSets           map[string][]string
	ForIPv6          bool
	SetupCB          func() error
	TearDownCB       func() error
	Options          []polprog.Option
}

type packet struct {
	protocol int
	srcAddr  string
	srcPort  int
	dstAddr  string
	dstPort  int

	preNATDstAddr string
	preNATDstPort int
	fromHostFlag  bool
	toHostFlag    bool
}

func (p packet) preNAT(dst string) packet {
	var err error
	parts := strings.Split(dst, ":")
	p.preNATDstAddr = parts[0]
	p.preNATDstPort, err = strconv.Atoi(parts[1])
	if err != nil {
		panic(err)
	}
	return p
}

func (p packet) fromHost() packet {
	p.fromHostFlag = true
	return p
}

func (p packet) toHost() packet {
	p.toHostFlag = true
	return p
}

func (p packet) String() string {
	protoName := fmt.Sprint(p.protocol)
	switch p.protocol {
	case 6:
		protoName = "tcp"
	case 17:
		protoName = "udp"
	case 1:
		protoName = "icmp"
	}
	preNAT := ""
	if p.preNATDstAddr != "" {
		preNAT = fmt.Sprintf("%s:%d->", p.preNATDstAddr, p.preNATDstPort)
	}
	fromHost := ""
	if p.fromHostFlag {
		fromHost = "(H)"
	}
	toHost := ""
	if p.toHostFlag {
		toHost = "(H)"
	}
	return fmt.Sprintf("%s-%s%s:%d->%s%s%s:%d", protoName, p.srcAddr, fromHost, p.srcPort, preNAT, p.dstAddr, toHost, p.dstPort)
}

func (p packet) StateIn() state.State {
	preNATDstAddr := p.dstAddr
	preNATDstPort := p.dstPort
	if p.preNATDstAddr != "" {
		preNATDstAddr = p.preNATDstAddr
		preNATDstPort = p.preNATDstPort
	}
	flags := uint64(0)
	if p.fromHostFlag {
		flags |= polprog.FlagSrcIsHost
	}
	if p.toHostFlag {
		flags |= polprog.FlagDestIsHost
	}

	dstPort := 0
	postNATDstPort := p.dstPort
	if uint8(p.protocol) == 1 {
		dstPort = p.dstPort
		preNATDstPort = 0
	}

	return state.State{
		IPProto:         uint8(p.protocol),
		SrcAddr:         ipUintFromString(p.srcAddr, 0),
		SrcAddr1:        ipUintFromString(p.srcAddr, 1),
		SrcAddr2:        ipUintFromString(p.srcAddr, 2),
		SrcAddr3:        ipUintFromString(p.srcAddr, 3),
		PostNATDstAddr:  ipUintFromString(p.dstAddr, 0),
		PostNATDstAddr1: ipUintFromString(p.dstAddr, 1),
		PostNATDstAddr2: ipUintFromString(p.dstAddr, 2),
		PostNATDstAddr3: ipUintFromString(p.dstAddr, 3),
		SrcPort:         uint16(p.srcPort),
		DstPort:         uint16(dstPort),
		PostNATDstPort:  uint16(postNATDstPort),
		PreNATDstAddr:   ipUintFromString(preNATDstAddr, 0),
		PreNATDstAddr1:  ipUintFromString(preNATDstAddr, 1),
		PreNATDstAddr2:  ipUintFromString(preNATDstAddr, 2),
		PreNATDstAddr3:  ipUintFromString(preNATDstAddr, 3),
		PreNATDstPort:   uint16(preNATDstPort),
		Flags:           flags,
	}
}

func (p packet) MatchStateOut(stateOut state.State) {
	// Check no other fields got clobbered.
	expectedStateOut := p.StateIn()

	// Zero parts we do not care about
	expectedStateOut.PolicyRC = 0 // PolicyRC tested by the caller
	expectedStateOut.RulesHit = 0
	expectedStateOut.RuleIDs = [state.MaxRuleIDs]uint64{}

	stateOut.PolicyRC = 0
	stateOut.RulesHit = 0
	stateOut.RuleIDs = [state.MaxRuleIDs]uint64{}

	Expect(stateOut).To(Equal(expectedStateOut), "policy program modified unexpected parts of the state")
}

func ipUintFromString(addrStr string, section int) uint32 {
	if addrStr == "" {
		return 0
	}

	addrBytes := net.ParseIP(addrStr).To4()
	if addrBytes != nil {
		if section > 0 {
			return 0
		}
		return binary.LittleEndian.Uint32(addrBytes)
	}
	addrBytes = net.ParseIP(addrStr).To16()
	return binary.LittleEndian.Uint32(addrBytes[section*4 : (section+1)*4])
}

func TestPolicyIPUintFromString(t *testing.T) {
	RegisterTestingT(t)
	Expect(ipUintFromString("10.0.0.1", 0)).To(Equal(uint32(0x0100000a)))
	Expect(ipUintFromString("10.0.0.1", 1)).To(Equal(uint32(0)))
	Expect(ipUintFromString("10.0.0.1", 2)).To(Equal(uint32(0)))
	Expect(ipUintFromString("10.0.0.1", 3)).To(Equal(uint32(0)))

	Expect(ipUintFromString("ffff:8888:4444::2222:1111:0000", 0)).To(Equal(uint32(0x8888ffff)))
	Expect(ipUintFromString("ffff:8888:4444::2222:1111:0000", 1)).To(Equal(uint32(0x00004444)))
	Expect(ipUintFromString("ffff:8888:4444::2222:1111:0000", 2)).To(Equal(uint32(0x22220000)))
	Expect(ipUintFromString("ffff:8888:4444::2222:1111:0000", 3)).To(Equal(uint32(0x00001111)))
}

type testPolicy interface {
	Policy() polprog.Rules
	IPSets() map[string][]string
	AllowedPackets() []testCase
	DroppedPackets() []testCase
	UnmatchedPackets() []testCase
	XDP() bool
	ForIPv6() bool
	Setup() error
	TearDown() error
}

type testCase interface {
	String() string
	StateIn() state.State
	MatchStateOut(stateOut state.State)
}

var nextPolProgIdx atomic.Int64
var jumpStride = asm.TrampolineStrideDefault

func runTest(t *testing.T, tp testPolicy, polprogOpts ...polprog.Option) {
	RegisterTestingT(t)

	err := tp.Setup()
	Expect(err).NotTo(HaveOccurred())

	defer func() {
		err := tp.TearDown()
		Expect(err).NotTo(HaveOccurred())
	}()

	// The prog builder refuses to allocate IDs as a precaution, give it an allocator that forces allocations.
	realAlloc := idalloc.New()
	forceAlloc := &forceAllocator{alloc: realAlloc}

	// Make sure the maps are available.
	// FIXME should clean up the maps at the end of each test but recreating the maps seems to be racy
	if tp.ForIPv6() {
		cleanIPSetMapV6()
		setUpIPSetsV6(tp.IPSets(), realAlloc, ipsMapV6)
	} else {
		cleanIPSetMap()
		setUpIPSets(tp.IPSets(), realAlloc, ipsMap)
	}

	for _, polJumpMap := range policyJumpMap {
		if polJumpMap != nil {
			_ = polJumpMap.Close()
		}
	}

	policyJumpMap = jump.Maps()
	for _, hk := range []hook.Hook{hook.Egress, hook.Ingress} {
		_ = unix.Unlink(policyJumpMap[hk].Path())
		err = policyJumpMap[hk].EnsureExists()
		Expect(err).NotTo(HaveOccurred())
	}

	allowIdx := tcdefs.ProgIndexAllowed
	denyIdx := tcdefs.ProgIndexDrop

	ipsfd := ipsMap.MapFD()

	polprogOpts = append(polprogOpts, polprog.WithAllowDenyJumps(allowIdx, denyIdx))

	staticProgsMap := maps.NewPinnedMap(maps.MapParameters{
		Type:       "prog_array",
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 32,
		Name:       "teststatic",
	})
	err = staticProgsMap.EnsureExists()
	defer func() {
		_ = staticProgsMap.Close()
	}()
	Expect(err).NotTo(HaveOccurred())

	polProgIdx := int(nextPolProgIdx.Add(1))
	stride := jump.TCMaxEntryPoints
	polprogOpts = append(polprogOpts, polprog.WithPolicyMapIndexAndStride(int(polProgIdx), stride))

retry:
	polprogOpts = append(polprogOpts, polprog.WithTrampolineStride(jumpStride))

	if tp.ForIPv6() {
		polprogOpts = append(polprogOpts, polprog.WithIPv6())
		ipsfd = ipsMapV6.MapFD()
	}
	pg := polprog.NewBuilder(
		forceAlloc,
		ipsfd,
		testStateMap.MapFD(),
		staticProgsMap.MapFD(),
		policyJumpMap[hook.Ingress].MapFD(),
		polprogOpts...,
	)
	insns, err := pg.Instructions(tp.Policy())
	Expect(err).NotTo(HaveOccurred(), "failed to assemble program")

	// Load the program(s) into the kernel.
	var polProgFDs []bpf.ProgFD
	defer func() {
		var errs []error
		for _, polProgFD := range polProgFDs {
			err := polProgFD.Close()
			if err != nil {
				errs = append(errs, err)
			}
		}
		Expect(errs).To(BeEmpty())
	}()
	for i, p := range insns {
		polProgFD, err := bpf.LoadBPFProgramFromInsns(p, "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
		if err != nil && errors.Is(err, unix.ERANGE) && jumpStride == asm.TrampolineStrideDefault {
			jumpStride = 14000
			goto retry
		}
		Expect(err).NotTo(HaveOccurred(), "failed to load program into the kernel")
		Expect(polProgFD).NotTo(BeZero())
		polProgFDs = append(polProgFDs, polProgFD)
		err = policyJumpMap[hook.Ingress].Update(
			jump.Key(polprog.SubProgramJumpIdx(polProgIdx, i, stride)),
			jump.Value(polProgFD.FD()),
		)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to add policy sub program %d/%d", i, len(insns)))
	}

	// Give the policy program somewhere to jump to.
	allowProgIdx := tcdefs.ProgIndexAllowed
	epiFD := installAllowedProgram(staticProgsMap, allowProgIdx)
	defer func() {
		err := epiFD.Close()
		Expect(err).NotTo(HaveOccurred())
	}()

	dropProgIdx := tcdefs.ProgIndexDrop
	dropFD := installDropProgram(staticProgsMap, dropProgIdx)
	defer func() {
		err := dropFD.Close()
		Expect(err).NotTo(HaveOccurred())
	}()

	log.Debug("Setting up state map")
	for _, tc := range tp.AllowedPackets() {
		t.Run(fmt.Sprintf("should allow %s", tc), func(t *testing.T) {
			RegisterTestingT(t)
			runProgram(tc, testStateMap, polProgFDs[0], RCAllowedReached, state.PolicyAllow)
		})
	}
	for _, tc := range tp.DroppedPackets() {
		t.Run(fmt.Sprintf("should drop %s", tc), func(t *testing.T) {
			RegisterTestingT(t)
			runProgram(tc, testStateMap, polProgFDs[0], RCDropReached, state.PolicyDeny)
		})
	}
	for _, tc := range tp.UnmatchedPackets() {
		t.Run(fmt.Sprintf("should not match %s", tc), func(t *testing.T) {
			RegisterTestingT(t)
			runProgram(tc, testStateMap, polProgFDs[0], XDPPass, state.PolicyNoMatch)
		})
	}
}

// installAllowedProgram installs a trivial BPF program into the jump table that returns RCAllowedReached.
func installAllowedProgram(jumpMap maps.Map, jumpMapindex int) bpf.ProgFD {
	b := asm.NewBlock(false)

	// Load the RC into the return register.
	b.MovImm64(asm.R0, RCAllowedReached)
	// Exit!
	b.Exit()

	epiInsns, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())
	epiFD, err := bpf.LoadBPFProgramFromInsns(epiInsns, "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
	Expect(err).NotTo(HaveOccurred(), "failed to load program into the kernel")
	Expect(epiFD).NotTo(BeZero())

	jumpValue := make([]byte, 4)
	binary.LittleEndian.PutUint32(jumpValue, uint32(epiFD))
	err = jumpMap.Update([]byte{byte(jumpMapindex), 0, 0, 0}, jumpValue)
	Expect(err).NotTo(HaveOccurred())

	return epiFD
}

// installDropProgram installs a trivial BPF program into the jump table that returns RCDropReached.
func installDropProgram(jumpMap maps.Map, jumpMapindex int) bpf.ProgFD {
	b := asm.NewBlock(false)

	// Load the RC into the return register.
	b.MovImm64(asm.R0, RCDropReached)
	// Exit!
	b.Exit()

	epiInsns, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())
	dropFD, err := bpf.LoadBPFProgramFromInsns(epiInsns, "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
	Expect(err).NotTo(HaveOccurred(), "failed to load program into the kernel")
	Expect(dropFD).NotTo(BeZero())

	jumpValue := make([]byte, 4)
	binary.LittleEndian.PutUint32(jumpValue, uint32(dropFD))
	err = jumpMap.Update([]byte{byte(jumpMapindex), 0, 0, 0}, jumpValue)
	Expect(err).NotTo(HaveOccurred())

	return dropFD
}

func runProgram(tc testCase, stateMap maps.Map, progFD bpf.ProgFD, expProgRC int, expPolRC state.PolicyResult) {
	// The policy program takes its input from the state map (rather than looking at the
	// packet).  Set up the state map.
	stateIn := tc.StateIn()
	stateMapKey := []byte{0, 0, 0, 0} // State map has a single key
	stateBytesIn := stateIn.AsBytes()
	log.WithField("stateBytes", stateBytesIn).Debug("State bytes in")
	log.Debugf("State in %#v", stateIn)
	err := stateMap.Update(stateMapKey, stateBytesIn)
	Expect(err).NotTo(HaveOccurred(), "failed to update state map")

	log.Debug("Running BPF program")
	result, err := bpf.RunBPFProgram(progFD, make([]byte, 1000), 1)
	Expect(err).NotTo(HaveOccurred())

	log.Debug("Checking result...")
	stateBytesOut, err := stateMap.Get(stateMapKey)
	Expect(err).NotTo(HaveOccurred())
	log.WithField("stateBytes", stateBytesOut).Debug("State bytes out")
	stateOut := state.StateFromBytes(stateBytesOut)
	log.Debugf("State out %#v", stateOut)
	Expect(stateOut.PolicyRC).To(BeNumerically("==", expPolRC), "policy RC was incorrect")
	Expect(result.RC).To(BeNumerically("==", expProgRC), "program RC was incorrect")
	tc.MatchStateOut(stateOut)
}

func setUpIPSets(ipSets map[string][]string, alloc *idalloc.IDAllocator, ipsMap maps.Map) {
	for name, members := range ipSets {
		id := alloc.GetOrAlloc(name)
		for _, m := range members {
			entry := ipsets.ProtoIPSetMemberToBPFEntry(id, m)
			err := ipsMap.Update(entry.AsBytes(), ipsets.DummyValue)
			Expect(err).NotTo(HaveOccurred())
		}
	}
}

func setUpIPSetsV6(ipSets map[string][]string, alloc *idalloc.IDAllocator, ipsMap maps.Map) {
	for name, members := range ipSets {
		id := alloc.GetOrAlloc(name)
		for _, m := range members {
			entry := ipsets.ProtoIPSetMemberToBPFEntryV6(id, m)
			err := ipsMapV6.Update(entry.AsBytes(), ipsets.DummyValue)
			Expect(err).NotTo(HaveOccurred())
		}
	}
}

func cleanIPSetMap() {
	// Clean out any existing IP sets.  (The other maps have a fixed number of keys that
	// we set as needed.)
	var keys [][]byte
	err := ipsMap.Iter(func(k, v []byte) maps.IteratorAction {
		kCopy := make([]byte, len(k))
		copy(kCopy, k)
		keys = append(keys, kCopy)
		return maps.IterNone
	})
	Expect(err).NotTo(HaveOccurred(), "failed to clean out map before test")
	for _, k := range keys {
		err = ipsMap.Delete(k)
		Expect(err).NotTo(HaveOccurred(), "failed to clean out map before test")
	}
}

func cleanIPSetMapV6() {
	// Clean out any existing IP sets.  (The other maps have a fixed number of keys that
	// we set as needed.)
	var keys [][]byte
	err := ipsMapV6.Iter(func(k, v []byte) maps.IteratorAction {
		kCopy := make([]byte, len(k))
		copy(kCopy, k)
		keys = append(keys, kCopy)
		return maps.IterNone
	})
	Expect(err).NotTo(HaveOccurred(), "failed to clean out map before test")
	for _, k := range keys {
		err = ipsMapV6.Delete(k)
		Expect(err).NotTo(HaveOccurred(), "failed to clean out map before test")
	}
}
