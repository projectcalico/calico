// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

package polprog

import (
	"strings"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/proto"
)

func TestPolicySanityCheck(t *testing.T) {
	// Just a basic sanity check with a kitchen sink policy.  The policy behaviour is tested "for real" in the
	// bpf/ut package.

	RegisterTestingT(t)
	alloc := idalloc.New()
	setID := func(id string) string {
		alloc.GetOrAlloc(id)
		return id
	}
	pg := NewBuilder(alloc, 1, 2, 3, false)
	insns, err := pg.Instructions(Rules{
		Tiers: []Tier{{
			Policies: []Policy{{
				Rules: []Rule{{
					Rule: &proto.Rule{
						Action:                  "Allow",
						IpVersion:               4,
						Protocol:                &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}},
						SrcNet:                  []string{"10.0.0.0/8"},
						SrcPorts:                []*proto.PortRange{{First: 80, Last: 81}, {First: 8080, Last: 8081}},
						SrcNamedPortIpSetIds:    []string{setID("n:abcdef1234567890")},
						DstNet:                  []string{"11.0.0.0/8"},
						DstPorts:                []*proto.PortRange{{First: 3000, Last: 3001}},
						DstNamedPortIpSetIds:    []string{setID("n:foo1234567890")},
						Icmp:                    &proto.Rule_IcmpTypeCode{IcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}},
						SrcIpSetIds:             []string{setID("s:sbcdef1234567890")},
						DstIpSetIds:             []string{setID("s:dbcdef1234567890")},
						DstIpPortSetIds:         []string{setID("svc:abcdefg1234567")},
						NotProtocol:             &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "UDP"}},
						NotSrcNet:               []string{"12.0.0.0/8"},
						NotSrcPorts:             []*proto.PortRange{{First: 5000, Last: 5000}},
						NotDstNet:               []string{"13.0.0.0/8"},
						NotDstPorts:             []*proto.PortRange{{First: 4000, Last: 4000}},
						NotIcmp:                 &proto.Rule_NotIcmpTypeCode{NotIcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}},
						NotSrcIpSetIds:          []string{setID("s:abcdef1234567890")},
						NotDstIpSetIds:          []string{setID("s:abcdef123456789l")},
						NotSrcNamedPortIpSetIds: []string{setID("n:0bcdef1234567890")},
						NotDstNamedPortIpSetIds: []string{setID("n:0bcdef1234567890")},
					},
				}},
			}},
		}},
	})

	Expect(err).NotTo(HaveOccurred())
	for i, in := range insns {
		t.Log(i, ": ", in.Instruction)
	}
}

func TestLogActionIgnored(t *testing.T) {
	RegisterTestingT(t)
	alloc := idalloc.New()

	pg := NewBuilder(alloc, 1, 2, 3, false)
	insns, err := pg.Instructions(Rules{
		Tiers: []Tier{{
			Name: "default",
			Policies: []Policy{{
				Name: "test policy",
				Rules: []Rule{{Rule: &proto.Rule{
					Action: "Log",
				}}},
			}},
		}}})
	Expect(err).NotTo(HaveOccurred())

	pg = NewBuilder(alloc, 1, 2, 3, false)
	noOpInsns, err := pg.Instructions(Rules{
		Tiers: []Tier{{
			Name:     "default",
			Policies: []Policy{},
		}}})
	Expect(err).NotTo(HaveOccurred())
	Expect(noOpInsns).To(Equal(insns))
}

func TestPolicyDump(t *testing.T) {
	RegisterTestingT(t)
	checkLabelsAndComments := func(insns asm.Insns, idx int, expectedString string, matchLabelOrComment string, offset int) {
		if idx == -1 {
			idx = getStartofTierInsnIndex(insns)
			Expect(idx).NotTo(Equal(-1))
			idx = idx + offset
		}
		if matchLabelOrComment == "label" {
			Expect(checkIfStringExists(insns[idx].Labels, expectedString)).To(BeTrue())
		} else {
			Expect(checkIfStringExists(insns[idx].Comments, expectedString)).To(BeTrue())
		}
	}
	checkLabelsAndComments(genInsns("ip_proto"), 0, "start", "label", 0)
	checkLabelsAndComments(genInsns("ip_proto"), 5, "Load packet metadata saved by previous program", "comment", 0)
	checkLabelsAndComments(genInsns("ip_proto"), 9, "Save state pointer in register R9", "comment", 0)
	checkLabelsAndComments(genInsns("ip_proto"), 10, "policy", "label", 0)
	checkLabelsAndComments(genInsns("ip_proto"), -1, "If protocol != tcp, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("not_ip_proto"), -1, "If protocol == udp, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("src_net"), -1, "If source not in {10.0.0.0/8,11.0.0.0/8}, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("not_src_net"), -1, "If source in {12.0.0.0/8}, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("dst_net"), -1, "If dest not in {13.0.0.0/8,14.0.0.0/8}, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("not_dst_net"), -1, "If dest in {12.0.0.0/8,15.0.0.0/8}, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("src_ports"), -1, "If source port is not within any of {80,8080-8081}, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("dst_ports"), -1, "If dest port is not within any of {90-95,9090-9091}, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("not_src_ports"), -1, "If source port is within any of {80,8080-8081}, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("not_dst_ports"), -1, "If dest port is within any of {90-95,9090-9091}, skip to next rule", "comment", 0)

	checkLabelsAndComments(genInsns("src_named_port"), -1, "If source port is not within any of the named ports {n:abcdef1234567890}, skip to next rule", "comment", 1)
	checkLabelsAndComments(genInsns("not_src_named_port"), -1, "If source port is within any of the named ports {n:abcdef1234567890}, skip to next rule", "comment", 1)
	checkLabelsAndComments(genInsns("dst_named_port"), -1, "If dest port is not within any of the named ports {n:foo1234567890}, skip to next rule", "comment", 1)
	checkLabelsAndComments(genInsns("not_dst_named_port"), -1, "If dest port is within any of the named ports {n:foo1234567890}, skip to next rule", "comment", 1)

	checkLabelsAndComments(genInsns("src_ipset_ids"), -1, "If source doesn't match ipset s:sbcdef1234567890, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("not_src_ipset_ids"), -1, "If source matches ipset s:sbcdef1234567890, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("dst_ipset_ids"), -1, "If dest doesn't match ipset d:sbcdef1234567890, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("not_dst_ipset_ids"), -1, "If dest matches ipset d:sbcdef1234567890, skip to next rule", "comment", 0)

	checkLabelsAndComments(genInsns("icmp_type_code"), -1, "If ICMP type != 10 or code != 12, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("not_icmp_type_code"), -1, "If ICMP type == 10 and code == 12, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("icmp_type"), -1, "If ICMP type != 10, skip to next rule", "comment", 0)
	checkLabelsAndComments(genInsns("not_icmp_type"), -1, "If ICMP type == 10, skip to next rule", "comment", 0)
}

func checkIfStringExists(strArray []string, expectedStr string) bool {
	for _, str := range strArray {
		if str == expectedStr {
			return true
		}
	}
	return false
}

func getStartofTierInsnIndex(insns asm.Insns) int {
	for i, in := range insns {
		for _, comment := range in.Comments {
			if strings.Contains(comment, "Start of tier") {
				return i
			}
		}
	}
	return -1
}

func genInsns(match string) asm.Insns {
	alloc := idalloc.New()
	setID := func(id string) string {
		alloc.GetOrAlloc(id)
		return id
	}
	pg := NewBuilder(alloc, 1, 2, 3, true)
	pol := Rules{
		Tiers: []Tier{{
			Policies: []Policy{{
				Rules: []Rule{{
					Rule: &proto.Rule{
						Action:    "Allow",
						IpVersion: 4,
					},
				}},
			}},
		}},
	}
	switch match {
	case "ip_proto":
		pol.Tiers[0].Policies[0].Rules[0].Rule.Protocol = &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}}
	case "not_ip_proto":
		pol.Tiers[0].Policies[0].Rules[0].Rule.NotProtocol = &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "UDP"}}
	case "src_net":
		pol.Tiers[0].Policies[0].Rules[0].Rule.SrcNet = []string{"10.0.0.0/8", "11.0.0.0/8"}
	case "not_src_net":
		pol.Tiers[0].Policies[0].Rules[0].Rule.NotSrcNet = []string{"12.0.0.0/8"}
	case "dst_net":
		pol.Tiers[0].Policies[0].Rules[0].Rule.DstNet = []string{"13.0.0.0/8", "14.0.0.0/8"}
	case "not_dst_net":
		pol.Tiers[0].Policies[0].Rules[0].Rule.NotDstNet = []string{"12.0.0.0/8", "15.0.0.0/8"}
	case "src_ports":
		pol.Tiers[0].Policies[0].Rules[0].Rule.SrcPorts = []*proto.PortRange{{First: 80, Last: 80}, {First: 8080, Last: 8081}}
	case "dst_ports":
		pol.Tiers[0].Policies[0].Rules[0].Rule.DstPorts = []*proto.PortRange{{First: 90, Last: 95}, {First: 9090, Last: 9091}}
	case "not_src_ports":
		pol.Tiers[0].Policies[0].Rules[0].Rule.NotSrcPorts = []*proto.PortRange{{First: 80, Last: 80}, {First: 8080, Last: 8081}}
	case "not_dst_ports":
		pol.Tiers[0].Policies[0].Rules[0].Rule.NotDstPorts = []*proto.PortRange{{First: 90, Last: 95}, {First: 9090, Last: 9091}}
	case "src_named_port":
		pol.Tiers[0].Policies[0].Rules[0].Rule.SrcNamedPortIpSetIds = []string{setID("n:abcdef1234567890")}
	case "dst_named_port":
		pol.Tiers[0].Policies[0].Rules[0].Rule.DstNamedPortIpSetIds = []string{setID("n:foo1234567890")}
	case "not_src_named_port":
		pol.Tiers[0].Policies[0].Rules[0].Rule.NotSrcNamedPortIpSetIds = []string{setID("n:abcdef1234567890")}
	case "not_dst_named_port":
		pol.Tiers[0].Policies[0].Rules[0].Rule.NotDstNamedPortIpSetIds = []string{setID("n:foo1234567890")}
	case "src_ipset_ids":
		pol.Tiers[0].Policies[0].Rules[0].Rule.SrcIpSetIds = []string{setID("s:sbcdef1234567890")}
	case "not_src_ipset_ids":
		pol.Tiers[0].Policies[0].Rules[0].Rule.NotSrcIpSetIds = []string{setID("s:sbcdef1234567890")}
	case "dst_ipset_ids":
		pol.Tiers[0].Policies[0].Rules[0].Rule.DstIpSetIds = []string{setID("d:sbcdef1234567890")}
	case "not_dst_ipset_ids":
		pol.Tiers[0].Policies[0].Rules[0].Rule.NotDstIpSetIds = []string{setID("d:sbcdef1234567890")}
	case "icmp_type_code":
		pol.Tiers[0].Policies[0].Rules[0].Rule.Icmp = &proto.Rule_IcmpTypeCode{IcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}}
	case "not_icmp_type_code":
		pol.Tiers[0].Policies[0].Rules[0].Rule.NotIcmp = &proto.Rule_NotIcmpTypeCode{NotIcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}}
	case "icmp_type":
		pol.Tiers[0].Policies[0].Rules[0].Rule.Icmp = &proto.Rule_IcmpType{IcmpType: 10}
	case "not_icmp_type":
		pol.Tiers[0].Policies[0].Rules[0].Rule.NotIcmp = &proto.Rule_NotIcmpType{NotIcmpType: 10}
	default:
	}
	insns, _ := pg.Instructions(pol)
	return insns
}
