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
	"fmt"
	"math/rand"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/proto"
)

// These tests are just sanity checks and low-level UTs.  Most of the tests
// of the policy program builder are in felix/bpf/ut/pol_prog_test.go because
// that file has access to the eBPF test machinery (to allow verifying/running
// the BPF programs "for real").

func TestPolicySanityCheck(t *testing.T) {
	// Just a basic sanity check with a kitchen sink policy.  The policy behaviour is tested "for real" in the
	// bpf/ut package.

	RegisterTestingT(t)
	alloc := idalloc.New()
	setID := func(id string) string {
		alloc.GetOrAlloc(id)
		return id
	}
	pg := NewBuilder(alloc, 1, 2, 3, 4, WithAllowDenyJumps(666, 777))
	progs, err := pg.Instructions(Rules{
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
	for i, in := range progs[0] {
		t.Log(i, ": ", in.String())
	}
}

func TestPolicyDump(t *testing.T) {
	RegisterTestingT(t)
	alloc := idalloc.New()
	setID := func(id string) string {
		alloc.GetOrAlloc(id)
		return id
	}

	checkLabelsAndComments := func(rule *proto.Rule, expectedString string, matchLabelOrComment string) {

		pg := NewBuilder(alloc, 1, 2, 3, 4, WithAllowDenyJumps(666, 777), WithPolicyDebugEnabled())
		rule.Action = "Allow"
		rule.IpVersion = 4
		insns, err := pg.Instructions(Rules{
			Tiers: []Tier{{
				Policies: []Policy{{
					Rules: []Rule{{
						Rule: rule,
					}},
				}},
			}},
		})
		Expect(err).NotTo(HaveOccurred())

		labels, comments := aggregateCommentsAndLabels(&insns[0])
		if matchLabelOrComment == "label" {
			Expect(labels).To(ContainElement(expectedString))
		} else {
			Expect(comments).To(ContainElement(expectedString))
		}
	}
	checkLabelsAndComments(&proto.Rule{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}}}, "start", "label")
	checkLabelsAndComments(&proto.Rule{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}}}, "Load packet metadata saved by previous program", "comment")
	checkLabelsAndComments(&proto.Rule{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}}}, "Save state pointer in register R9", "comment")
	checkLabelsAndComments(&proto.Rule{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}}}, "policy", "label")
	checkLabelsAndComments(&proto.Rule{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}}}, "If protocol != tcp, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{NotProtocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "UDP"}}}, "If protocol == udp, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{SrcNet: []string{"10.0.0.0/8", "11.0.0.0/8"}}, "If source not in {10.0.0.0/8,11.0.0.0/8}, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{NotSrcNet: []string{"12.0.0.0/8"}}, "If source in {12.0.0.0/8}, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{DstNet: []string{"13.0.0.0/8", "14.0.0.0/8"}}, "If dest not in {13.0.0.0/8,14.0.0.0/8}, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{NotDstNet: []string{"12.0.0.0/8", "15.0.0.0/8"}}, "If dest in {12.0.0.0/8,15.0.0.0/8}, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{SrcPorts: []*proto.PortRange{{First: 80, Last: 80}, {First: 8080, Last: 8081}}}, "If source port is not within any of {80,8080-8081}, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{DstPorts: []*proto.PortRange{{First: 90, Last: 95}, {First: 9090, Last: 9091}}}, "If dest port is not within any of {90-95,9090-9091}, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{NotSrcPorts: []*proto.PortRange{{First: 80, Last: 80}, {First: 8080, Last: 8081}}}, "If source port is within any of {80,8080-8081}, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{NotDstPorts: []*proto.PortRange{{First: 90, Last: 95}, {First: 9090, Last: 9091}}}, "If dest port is within any of {90-95,9090-9091}, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{SrcNamedPortIpSetIds: []string{setID("n:abcdef1234567890")}}, "If source port is not within any of the named ports {n:abcdef1234567890}, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{DstNamedPortIpSetIds: []string{setID("n:foo1234567890")}}, "If dest port is not within any of the named ports {n:foo1234567890}, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{NotSrcNamedPortIpSetIds: []string{setID("n:abcdef1234567890")}}, "If source port is within any of the named ports {n:abcdef1234567890}, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{NotDstNamedPortIpSetIds: []string{setID("n:foo1234567890")}}, "If dest port is within any of the named ports {n:foo1234567890}, skip to next rule", "comment")

	checkLabelsAndComments(&proto.Rule{SrcIpSetIds: []string{setID("s:sbcdef1234567890")}}, "If source doesn't match ipset s:sbcdef1234567890 (0xc9e0b8362d2ae7aa), skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{NotSrcIpSetIds: []string{setID("s:sbcdef1234567890")}}, "If source matches ipset s:sbcdef1234567890 (0xc9e0b8362d2ae7aa), skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{DstIpSetIds: []string{setID("d:sbcdef1234567890")}}, "If dest doesn't match ipset d:sbcdef1234567890 (0x8cc518c2047a26bb), skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{NotDstIpSetIds: []string{setID("d:sbcdef1234567890")}}, "If dest matches ipset d:sbcdef1234567890 (0x8cc518c2047a26bb), skip to next rule", "comment")

	checkLabelsAndComments(&proto.Rule{Icmp: &proto.Rule_IcmpTypeCode{IcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}}}, "If ICMP type != 10 or code != 12, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{NotIcmp: &proto.Rule_NotIcmpTypeCode{NotIcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}}}, "If ICMP type == 10 and code == 12, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{Icmp: &proto.Rule_IcmpType{IcmpType: 10}}, "If ICMP type != 10, skip to next rule", "comment")
	checkLabelsAndComments(&proto.Rule{NotIcmp: &proto.Rule_NotIcmpType{NotIcmpType: 10}}, "If ICMP type == 10, skip to next rule", "comment")
}

func aggregateCommentsAndLabels(insns *asm.Insns) ([]string, []string) {
	labels := []string{}
	comments := []string{}
	for _, in := range *insns {
		labels = append(labels, in.Labels...)
		comments = append(comments, in.Comments...)
	}
	return labels, comments
}

func TestProgramSplitting(t *testing.T) {
	RegisterTestingT(t)
	alloc := idalloc.New()
	setID := func(id string) string {
		alloc.GetOrAlloc(id)
		return id
	}
	pg := NewBuilder(alloc, 1, 2, 3, 4,
		WithAllowDenyJumps(666, 777),
		WithPolicyMapIndexAndStride(15, 1000))

	// First tier: 10k rules that do a mix of pass/deny.
	tier0 := Tier{
		Name: "tier0",
	}
	actions := []string{"pass", "deny"}
	for i := range 250 {
		pol := Policy{}
		for j := range 40 {
			pol.Rules = append(pol.Rules, Rule{Rule: &proto.Rule{
				Action:      actions[j%len(actions)],
				IpVersion:   4,
				Protocol:    &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}},
				SrcIpSetIds: []string{setID(fmt.Sprintf("s:sbcdef12%08x", i+j))},
			}})
		}
		tier0.Policies = append(tier0.Policies, pol)
	}
	// Second tier: 1k rules that do a mix of allow/deny.
	actions = []string{"allow", "deny"}
	tier1 := Tier{
		Name: "tier0",
	}
	for i := range 25 {
		pol := Policy{}
		for j := range 40 {
			pol.Rules = append(pol.Rules, Rule{Rule: &proto.Rule{
				Action:      actions[j%len(actions)],
				IpVersion:   4,
				Protocol:    &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}},
				SrcIpSetIds: []string{setID(fmt.Sprintf("s:sbcdef12%08x", i+j))},
			}})
		}
		tier1.Policies = append(tier1.Policies, pol)
	}

	tiers := []Tier{tier0, tier1}

	progs, err := pg.Instructions(Rules{
		Tiers: tiers,
	})
	Expect(err).NotTo(HaveOccurred())
	// Allow leeway in program size for enterprise.
	Expect(len(progs)).To(BeNumerically(">=", 6))
	Expect(len(progs)).To(BeNumerically("<=", 8))
}

// TestProgramSplitReachability moves the split point across every rule
// boundary, including after unconditional jumps.
func TestProgramSplitReachability(t *testing.T) {
	RegisterTestingT(t)

	var policy Policy
	for i := range 20 {
		policy.Rules = append(policy.Rules, Rule{
			Rule:    &proto.Rule{Action: "Allow", SrcNet: []string{fmt.Sprintf("10.0.0.%d/32", i)}},
			MatchID: uint64(i + 1),
		})
	}
	policy.Rules = append(policy.Rules, Rule{Rule: &proto.Rule{Action: "Log"}, MatchID: 100})
	rules := Rules{
		Tiers: []Tier{
			{Name: "pass", Policies: []Policy{{Rules: []Rule{{Rule: &proto.Rule{Action: "Pass"}, MatchID: 101}}}}, EndAction: TierEndDeny},
			{Name: "default", Policies: []Policy{policy}, EndAction: TierEndDeny},
		},
		Profiles: []Profile{
			{Name: "kns", Rules: []Rule{{Rule: &proto.Rule{Action: "Allow"}, MatchID: 102}}},
			{Name: "ksa"},
		},
	}

	sawUnreachableRest := false
	for limit := 1; limit < 120; limit++ {
		pg := NewBuilder(idalloc.New(), 1, 2, 3, 4,
			WithAllowDenyJumps(666, 777),
			WithPolicyMapIndexAndStride(15, 1000),
			WithFlowLogs(),
			WithPolicyDebugEnabled(),
			WithMaxJumpsPerProgram(limit),
		)
		progs, err := pg.Instructions(rules)
		Expect(err).NotTo(HaveOccurred(), "limit %d", limit)
		expectValidSubPrograms(progs, 15, 1000, fmt.Sprintf("limit %d", limit))
		if pg.restUnreachable {
			sawUnreachableRest = true
			last := progs[len(progs)-1]
			Expect(last).To(ContainElement(HaveField("Comments", ContainElement("Rest of the policy is unreachable and is not built"))),
				"limit %d", limit)
		}
	}
	Expect(sawUnreachableRest).To(BeTrue(), "no limit put the split after unconditional code")
}

func TestCheckSubPrograms(t *testing.T) {
	RegisterTestingT(t)

	var policy Policy
	for i := range 20 {
		policy.Rules = append(policy.Rules, Rule{
			Rule:    &proto.Rule{Action: "Allow", SrcNet: []string{fmt.Sprintf("10.0.0.%d/32", i)}},
			MatchID: uint64(i + 1),
		})
	}
	rules := Rules{Tiers: []Tier{{Name: "default", Policies: []Policy{policy}, EndAction: TierEndDeny}}}
	build := func() []asm.Insns {
		progs, err := NewBuilder(idalloc.New(), 1, 2, 3, 4,
			WithAllowDenyJumps(666, 777),
			WithPolicyMapIndexAndStride(15, 1000),
			WithMaxJumpsPerProgram(20),
		).Instructions(rules)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(progs)).To(BeNumerically(">", 1))
		return progs
	}
	Expect(CheckSubPrograms(build(), 15, 1000)).NotTo(HaveOccurred())

	progs := build()
	tailCall := asm.MakeInsn(asm.MovImm64, asm.R3, 0, 0, int32(SubProgramJumpIdx(15, 1, 1000)))
	for i := range progs[0] {
		if progs[0][i].Instruction == tailCall.Instruction {
			progs[0][i] = asm.MakeInsn(asm.MovImm64, asm.R3, 0, 0, int32(SubProgramJumpIdx(15, 2, 1000)))
		}
	}
	Expect(CheckSubPrograms(progs, 15, 1000)).To(MatchError(ContainSubstring("does not tail-call sub-program 1")))

	progs = build()
	progs[1] = append(progs[1], asm.MakeInsn(asm.Exit, 0, 0, 0, 0))
	Expect(CheckSubPrograms(progs, 15, 1000)).To(MatchError(ContainSubstring("sub-program 1 of")))
}

// TestProgramSplitRandomPolicies checks random policy shapes, split points and
// trampoline strides for code the verifier would reject.
func TestProgramSplitRandomPolicies(t *testing.T) {
	RegisterTestingT(t)

	r := rand.New(rand.NewSource(1))
	actions := []string{"Allow", "Deny", "Pass", "Log"}
	for iter := range 500 {
		alloc := idalloc.New()
		setID := func(id string) string {
			alloc.GetOrAlloc(id)
			return id
		}
		randomRule := func() *proto.Rule {
			rule := &proto.Rule{Action: actions[r.Intn(len(actions))]}
			if r.Intn(2) == 0 {
				rule.Protocol = &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}}
			}
			if r.Intn(2) == 0 {
				rule.SrcIpSetIds = []string{setID(fmt.Sprintf("s:%d", r.Intn(1000)))}
			}
			if r.Intn(3) == 0 {
				for range r.Intn(40) {
					rule.SrcNet = append(rule.SrcNet, fmt.Sprintf("10.%d.0.0/16", r.Intn(255)))
				}
			}
			if r.Intn(3) == 0 {
				rule.DstIpSetIds = []string{setID(fmt.Sprintf("s:%d", r.Intn(1000)))}
			}
			if r.Intn(2) == 0 {
				for range r.Intn(100) {
					first := int32(r.Intn(65000))
					pr := &proto.PortRange{First: first, Last: first + int32(r.Intn(2)*r.Intn(100))}
					if r.Intn(4) == 0 {
						rule.NotDstPorts = append(rule.NotDstPorts, pr)
					} else {
						rule.DstPorts = append(rule.DstPorts, pr)
					}
				}
				if r.Intn(3) == 0 {
					rule.DstNamedPortIpSetIds = []string{setID(fmt.Sprintf("n:%d", r.Intn(1000)))}
				}
			}
			return rule
		}

		var tiers []Tier
		for ti := range 1 + r.Intn(3) {
			tier := Tier{Name: fmt.Sprint("tier", ti), EndAction: []TierEndAction{TierEndDeny, TierEndPass}[r.Intn(2)]}
			for range 1 + r.Intn(10) {
				var pol Policy
				for range 1 + r.Intn(10) {
					pol.Rules = append(pol.Rules, Rule{Rule: randomRule(), MatchID: r.Uint64()})
				}
				tier.Policies = append(tier.Policies, pol)
			}
			tiers = append(tiers, tier)
		}
		rules := Rules{
			Tiers:    tiers,
			Profiles: []Profile{{Name: "kns", Rules: []Rule{{Rule: &proto.Rule{Action: "Allow"}}}}},
		}

		opts := []Option{
			WithAllowDenyJumps(666, 777),
			WithPolicyMapIndexAndStride(15, 1000),
			WithTrampolineStride([]int{asm.TrampolineStrideDefault, 1000 + r.Intn(3000)}[r.Intn(2)]),
		}
		if r.Intn(2) == 0 {
			opts = append(opts, WithFlowLogs())
		}
		opts = append(opts, WithMaxJumpsPerProgram(20+r.Intn(1000)))
		pg := NewBuilder(alloc, 1, 2, 3, 4, opts...)
		progs, err := pg.Instructions(rules)
		Expect(err).NotTo(HaveOccurred(), "iteration %d", iter)
		expectValidSubPrograms(progs, 15, 1000, fmt.Sprintf("iteration %d", iter))
	}
}

// expectValidSubPrograms fails the test if CheckSubPrograms reports an error.
func expectValidSubPrograms(progs []asm.Insns, polMapIdx, stride int, desc string) {
	ExpectWithOffset(1, CheckSubPrograms(progs, polMapIdx, stride)).NotTo(HaveOccurred(), desc)
}
