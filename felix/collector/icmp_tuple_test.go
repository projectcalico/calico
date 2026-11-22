//go:build linux

// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package collector

import (
	"net"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/app-policy/checker"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/nfnetlink"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

// An ICMPv6 flow carries its echo identifier as the source port, and its type and code as the
// destination port, whether an NFLOG packet or a conntrack entry reported it. A staged rule's
// ICMPv6 type then decides the flow's pending verdict, as it does once the rule is enforced.
func TestICMPv6TupleCarriesTypeAndCode(t *testing.T) {
	RegisterTestingT(t)

	var src, dst [16]byte
	copy(src[:], net.ParseIP("fd00::1"))
	copy(dst[:], net.ParseIP("fd00::2"))
	echoRequest := extractTupleFromNflogTuple(nfnetlink.NflogPacketTuple{
		Src: src, Dst: dst, Proto: 58,
		L4Src: nfnetlink.NflogL4Info{Id: 77},
		L4Dst: nfnetlink.NflogL4Info{Type: 128},
	})
	Expect(echoRequest.L4Src).To(Equal(77))
	Expect(echoRequest.L4Dst).To(Equal(128 << 8))
	Expect(extractTupleFromCtEntryTuple(nfnetlink.CtTuple{
		Src: src, Dst: dst, ProtoNum: 58,
		L4Src: nfnetlink.CtL4Src{Id: 77},
		L4Dst: nfnetlink.CtL4Dst{Type: 128},
	})).To(Equal(echoRequest), "conntrack and NFLOG should key the flow the same way")

	unreachable := extractTupleFromNflogTuple(nfnetlink.NflogPacketTuple{
		Src: src, Dst: dst, Proto: 58,
		L4Dst: nfnetlink.NflogL4Info{Type: 1, Code: 4},
	})
	Expect(unreachable.L4Dst).To(Equal(1<<8 | 4))

	allowPing := &proto.PolicyID{Name: "allow-ping", Kind: v3.KindStagedGlobalNetworkPolicy}
	store := policystore.NewPolicyStore()
	store.PolicyByID[types.ProtoToPolicyID(allowPing)] = &proto.Policy{
		Tier: "default",
		InboundRules: []*proto.Rule{{
			Action:    "allow",
			IpVersion: proto.IPVersion_IPV6,
			Protocol:  &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "ICMPv6"}},
			Icmp:      &proto.Rule_IcmpType{IcmpType: 128},
		}},
	}
	ep := &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{{
		Name: "default", IngressPolicies: []*proto.PolicyID{allowPing}, DefaultAction: "Deny",
	}}}

	flow := TupleAsFlow(echoRequest)
	trace, err := checker.Evaluate(checker.StagedAsEnforced, rules.RuleDirIngress, store, ep, &flow)
	Expect(err).NotTo(HaveOccurred())
	Expect(trace).To(Equal([]*calc.RuleID{calc.NewRuleID(v3.KindStagedGlobalNetworkPolicy, "default",
		"allow-ping", "", 0, rules.RuleDirIngress, rules.RuleActionAllow)}))

	flow = TupleAsFlow(unreachable)
	trace, err = checker.Evaluate(checker.StagedAsEnforced, rules.RuleDirIngress, store, ep, &flow)
	Expect(err).NotTo(HaveOccurred())
	Expect(trace).To(Equal([]*calc.RuleID{calc.NewRuleID(v3.KindStagedGlobalNetworkPolicy, "default",
		"allow-ping", "", -1, rules.RuleDirIngress, rules.RuleActionDeny)}))
}
