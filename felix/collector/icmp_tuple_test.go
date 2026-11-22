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

// An ICMP or ICMPv6 flow carries its echo identifier as the source port, and its type and code
// as the destination port, whether an NFLOG packet or a conntrack entry reported it. A staged
// rule's ICMP type then decides the flow's pending verdict, as it does once the rule is enforced.
func TestICMPTupleCarriesTypeAndCode(t *testing.T) {
	testCases := []struct {
		name             string
		src, dst         string
		proto            int
		ruleProtocol     string
		ipVersion        proto.IPVersion
		echoType         int
		otherType, other int
	}{
		{"ICMP", "10.0.0.1", "10.0.0.2", 1, "ICMP", proto.IPVersion_IPV4, 8, 3, 1},
		{"ICMPv6", "fd00::1", "fd00::2", 58, "ICMPv6", proto.IPVersion_IPV6, 128, 1, 4},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)

			var src, dst [16]byte
			copy(src[:], net.ParseIP(tc.src).To16())
			copy(dst[:], net.ParseIP(tc.dst).To16())
			echoRequest := extractTupleFromNflogTuple(nfnetlink.NflogPacketTuple{
				Src: src, Dst: dst, Proto: tc.proto,
				L4Src: nfnetlink.NflogL4Info{Id: 77},
				L4Dst: nfnetlink.NflogL4Info{Type: tc.echoType},
			})
			Expect(echoRequest.L4Src).To(Equal(77))
			Expect(echoRequest.L4Dst).To(Equal(tc.echoType << 8))
			Expect(extractTupleFromCtEntryTuple(nfnetlink.CtTuple{
				Src: src, Dst: dst, ProtoNum: tc.proto,
				L4Src: nfnetlink.CtL4Src{Id: 77},
				L4Dst: nfnetlink.CtL4Dst{Type: tc.echoType},
			})).To(Equal(echoRequest), "conntrack and NFLOG should key the flow the same way")

			other := extractTupleFromCtEntryTuple(nfnetlink.CtTuple{
				Src: src, Dst: dst, ProtoNum: tc.proto,
				L4Dst: nfnetlink.CtL4Dst{Type: tc.otherType, Code: tc.other},
			})
			Expect(other.L4Dst).To(Equal(tc.otherType<<8 | tc.other))
			Expect(extractTupleFromNflogTuple(nfnetlink.NflogPacketTuple{
				Src: src, Dst: dst, Proto: tc.proto,
				L4Dst: nfnetlink.NflogL4Info{Type: tc.otherType, Code: tc.other},
			})).To(Equal(other))

			allowPing := &proto.PolicyID{Name: "allow-ping", Kind: v3.KindStagedGlobalNetworkPolicy}
			store := policystore.NewPolicyStore()
			store.PolicyByID[types.ProtoToPolicyID(allowPing)] = &proto.Policy{
				Tier: "default",
				InboundRules: []*proto.Rule{{
					Action:    "allow",
					IpVersion: tc.ipVersion,
					Protocol:  &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: tc.ruleProtocol}},
					Icmp:      &proto.Rule_IcmpType{IcmpType: int32(tc.echoType)},
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

			flow = TupleAsFlow(other)
			trace, err = checker.Evaluate(checker.StagedAsEnforced, rules.RuleDirIngress, store, ep, &flow)
			Expect(err).NotTo(HaveOccurred())
			Expect(trace).To(Equal([]*calc.RuleID{calc.NewRuleID(v3.KindStagedGlobalNetworkPolicy, "default",
				"allow-ping", "", -1, rules.RuleDirIngress, rules.RuleActionDeny)}))
		})
	}
}
