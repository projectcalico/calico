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

package checker

// Benchmark for Evaluate() against rules that match on a named port or on a destination service,
// both of which Felix sends as IP+port sets, with a flow that matches none of them. Every rule
// reaches one set membership check, so a per-check cost shows up once per rule.
//
//	go test ./app-policy/checker/ -run '^$' -bench BenchmarkEvaluateIPPortSets \
//	    -benchmem -benchtime 1000x -cpu 1

import (
	"fmt"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

const ipPortSetRules = 1000

func BenchmarkEvaluateIPPortSets(b *testing.B) {
	b.Run("NamedPorts", func(b *testing.B) {
		benchEvaluateIPPortSets(b, func(setID string) *proto.Rule {
			return &proto.Rule{Action: "allow", Protocol: tcpProtocol(), DstNamedPortIpSetIds: []string{setID}}
		})
	})
	b.Run("Services", func(b *testing.B) {
		benchEvaluateIPPortSets(b, func(setID string) *proto.Rule {
			return &proto.Rule{Action: "allow", Protocol: tcpProtocol(), DstIpPortSetIds: []string{setID}}
		})
	})
}

func benchEvaluateIPPortSets(b *testing.B, ruleFor func(setID string) *proto.Rule) {
	restoreLogging := withBenchLogging(logrus.WarnLevel)
	defer restoreLogging()

	store := policystore.NewPolicyStore()
	var outbound []*proto.Rule
	for i := range ipPortSetRules {
		id := fmt.Sprintf("ip-port-set-%d", i)
		s := policystore.NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
		s.AddString(fmt.Sprintf("10.1.%d.%d,tcp:8080", i/256, i%256))
		store.IPSetByID[id] = s
		outbound = append(outbound, ruleFor(id))
	}
	pid := &proto.PolicyID{Name: "ip-port-sets", Kind: v3.KindGlobalNetworkPolicy}
	store.PolicyByID[types.ProtoToPolicyID(pid)] = &proto.Policy{Tier: "tier1", OutboundRules: outbound}
	ep := &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{{
		Name:           "tier1",
		EgressPolicies: []*proto.PolicyID{pid},
		DefaultAction:  "Deny",
	}}}
	flow := egressFlow("10.2.0.1", 8080)

	// Pre-flight outside the timed loop. A flow to the last rule's set member must be allowed by
	// that rule, which shows the rules get as far as their set check; and the benchmark's flow
	// must walk every rule to the tier's default deny, or the loop would time an early exit.
	last := fmt.Sprintf("10.1.%d.%d", (ipPortSetRules-1)/256, (ipPortSetRules-1)%256)
	trace, err := Evaluate(EnforcedOnly, rules.RuleDirEgress, store, ep, egressFlow(last, 8080))
	if err != nil {
		b.Fatalf("evaluation failed: %v", err)
	}
	if len(trace) != 1 || trace[0].Action != rules.RuleActionAllow || trace[0].Index != ipPortSetRules-1 {
		b.Fatalf("expected an allow from the last rule, got %v", trace)
	}
	trace, err = Evaluate(EnforcedOnly, rules.RuleDirEgress, store, ep, flow)
	if err != nil {
		b.Fatalf("evaluation failed: %v", err)
	}
	if len(trace) != 1 || trace[0].Action != rules.RuleActionDeny || trace[0].Index != tierDefaultActionIndex {
		b.Fatalf("expected a full walk ending in the tier default deny, got %v", trace)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchTraceSink, _ = Evaluate(EnforcedOnly, rules.RuleDirEgress, store, ep, flow)
	}
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/ipPortSetRules, "ns/rule")
}

func tcpProtocol() *proto.Protocol {
	return &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}}
}
