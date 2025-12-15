// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

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

import (
	"fmt"
	"net"
	"testing"

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/gogo/googleapis/google/rpc"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

func TestEvaluateNoEndpoint(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()

	flow := &MockFlow{}
	trace := Evaluate(rules.RuleDirIngress, store, nil, flow)
	Expect(trace).To(BeNil())
}

func TestEvaluateEndpointNoTiersNoProfiles(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()

	ep := &proto.WorkloadEndpoint{}
	flow := &MockFlow{}
	trace := Evaluate(rules.RuleDirIngress, store, ep, flow)
	Expect(trace).To(HaveLen(1))
	Expect(trace[0].Action).To(Equal(rules.RuleActionDeny))
	Expect(trace[0].Direction).To(Equal(rules.RuleDirIngress))
	Expect(trace[0].Index).To(Equal(-1))
	Expect(trace[0].Tier).To(Equal("__PROFILE__"))
	Expect(trace[0].Name).To(Equal("__PROFILE__"))
	Expect(trace[0].Namespace).To(Equal(""))
}

func TestEvaluateEndpointWithMatchingPolicy(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()

	ep := &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{
			{
				Name:            "tier1",
				IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
				DefaultAction:   "Deny",
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy})] = &proto.Policy{
		Tier: "tier1",
		InboundRules: []*proto.Rule{
			{
				Action: "allow",
			},
		},
	}
	flow := &MockFlow{
		Protocol: 6,
		DestPort: 80,
	}
	trace := Evaluate(rules.RuleDirIngress, store, ep, flow)
	Expect(trace).To(HaveLen(1))
	Expect(trace[0].Action).To(Equal(rules.RuleActionAllow))
	Expect(trace[0].Direction).To(Equal(rules.RuleDirIngress))
	Expect(trace[0].Index).To(Equal(0))
	Expect(trace[0].Tier).To(Equal("tier1"))
	Expect(trace[0].Name).To(Equal("policy1"))
	Expect(trace[0].Namespace).To(Equal(""))
}

func TestEvaluateEndpointWithNonMatchingPolicyTierDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name     string
		tiers    []*proto.TierInfo
		expLen   int
		expActs  []rules.RuleAction
		expIndex int
	}{
		{
			name: "Tier1 Deny -> Tier2 Pass",
			tiers: []*proto.TierInfo{
				{
					Name:            "tier1",
					IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
					DefaultAction:   "Deny",
				},
				{
					Name:            "tier2",
					IngressPolicies: []*proto.PolicyID{{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}},
					DefaultAction:   "Pass",
				},
			},
			expLen:   1,
			expActs:  []rules.RuleAction{rules.RuleActionDeny},
			expIndex: -1,
		},
		{
			name: "Tier1 Pass -> Tier2 Deny",
			tiers: []*proto.TierInfo{
				{
					Name:            "tier1",
					IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
					DefaultAction:   "Pass",
				},
				{
					Name:            "tier2",
					IngressPolicies: []*proto.PolicyID{{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}},
					DefaultAction:   "Deny",
				},
			},
			expLen:   2,
			expActs:  []rules.RuleAction{rules.RuleActionPass, rules.RuleActionDeny},
			expIndex: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := policystore.NewPolicyStore()
			ep := &proto.WorkloadEndpoint{Tiers: tt.tiers}
			store.PolicyByID[types.PolicyID{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}] = &proto.Policy{Tier: "default"}
			store.PolicyByID[types.PolicyID{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}] = &proto.Policy{Tier: "default"}

			flow := &MockFlow{Protocol: 6, DestPort: 443}
			trace := Evaluate(rules.RuleDirIngress, store, ep, flow)

			Expect(trace).To(HaveLen(tt.expLen))
			for i, act := range tt.expActs {
				Expect(trace[i].Action).To(Equal(act))
				Expect(trace[i].Index).To(Equal(tt.expIndex))
			}
		})
	}
}

func TestEvaluateEndpointWithMatchingProfile(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()

	ep := &proto.WorkloadEndpoint{
		ProfileIds: []string{"profile1"},
	}
	store.ProfileByID[types.ProtoToProfileID(&proto.ProfileID{Name: "profile1"})] = &proto.Profile{
		InboundRules: []*proto.Rule{
			{
				Action: "allow",
			},
		},
	}
	flow := &MockFlow{
		Protocol: 6,
		DestPort: 80,
	}
	trace := Evaluate(rules.RuleDirIngress, store, ep, flow)
	Expect(trace).To(HaveLen(1))
	Expect(trace[0].Action).To(Equal(rules.RuleActionAllow))
	Expect(trace[0].Direction).To(Equal(rules.RuleDirIngress))
	Expect(trace[0].Index).To(Equal(0))
	Expect(trace[0].Tier).To(Equal("__PROFILE__"))
	Expect(trace[0].Name).To(Equal("profile1"))
	Expect(trace[0].Namespace).To(Equal(""))
}

func TestEvaluateEndpointWithNonMatchingProfile(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()

	ep := &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{
			{
				Name:           "tier1",
				EgressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
				DefaultAction:  "Deny",
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy})] = &proto.Policy{
		Tier:      "tier1",
		Namespace: "ns1",
		OutboundRules: []*proto.Rule{
			{
				Action: "allow",
				SrcNet: []string{"10.0.0.0/24"},
				DstPorts: []*proto.PortRange{
					{First: 80, Last: 80},
				},
			},
			{
				Action: "deny",
				SrcNet: []string{"192.168.1.0/24"},
				DstPorts: []*proto.PortRange{
					{First: 441, Last: 444},
				},
			},
		},
	}

	ip_10_0_0_1 := net.ParseIP("10.0.0.1")
	ip_10_0_0_2 := net.ParseIP("10.0.0.2")
	ip_192_168_1_1 := net.ParseIP("192.168.1.1")
	ip_192_168_1_2 := net.ParseIP("192.168.1.2")

	flow1 := &MockFlow{
		Protocol:   6,
		SourcePort: 80,
		DestPort:   443,
		SourceIP:   ip_10_0_0_1,
		DestIP:     ip_192_168_1_1,
	}
	trace := Evaluate(rules.RuleDirEgress, store, ep, flow1)
	Expect(trace).To(HaveLen(1))
	Expect(trace[0].Action).To(Equal(rules.RuleActionDeny))
	Expect(trace[0].Direction).To(Equal(rules.RuleDirEgress))
	Expect(trace[0].Index).To(Equal(-1))
	Expect(trace[0].Tier).To(Equal("tier1"))
	Expect(trace[0].Name).To(Equal("policy1"))
	Expect(trace[0].Namespace).To(Equal("ns1"))

	// Test with a matching source IP and destination port 80
	flow2 := &MockFlow{
		Protocol:   6,
		SourcePort: 443,
		DestPort:   80,
		SourceIP:   ip_10_0_0_1,
		DestIP:     ip_192_168_1_1,
	}
	trace = Evaluate(rules.RuleDirEgress, store, ep, flow2)
	Expect(trace).To(HaveLen(1))
	Expect(trace[0].Action).To(Equal(rules.RuleActionAllow))
	Expect(trace[0].Direction).To(Equal(rules.RuleDirEgress))
	Expect(trace[0].Index).To(Equal(0))
	Expect(trace[0].Tier).To(Equal("tier1"))
	Expect(trace[0].Name).To(Equal("policy1"))
	Expect(trace[0].Namespace).To(Equal("ns1"))

	// Test with a matching source IP and destination port 443
	flow3 := &MockFlow{
		Protocol:   6,
		SourcePort: 80,
		DestPort:   443,
		SourceIP:   ip_192_168_1_2,
		DestIP:     ip_10_0_0_2,
	}
	trace = Evaluate(rules.RuleDirEgress, store, ep, flow3)
	Expect(trace).To(HaveLen(1))
	Expect(trace[0].Action).To(Equal(rules.RuleActionDeny))
	Expect(trace[0].Direction).To(Equal(rules.RuleDirEgress))
	Expect(trace[0].Index).To(Equal(1))
	Expect(trace[0].Tier).To(Equal("tier1"))
	Expect(trace[0].Name).To(Equal("policy1"))
	Expect(trace[0].Namespace).To(Equal("ns1"))
}

// actionFromString should parse strings in case-insensitive mode.
func TestActionFromString(t *testing.T) {
	RegisterTestingT(t)

	Expect(actionFromString("allow")).To(Equal(ALLOW))
	Expect(actionFromString("Allow")).To(Equal(ALLOW))
	Expect(actionFromString("deny")).To(Equal(DENY))
	Expect(actionFromString("Deny")).To(Equal(DENY))
	Expect(actionFromString("pass")).To(Equal(PASS))
	Expect(actionFromString("Pass")).To(Equal(PASS))
	Expect(actionFromString("log")).To(Equal(LOG))
	Expect(actionFromString("Log")).To(Equal(LOG))
	Expect(actionFromString("next-tier")).To(Equal(PASS))
	Expect(func() { actionFromString("no_match") }).To(Panic())
}

// A policy with no rules does not match.
func TestCheckPolicyNoRules(t *testing.T) {
	RegisterTestingT(t)

	policy := &proto.Policy{}
	store := policystore.NewPolicyStore()
	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sue",
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)
	reqCache := NewRequestCache(store, flow)
	st, idx := checkPolicy(policy, rules.RuleDirIngress, reqCache)
	Expect(st).To(Equal(NO_MATCH))
	Expect(idx).To(Equal(tierDefaultActionIndex))
}

// If rules exist, but none match, we should get NO_MATCH
// Rules that do match should return their Action.
// Log rules should continue processing.
func TestCheckPolicyRules(t *testing.T) {
	RegisterTestingT(t)

	policy := &proto.Policy{InboundRules: []*proto.Rule{
		{
			Action: "log",
			HttpMatch: &proto.HTTPMatch{
				Methods: []string{"GET", "POST"},
			},
		},
		{
			Action: "allow",
			HttpMatch: &proto.HTTPMatch{
				Methods: []string{"POST"},
			},
		},
		{
			Action: "deny",
			HttpMatch: &proto.HTTPMatch{
				Methods: []string{"GET"},
			},
		},
	}}
	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sue",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "HEAD"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)
	reqCache := NewRequestCache(policystore.NewPolicyStore(), flow)
	st, idx := checkPolicy(policy, rules.RuleDirIngress, reqCache)
	Expect(st).To(Equal(NO_MATCH))
	Expect(idx).To(Equal(tierDefaultActionIndex))

	http := req.GetAttributes().GetRequest().GetHttp()
	http.Method = "POST"
	st, idx = checkPolicy(policy, rules.RuleDirIngress, reqCache)
	Expect(st).To(Equal(ALLOW))
	Expect(idx).To(Equal(1))

	http.Method = "GET"
	st, idx = checkPolicy(policy, rules.RuleDirIngress, reqCache)
	Expect(st).To(Equal(DENY))
	Expect(idx).To(Equal(2))
}

// If tiers have no ingress policies, we should not get NO_MATCH.
func TestCheckNoIngressPolicyRulesInTier(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.Endpoint = &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{
			{
				Name:           "tier1",
				EgressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}},
				DefaultAction:  "Deny",
			},
		},
		ProfileIds: []string{"profile1"},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy})] = &proto.Policy{
		Tier: "tier1",
		OutboundRules: []*proto.Rule{
			{
				Action: "allow",
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy})] = &proto.Policy{
		Tier: "tier1",
		OutboundRules: []*proto.Rule{
			{
				Action: "allow",
			},
		},
	}
	store.ProfileByID[types.ProtoToProfileID(&proto.ProfileID{Name: "profile1"})] = &proto.Profile{
		InboundRules: []*proto.Rule{
			{
				Action:    "allow",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"GET"}},
			},
		},
	}
	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sue",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "GET"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)
	status, _ := checkTiers(store, store.Endpoint, rules.RuleDirIngress, flow)
	expectedStatus := rpc.Status{Code: OK}
	Expect(status.Code).To(Equal(expectedStatus.Code))
	Expect(status.Message).To(Equal(expectedStatus.Message))
	Expect(status.Details).To(BeNil())
}

// CheckStore when the store has no endpoint should deny requests.
func TestCheckStoreNoEndpoint(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "HEAD"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)
	status := checkStore(store, nil, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(PERMISSION_DENIED))
}

// CheckStore with no Tiers and no Profiles on the endpoint should deny.
func TestCheckStoreNoTiers(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.Endpoint = &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{},
	}
	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "HEAD"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)
	status := checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(PERMISSION_DENIED))
}

// If a Policy matches, the action on the matched rule is the result.
func TestCheckStorePolicyMatch(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.Endpoint = &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{
			{
				Name:            "tier1",
				IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}},
				DefaultAction:   "Deny",
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy})] = &proto.Policy{
		Tier: "tier1",
		InboundRules: []*proto.Rule{
			{
				Action:    "deny",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"HEAD"}},
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy})] = &proto.Policy{
		Tier: "tier1",
		InboundRules: []*proto.Rule{
			{
				Action:    "allow",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"GET"}},
			},
		},
	}

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sally",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "GET"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)

	status := checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(OK))

	http := req.GetAttributes().GetRequest().GetHttp()
	http.Method = "HEAD"

	status = checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(PERMISSION_DENIED))
}

// And endpoint with no Tiers should evaluate Profiles.
func TestCheckStoreProfileOnly(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.Endpoint = &proto.WorkloadEndpoint{
		Tiers:      []*proto.TierInfo{},
		ProfileIds: []string{"profile1", "profile2"},
	}
	store.ProfileByID[types.ProtoToProfileID(&proto.ProfileID{Name: "profile1"})] = &proto.Profile{
		InboundRules: []*proto.Rule{
			{
				Action:    "Deny",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"HEAD"}},
			},
		},
	}
	store.ProfileByID[types.ProtoToProfileID(&proto.ProfileID{Name: "profile2"})] = &proto.Profile{
		InboundRules: []*proto.Rule{
			{
				Action:    "allow",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"GET"}},
			},
		},
	}

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/quinn",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "GET"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)

	status := checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(OK))

	http := req.GetAttributes().GetRequest().GetHttp()
	http.Method = "HEAD"

	status = checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(PERMISSION_DENIED))
}

// And endpoint with a Tier should not evaluate profiles; there is a default deny on the tier.
func TestCheckStorePolicyDefaultDeny(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.Endpoint = &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{
			{
				Name:            "tier1",
				IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
				DefaultAction:   "Deny",
			},
		},
		ProfileIds: []string{"profile1"},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Name: "policy1"})] = &proto.Policy{
		Tier: "tier1",
		InboundRules: []*proto.Rule{
			{
				Action:    "deny",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"HEAD"}},
			},
		},
	}
	store.ProfileByID[types.ProtoToProfileID(&proto.ProfileID{Name: "profile1"})] = &proto.Profile{
		InboundRules: []*proto.Rule{
			{
				Action:    "allow",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"GET"}},
			},
		},
	}

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/quinn",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "GET"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)

	status := checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(PERMISSION_DENIED))
}

// Ensure policy action of "Pass" ends policy evaluation and moves to profiles.
func TestCheckStorePass(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.Endpoint = &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{{
			Name:            "tier1",
			IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}},
			DefaultAction:   "Deny",
		}},
		ProfileIds: []string{"profile1"},
	}

	// Policy1 matches and has action PASS, which means policy2 is not evaluated.
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Kind: v3.KindGlobalNetworkPolicy, Name: "policy1"})] = &proto.Policy{
		Tier: "tier1",
		InboundRules: []*proto.Rule{
			{
				Action:    "next-tier",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"GET"}},
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Kind: v3.KindGlobalNetworkPolicy, Name: "policy2"})] = &proto.Policy{
		Tier: "tier1",
		InboundRules: []*proto.Rule{
			{
				Action:    "deny",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"GET"}},
			},
		},
	}

	// Profile1 matches and allows the traffic.
	store.ProfileByID[types.ProtoToProfileID(&proto.ProfileID{Name: "profile1"})] = &proto.Profile{
		InboundRules: []*proto.Rule{
			{
				Action:    "allow",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"HEAD", "GET"}},
			},
		},
	}

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/molly",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "GET"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)

	status := checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(OK))
}

func TestCheckStoreInitFails(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.Endpoint = &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{{
			Name:            "tier1",
			IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}},
			DefaultAction:   "Deny",
		}},
		ProfileIds: []string{"profile1"},
	}

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://malformed",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "GET"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)

	status := checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(PERMISSION_DENIED))
}

// Ensure checkStore returns INVALID_ARGUMENT on invalid input
func TestCheckStoreWithInvalidData(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.Endpoint = &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{{
			Name:            "tier1",
			IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}},
			DefaultAction:   "Deny",
		}},
		ProfileIds: []string{"profile1"},
	}
	id := types.ProtoToPolicyID(&proto.PolicyID{Kind: v3.KindGlobalNetworkPolicy, Name: "policy1"})
	store.PolicyByID[id] = &proto.Policy{InboundRules: []*proto.Rule{
		{
			Action: "allow",
			HttpMatch: &proto.HTTPMatch{
				Methods: []string{"GET", "POST"},
				Paths: []*proto.HTTPMatch_PathMatch{
					{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}},
				},
			},
		},
	}}
	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sue",
		},
		Request: &authz.AttributeContext_Request{
			// the path is invalid data as it does not have the `/' prefix
			Http: &authz.AttributeContext_HttpRequest{Method: "GET", Path: "foo"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)
	status := checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(INVALID_ARGUMENT))
}

// Check multiple tiers with next-tier (pass) to next tier and match the action on the matched rule in the next tier is
// the result. For one path, /bar, matching hits tier2 default pass action, and result is based on a matched rule in tier3.
func TestCheckStorePolicyMultiTierMatch(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.Endpoint = &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{
			{
				Name:            "tier1",
				IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
				DefaultAction:   "Deny",
			},
			{
				Name:            "tier2",
				IngressPolicies: []*proto.PolicyID{{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}, {Name: "policy3", Kind: v3.KindGlobalNetworkPolicy}},
				DefaultAction:   "Pass",
			},
			{
				Name:            "tier3",
				IngressPolicies: []*proto.PolicyID{{Name: "policy4", Kind: v3.KindGlobalNetworkPolicy}},
				DefaultAction:   "Deny",
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Kind: v3.KindGlobalNetworkPolicy, Name: "policy1"})] = &proto.Policy{
		Tier: "tier1",
		InboundRules: []*proto.Rule{
			{
				Action:    "next-tier",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"GET", "HEAD"}},
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy})] = &proto.Policy{
		Tier: "tier2",
		InboundRules: []*proto.Rule{
			{
				Action: "deny",
				HttpMatch: &proto.HTTPMatch{
					Paths: []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/bad"}}},
				},
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Name: "policy3", Kind: v3.KindGlobalNetworkPolicy})] = &proto.Policy{
		Tier: "tier2",
		InboundRules: []*proto.Rule{
			{
				Action: "allow",
				HttpMatch: &proto.HTTPMatch{
					Paths: []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}},
				},
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Name: "policy4", Kind: v3.KindGlobalNetworkPolicy})] = &proto.Policy{
		Tier: "tier3",
		InboundRules: []*proto.Rule{
			{
				Action: "allow",
				HttpMatch: &proto.HTTPMatch{
					Paths: []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/bar"}}},
				},
			},
		},
	}

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sally",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "GET", Path: "/foo"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)

	status := checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(OK))

	// Change to a bad path, and check that we get PERMISSION_DENIED
	http := req.GetAttributes().GetRequest().GetHttp()
	http.Path = "/bad"

	status = checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(PERMISSION_DENIED))

	// Change to a path that hits tier2 default Pass action, and then is allowed in tier3
	http.Path = "/bar"

	status = checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(OK))
}

// Check multiple tiers with next-tier (pass) or deny in first tier and an allow in next tier.
func TestCheckStorePolicyMultiTierDiffTierMatch(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.Endpoint = &proto.WorkloadEndpoint{
		Tiers: []*proto.TierInfo{
			{
				Name:            "tier1",
				IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}},
				DefaultAction:   "Deny",
			},
			{
				Name:            "tier2",
				IngressPolicies: []*proto.PolicyID{{Name: "policy3", Kind: v3.KindGlobalNetworkPolicy}},
				DefaultAction:   "Pass",
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Kind: v3.KindGlobalNetworkPolicy, Name: "policy1"})] = &proto.Policy{
		Tier: "tier1",
		InboundRules: []*proto.Rule{
			{
				Action:    "deny",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"HEAD"}},
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Kind: v3.KindGlobalNetworkPolicy, Name: "policy2"})] = &proto.Policy{
		Tier: "tier1",
		InboundRules: []*proto.Rule{
			{
				Action:    "next-tier",
				HttpMatch: &proto.HTTPMatch{Methods: []string{"GET"}},
			},
		},
	}
	store.PolicyByID[types.ProtoToPolicyID(&proto.PolicyID{Name: "policy3", Kind: v3.KindGlobalNetworkPolicy})] = &proto.Policy{
		Tier: "tier2",
		InboundRules: []*proto.Rule{
			{
				Action: "allow",
				HttpMatch: &proto.HTTPMatch{
					Methods: []string{"GET"},
					Paths:   []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}},
				},
			},
		},
	}

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sally",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "HEAD", Path: "/foo"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)
	status := checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(PERMISSION_DENIED))

	http := req.GetAttributes().GetRequest().GetHttp()
	http.Method = "GET"

	status = checkStore(store, store.Endpoint, rules.RuleDirIngress, flow)
	Expect(status.Code).To(Equal(OK))
}

func TestLookupEndpointKeysFromSrcDstNoStore(t *testing.T) {
	RegisterTestingT(t)

	src, dst, err := LookupEndpointKeysFromSrcDst(nil, "10.0.0.1", "192.168.1.1")
	Expect(err).To(HaveOccurred())
	Expect(src).To(BeNil())
	Expect(dst).To(BeNil())
}

func TestLookupEndpointKeysFromSrcDst(t *testing.T) {
	RegisterTestingT(t)

	store := policystore.NewPolicyStore()
	store.IPToIndexes.Update(ip.MustParseCIDROrIP("10.0.0.1/32").Addr(), &proto.WorkloadEndpointUpdate{Id: &proto.WorkloadEndpointID{OrchestratorId: "default", WorkloadId: "wep1", EndpointId: "ep1"}, Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{"profile1"}}})
	store.IPToIndexes.Update(ip.MustParseCIDROrIP("10.0.0.2/32").Addr(), &proto.WorkloadEndpointUpdate{Id: &proto.WorkloadEndpointID{OrchestratorId: "default", WorkloadId: "wep2", EndpointId: "ep2"}, Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{"profile2"}}})
	store.IPToIndexes.Update(ip.MustParseCIDROrIP("192.168.1.1/32").Addr(), &proto.WorkloadEndpointUpdate{Id: &proto.WorkloadEndpointID{OrchestratorId: "default", WorkloadId: "wep3", EndpointId: "ep3"}, Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{"profile3"}}})
	store.IPToIndexes.Update(ip.MustParseCIDROrIP("192.168.1.2/32").Addr(), &proto.WorkloadEndpointUpdate{Id: &proto.WorkloadEndpointID{OrchestratorId: "default", WorkloadId: "wep4", EndpointId: "ep4"}, Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{"profile4"}}})

	tests := []struct {
		src, dst                 string
		expectedSrc, expectedDst []proto.WorkloadEndpointID
	}{
		{
			src: "10.0.0.1", dst: "192.168.1.1",
			expectedSrc: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep1", EndpointId: "ep1"}},
			expectedDst: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep3", EndpointId: "ep3"}},
		},
		{
			src: "10.0.0.2", dst: "10.0.0.1",
			expectedSrc: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep2", EndpointId: "ep2"}},
			expectedDst: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep1", EndpointId: "ep1"}},
		},
		{
			src: "10.0.0.3", dst: "192.168.1.1",
			expectedSrc: nil,
			expectedDst: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep3", EndpointId: "ep3"}},
		},
		{
			src: "10.0.0.1", dst: "192.168.1.2",
			expectedSrc: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep1", EndpointId: "ep1"}},
			expectedDst: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep4", EndpointId: "ep4"}},
		},
		{
			src: "192.168.1.1", dst: "10.0.0.2",
			expectedSrc: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep3", EndpointId: "ep3"}},
			expectedDst: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep2", EndpointId: "ep2"}},
		},
		{
			src: "192.168.1.2", dst: "10.0.0.1",
			expectedSrc: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep4", EndpointId: "ep4"}},
			expectedDst: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep1", EndpointId: "ep1"}},
		},
		{
			src: "192.168.1.3", dst: "10.0.0.1",
			expectedSrc: nil,
			expectedDst: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep1", EndpointId: "ep1"}},
		},
		{
			src: "10.0.0.1", dst: "192.168.1.3",
			expectedSrc: []proto.WorkloadEndpointID{{OrchestratorId: "default", WorkloadId: "wep1", EndpointId: "ep1"}},
			expectedDst: nil,
		},
	}

	for i, test := range tests {
		src, dst, err := LookupEndpointKeysFromSrcDst(store, test.src, test.dst)
		Expect(err).To(BeNil(), fmt.Sprintf("Test case %d", i))
		Expect(src).To(Equal(test.expectedSrc), fmt.Sprintf("Test case %d", i))
		Expect(dst).To(Equal(test.expectedDst), fmt.Sprintf("Test case %d", i))
	}
}

// MockFlow is a mock implementation of the Flow interface for testing purposes.
type MockFlow struct {
	SourceIP        net.IP
	DestIP          net.IP
	SourcePort      int
	DestPort        int
	Protocol        int
	HttpMethod      *string
	HttpPath        *string
	SourcePrincipal *string
	DestPrincipal   *string
	SourceLabels    map[string]string
	DestLabels      map[string]string
}

func (m *MockFlow) GetSourceIP() net.IP {
	return m.SourceIP
}

func (m *MockFlow) GetDestIP() net.IP {
	return m.DestIP
}

func (m *MockFlow) GetSourcePort() int {
	return m.SourcePort
}

func (m *MockFlow) GetDestPort() int {
	return m.DestPort
}

func (m *MockFlow) GetProtocol() int {
	return m.Protocol
}

func (m *MockFlow) GetHttpMethod() *string {
	return m.HttpMethod
}

func (m *MockFlow) GetHttpPath() *string {
	return m.HttpPath
}

func (m *MockFlow) GetSourcePrincipal() *string {
	return m.SourcePrincipal
}

func (m *MockFlow) GetDestPrincipal() *string {
	return m.DestPrincipal
}

func (m *MockFlow) GetSourceLabels() map[string]string {
	return m.SourceLabels
}

func (m *MockFlow) GetDestLabels() map[string]string {
	return m.DestLabels
}
