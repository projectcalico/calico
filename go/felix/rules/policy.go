// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package rules

import (
	"github.com/projectcalico/felix/go/felix/hashutils"
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
)

// ruleRenderer defined in rules_defs.go.

func (r *ruleRenderer) PolicyToIptablesChains(policyID *proto.PolicyID, policy *proto.Policy) (inbound, outbound *iptables.Chain) {
	inbound = &iptables.Chain{
		Name:  PolicyChainName(InboundPolChainPrefix, policyID),
		Rules: r.ProtoRulesToIptablesRules(policy.InboundRules),
	}
	outbound = &iptables.Chain{
		Name:  PolicyChainName(OutboundPolChainPrefix, policyID),
		Rules: r.ProtoRulesToIptablesRules(policy.OutboundRules),
	}
	return
}

func (r *ruleRenderer) ProtoRulesToIptablesRules(protoRules []*proto.Rule) []iptables.Rule {
	var rules []iptables.Rule
	for _, protoRule := range protoRules {
		rules = append(rules, r.ProtoRuleToIptablesRule(protoRule)...)
	}
	return rules
}

func (r *ruleRenderer) ProtoRuleToIptablesRule(protoRule *proto.Rule) []iptables.Rule {
	return []iptables.Rule{{
		MatchCriteria: `-m comment --comment "A rule to be"`,
		Action:        `-j LOG`,
	}}
}

func PolicyChainName(prefix string, polID *proto.PolicyID) string {
	return hashutils.GetLengthLimitedID(
		prefix,
		polID.Tier+"/"+polID.Name,
		iptables.MaxChainNameLength,
	)
}
