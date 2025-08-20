// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/calico/felix/generictables"
)

type QoSPolicy struct {
	SrcAddrs string
	DSCP     uint8
}

func (r *DefaultRuleRenderer) EgressQoSPolicyChain(policies []QoSPolicy) *generictables.Chain {
	var rules []generictables.Rule
	// Policies is sorted and validated by QoS policy manager.
	for _, p := range policies {
		rules = append(rules, generictables.Rule{
			Match:  r.NewMatch().SourceNet(p.SrcAddrs),
			Action: r.DSCP(p.DSCP),
		})
	}

	return &generictables.Chain{
		Name:  ChainQoSPolicy,
		Rules: rules,
	}
}
