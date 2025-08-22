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

type DSCPRule struct {
	SrcAddrs string
	Value    uint8
}

func (r *DefaultRuleRenderer) EgressDSCPChain(rules []DSCPRule) *generictables.Chain {
	var renderedRules []generictables.Rule
	// Rules are sorted and validated by DSCP manager.
	for _, rule := range rules {
		renderedRules = append(renderedRules, generictables.Rule{
			Match:  r.NewMatch().SourceNet(rule.SrcAddrs),
			Action: r.DSCP(rule.Value),
		})
	}

	return &generictables.Chain{
		Name:  ChainEgressDSCP,
		Rules: renderedRules,
	}
}
