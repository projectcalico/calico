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
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/iptables"
)

func (r *ruleRenderer) StaticFilterTableChains() (chains []*iptables.Chain) {
	chains = append(chains, r.StaticFilterForwardChains()...)
	chains = append(chains, r.StaticFilterInputChains()...)
	chains = append(chains, r.StaticFilterOutputChains()...)
	return
}

func (r *ruleRenderer) StaticFilterInputChains() []*iptables.Chain {
	// TODO(smc) fitler input chain
	return []*iptables.Chain{}
}

func (r *ruleRenderer) StaticFilterForwardChains() []*iptables.Chain {
	rules := []iptables.Rule{}

	for _, prefix := range r.WorkloadIfacePrefixes {
		logrus.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + "+"
		rules = append(rules, r.DropRules(
			fmt.Sprintf("--in-interface %s --match conntrack --ctstate INVALID", ifaceMatch))...)

		rules = append(rules,
			iptables.Rule{
				MatchCriteria: fmt.Sprintf("--in-interface %s --match conntrack --ctstate RELATED,ESTABLISHED", ifaceMatch),
				Action:        iptables.AcceptAction{},
			},
			iptables.Rule{
				MatchCriteria: fmt.Sprintf("--out-interface %s --match conntrack --ctstate RELATED,ESTABLISHED", ifaceMatch),
				Action:        iptables.AcceptAction{},
			},
			iptables.Rule{
				MatchCriteria: fmt.Sprintf("--in-interface %s", ifaceMatch),
				Action:        iptables.JumpAction{Target: DispatchFromWorkloadEndpoint},
			},
			iptables.Rule{
				MatchCriteria: fmt.Sprintf("--out-interface %s", ifaceMatch),
				Action:        iptables.JumpAction{Target: DispatchToWorkloadEndpoint},
			},
			iptables.Rule{
				MatchCriteria: fmt.Sprintf("--in-interface %s", ifaceMatch),
				Action:        iptables.AcceptAction{},
			},
			iptables.Rule{
				MatchCriteria: fmt.Sprintf("--out-interface %s", ifaceMatch),
				Action:        iptables.AcceptAction{},
			})
	}

	return []*iptables.Chain{{
		Name:  ForwardChainName,
		Rules: rules,
	}}
}

func (r *ruleRenderer) StaticFilterOutputChains() []*iptables.Chain {
	// TODO(smc) fitler output chain
	return []*iptables.Chain{}
}

func (t ruleRenderer) DropRules(matchCriteria string) []iptables.Rule {
	return []iptables.Rule{
		{
			MatchCriteria: matchCriteria,
			Action:        iptables.DropAction{},
		},
	}
}
