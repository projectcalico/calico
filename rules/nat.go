// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/felix/iptables"
	"sort"
)

func (r *DefaultRuleRenderer) NATOutgoingChain(natOutgoingActive bool, ipVersion uint8) *iptables.Chain {
	var rules []iptables.Rule
	if natOutgoingActive {
		ipConf := r.ipSetConfig(ipVersion)
		allIPsSetName := ipConf.NameForMainIPSet(IPSetIDNATOutgoingAllPools)
		masqIPsSetName := ipConf.NameForMainIPSet(IPSetIDNATOutgoingMasqPools)
		rules = []iptables.Rule{
			{
				Action: iptables.MasqAction{},
				Match: iptables.Match().
					SourceIPSet(masqIPsSetName).
					NotDestIPSet(allIPsSetName),
			},
		}
	}
	return &iptables.Chain{
		Name:  ChainNATOutgoing,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) DNATsToIptablesChains(dnats map[string]string) []*iptables.Chain {
	// Extract and sort map keys so we can program rules in a determined order.
	sortedExtIps := make([]string, 0, len(dnats))
	for extIp := range dnats {
		sortedExtIps = append(sortedExtIps, extIp)
	}
	sort.Strings(sortedExtIps)

	rules := []iptables.Rule{}
	for _, extIp := range sortedExtIps {
		intIp := dnats[extIp]
		rules = append(rules, iptables.Rule{
			Match:  iptables.Match().DestNet(extIp),
			Action: iptables.DNATAction{DestAddr: intIp},
		})
	}
	return []*iptables.Chain{{
		Name:  ChainFIPDnat,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) SNATsToIptablesChains(snats map[string]string) []*iptables.Chain {
	// Extract and sort map keys so we can program rules in a determined order.
	sortedIntIps := make([]string, 0, len(snats))
	for intIp := range snats {
		sortedIntIps = append(sortedIntIps, intIp)
	}
	sort.Strings(sortedIntIps)

	rules := []iptables.Rule{}
	for _, intIp := range sortedIntIps {
		extIp := snats[intIp]
		rules = append(rules, iptables.Rule{
			Match:  iptables.Match().DestNet(intIp).SourceNet(intIp),
			Action: iptables.SNATAction{ToAddr: extIp},
		})
	}
	return []*iptables.Chain{{
		Name:  ChainFIPSnat,
		Rules: rules,
	}}
}
