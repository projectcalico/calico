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
	"sort"

	"github.com/projectcalico/felix/iptables"
)

func (r *DefaultRuleRenderer) MakeNatOutgoingRule(protocol string, action iptables.Action, ipVersion uint8) iptables.Rule {
	ipConf := r.ipSetConfig(ipVersion)
	allIPsSetName := ipConf.NameForMainIPSet(IPSetIDNATOutgoingAllPools)
	masqIPsSetName := ipConf.NameForMainIPSet(IPSetIDNATOutgoingMasqPools)

	match := iptables.Match().
		SourceIPSet(masqIPsSetName).
		NotDestIPSet(allIPsSetName)

	if protocol != "" {
		match = match.Protocol(protocol)
	}

	if r.Config.IptablesNATOutgoingInterfaceFilter != "" {
		match = match.OutInterface(r.Config.IptablesNATOutgoingInterfaceFilter)
	}

	rule := iptables.Rule{
		Action: action,
		Match:  match,
	}
	return rule
}

func (r *DefaultRuleRenderer) NATOutgoingChain(natOutgoingActive bool, ipVersion uint8) *iptables.Chain {
	var rules []iptables.Rule
	if natOutgoingActive {
		if r.Config.NATPortRange.MaxPort > 0 {
			toPorts := fmt.Sprintf("%d-%d", r.Config.NATPortRange.MinPort, r.Config.NATPortRange.MaxPort)
			rules = []iptables.Rule{
				r.MakeNatOutgoingRule("tcp", iptables.MasqAction{ToPorts: toPorts}, ipVersion),
				r.MakeNatOutgoingRule("tcp", iptables.ReturnAction{}, ipVersion),
				r.MakeNatOutgoingRule("udp", iptables.MasqAction{ToPorts: toPorts}, ipVersion),
				r.MakeNatOutgoingRule("udp", iptables.ReturnAction{}, ipVersion),
				r.MakeNatOutgoingRule("", iptables.MasqAction{}, ipVersion),
			}
		} else {
			rules = []iptables.Rule{
				r.MakeNatOutgoingRule("", iptables.MasqAction{}, ipVersion),
			}
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
