// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	"sort"
	"strings"

	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/iptables"
)

func (r *DefaultRuleRenderer) MakeNatOutgoingRule(protocol string, action iptables.Action, ipVersion uint8) iptables.Rule {
	if r.Config.BPFEnabled {
		return r.makeNATOutgoingRuleBPF(ipVersion, protocol, action)
	} else {
		return r.makeNATOutgoingRuleIPTables(ipVersion, protocol, action)
	}
}

func (r *DefaultRuleRenderer) makeNATOutgoingRuleBPF(version uint8, protocol string, action iptables.Action) iptables.Rule {
	match := iptables.Match().MarkMatchesWithMask(tcdefs.MarkSeenNATOutgoing, tcdefs.MarkSeenNATOutgoingMask)

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

func (r *DefaultRuleRenderer) makeNATOutgoingRuleIPTables(ipVersion uint8, protocol string, action iptables.Action) iptables.Rule {
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
		var defaultSnatRule iptables.Action = iptables.MasqAction{}
		if r.Config.NATOutgoingAddress != nil {
			defaultSnatRule = iptables.SNATAction{ToAddr: r.Config.NATOutgoingAddress.String()}
		}

		if r.Config.NATPortRange.MaxPort > 0 {
			toPorts := fmt.Sprintf("%d-%d", r.Config.NATPortRange.MinPort, r.Config.NATPortRange.MaxPort)
			var portRangeSnatRule iptables.Action = iptables.MasqAction{ToPorts: toPorts}
			if r.Config.NATOutgoingAddress != nil {
				toAddress := fmt.Sprintf("%s:%s", r.Config.NATOutgoingAddress.String(), toPorts)
				portRangeSnatRule = iptables.SNATAction{ToAddr: toAddress}
			}
			rules = []iptables.Rule{
				r.MakeNatOutgoingRule("tcp", portRangeSnatRule, ipVersion),
				r.MakeNatOutgoingRule("tcp", iptables.ReturnAction{}, ipVersion),
				r.MakeNatOutgoingRule("udp", portRangeSnatRule, ipVersion),
				r.MakeNatOutgoingRule("udp", iptables.ReturnAction{}, ipVersion),
				r.MakeNatOutgoingRule("", defaultSnatRule, ipVersion),
			}
		} else {
			rules = []iptables.Rule{
				r.MakeNatOutgoingRule("", defaultSnatRule, ipVersion),
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

func (r *DefaultRuleRenderer) BlockedCIDRsToIptablesChains(cidrs []string, ipVersion uint8) []*iptables.Chain {
	rules := []iptables.Rule{}
	if r.blockCIDRAction != nil {
		// Sort CIDRs so we can program rules in a determined order.
		sort.Strings(cidrs)
		for _, cidr := range cidrs {
			if strings.Contains(cidr, ":") == (ipVersion == 6) {
				rules = append(rules, iptables.Rule{
					Match:  iptables.Match().DestNet(cidr),
					Action: r.blockCIDRAction,
				})
			}
		}
	}
	return []*iptables.Chain{{
		Name:  ChainCIDRBlock,
		Rules: rules,
	}}
}
