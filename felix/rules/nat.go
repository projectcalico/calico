// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	. "github.com/projectcalico/calico/felix/generictables"
)

func (r *DefaultRuleRenderer) MakeNatOutgoingRule(protocol string, action Action, ipVersion uint8) Rule {
	if r.Config.BPFEnabled {
		return r.makeNATOutgoingRuleBPF(ipVersion, protocol, action)
	} else {
		return r.makeNATOutgoingRuleIPTables(ipVersion, protocol, action)
	}
}

func (r *DefaultRuleRenderer) makeNATOutgoingRuleBPF(version uint8, protocol string, action Action) Rule {
	match := r.NewMatch().MarkMatchesWithMask(tcdefs.MarkSeenNATOutgoing, tcdefs.MarkSeenNATOutgoingMask)

	if protocol != "" {
		match = match.Protocol(protocol)
	}

	if r.Config.IptablesNATOutgoingInterfaceFilter != "" {
		match = match.OutInterface(r.Config.IptablesNATOutgoingInterfaceFilter)
	}

	rule := Rule{
		Action: action,
		Match:  match,
	}
	return rule
}

func (r *DefaultRuleRenderer) makeNATOutgoingRuleIPTables(ipVersion uint8, protocol string, action Action) Rule {
	ipConf := r.ipSetConfig(ipVersion)
	allIPsSetName := ipConf.NameForMainIPSet(IPSetIDAllPools)
	masqIPsSetName := ipConf.NameForMainIPSet(IPSetIDNATOutgoingMasqPools)

	match := r.NewMatch().
		SourceIPSet(masqIPsSetName).
		NotDestIPSet(allIPsSetName)

	check := apiv3.NATOutgoingExclusionsType(r.Config.NATOutgoingExclusions)
	if check == apiv3.NATOutgoingExclusionsIPPoolsAndHostIPs {
		allHostsIPsSetName := ipConf.NameForMainIPSet(IPSetIDAllHostNets)
		match = match.NotDestIPSet(allHostsIPsSetName)
	}

	if protocol != "" {
		match = match.Protocol(protocol)
	}

	if r.Config.IptablesNATOutgoingInterfaceFilter != "" {
		match = match.OutInterface(r.Config.IptablesNATOutgoingInterfaceFilter)
	}

	rule := Rule{
		Action: action,
		Match:  match,
	}
	return rule
}

func (r *DefaultRuleRenderer) NATOutgoingChain(natOutgoingActive bool, ipVersion uint8) *Chain {
	var rules []Rule
	if natOutgoingActive {
		var defaultSnatRule Action = r.Masq("")
		if r.Config.NATOutgoingAddress != nil {
			defaultSnatRule = r.SNAT(r.Config.NATOutgoingAddress.String())
		}

		if r.Config.NATPortRange.MaxPort > 0 {
			toPorts := fmt.Sprintf("%d-%d", r.Config.NATPortRange.MinPort, r.Config.NATPortRange.MaxPort)
			var portRangeSnatRule Action = r.Masq(toPorts)
			if r.Config.NATOutgoingAddress != nil {
				toAddress := fmt.Sprintf("%s:%s", r.Config.NATOutgoingAddress.String(), toPorts)
				portRangeSnatRule = r.SNAT(toAddress)
			}
			rules = []Rule{
				r.MakeNatOutgoingRule("tcp", portRangeSnatRule, ipVersion),
				r.MakeNatOutgoingRule("tcp", r.Return(), ipVersion),
				r.MakeNatOutgoingRule("udp", portRangeSnatRule, ipVersion),
				r.MakeNatOutgoingRule("udp", r.Return(), ipVersion),
				r.MakeNatOutgoingRule("", defaultSnatRule, ipVersion),
			}
		} else {
			rules = []Rule{
				r.MakeNatOutgoingRule("", defaultSnatRule, ipVersion),
			}
		}
	}
	return &Chain{
		Name:  ChainNATOutgoing,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) DNATsToIptablesChains(dnats map[string]string) []*Chain {
	// Extract and sort map keys so we can program rules in a determined order.
	sortedExtIps := make([]string, 0, len(dnats))
	for extIp := range dnats {
		sortedExtIps = append(sortedExtIps, extIp)
	}
	sort.Strings(sortedExtIps)

	rules := []Rule{}
	for _, extIp := range sortedExtIps {
		intIp := dnats[extIp]
		rules = append(rules, Rule{
			Match:  r.NewMatch().DestNet(extIp),
			Action: r.DNAT(intIp, 0),
		})
	}
	return []*Chain{{
		Name:  ChainFIPDnat,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) SNATsToIptablesChains(snats map[string]string) []*Chain {
	// Extract and sort map keys so we can program rules in a determined order.
	sortedIntIps := make([]string, 0, len(snats))
	for intIp := range snats {
		sortedIntIps = append(sortedIntIps, intIp)
	}
	sort.Strings(sortedIntIps)

	rules := []Rule{}
	for _, intIp := range sortedIntIps {
		extIp := snats[intIp]
		rules = append(rules, Rule{
			Match:  r.NewMatch().DestNet(intIp).SourceNet(intIp),
			Action: r.SNAT(extIp),
		})
	}
	return []*Chain{{
		Name:  ChainFIPSnat,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) BlockedCIDRsToIptablesChains(cidrs []string, ipVersion uint8) []*Chain {
	rules := []Rule{}
	if r.blockCIDRAction != nil {
		// Sort CIDRs so we can program rules in a determined order.
		sort.Strings(cidrs)
		for _, cidr := range cidrs {
			if strings.Contains(cidr, ":") == (ipVersion == 6) {
				rules = append(rules, Rule{
					Match:  r.NewMatch().DestNet(cidr),
					Action: r.blockCIDRAction,
				})
			}
		}
	}
	return []*Chain{{
		Name:  ChainCIDRBlock,
		Rules: rules,
	}}
}
