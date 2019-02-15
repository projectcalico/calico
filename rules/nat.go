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
	"fmt"
	"sort"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/iptables"
)

func makeRule(r *DefaultRuleRenderer, protocol string, action string, ipVersion uint8, rule []iptables.Rule) []iptables.Rule {
	logrus.Debugf("\nprotocol  = %v action = %v\n", protocol, action)
	ipConf := r.ipSetConfig(ipVersion)
	allIPsSetName := ipConf.NameForMainIPSet(IPSetIDNATOutgoingAllPools)
	masqIPsSetName := ipConf.NameForMainIPSet(IPSetIDNATOutgoingMasqPools)
	match := iptables.Match()

	if protocol != "" {
		match = iptables.Match().
			SourceIPSet(masqIPsSetName).
			NotDestIPSet(allIPsSetName).
			Protocol(protocol)
	} else {
		match = iptables.Match().
			SourceIPSet(masqIPsSetName).
			NotDestIPSet(allIPsSetName)
	}

	if r.Config.IptablesNATOutgoingInterfaceFilter != "" {
		match = iptables.Match().
			OutInterface(r.Config.IptablesNATOutgoingInterfaceFilter)
	}

	logrus.Debugf("\nmatch = %v\n", match)

	if action == "masq" {
		toPorts := ""
		if r.Config.NATPortRange.MaxPort > 0 && protocol != "" {
			toPorts = fmt.Sprintf("%d-%d", r.Config.NATPortRange.MinPort, r.Config.NATPortRange.MaxPort)
		}
		rule = []iptables.Rule{
			{
				Action: iptables.MasqAction{ToPorts: toPorts},
				Match:  match,
			},
		}
		logrus.Debugf("\nrule for action masq = %v\n", rule)
	} else if action == "return" {
		rule = []iptables.Rule{
			{
				Action: iptables.ReturnAction{},
				Match:  match,
			},
		}
		logrus.Debugf("\nrule for action return = %v\n", rule)
	} else if action == "drop" {
		rule = []iptables.Rule{
			{
				Action: iptables.DropAction{},
				Match:  match,
			},
		}
		logrus.Debugf("\nrule for action drop = %v\n", rule)
	} else {
		rule = []iptables.Rule{
			{
				Action: iptables.MasqAction{},
				Match:  match,
			},
		}
		logrus.Debugf("\nrule for no action = %v\n", rule)
	}
	logrus.Debugf("\nrules in makeRule = %v\n", rule)
	return rule
}

func (r *DefaultRuleRenderer) NATOutgoingChain(natOutgoingActive bool, ipVersion uint8) *iptables.Chain {
	logrus.Debugf("\ninside NATOutgoingChain func\n natOutgoingActive = %v, ipVersion = %v\n", natOutgoingActive, ipVersion)
	var rules []iptables.Rule
	if natOutgoingActive {
		if r.Config.NATPortRange.MaxPort > 0 {
			rules = makeRule(r, "tcp", "masq", ipVersion, rules)
			rules = append(rules, makeRule(r, "tcp", "return", ipVersion, rules)...)
			rules = append(rules, makeRule(r, "udp", "masq", ipVersion, rules)...)
			rules = append(rules, makeRule(r, "udp", "return", ipVersion, rules)...)
			rules = append(rules, makeRule(r, "", "masq", ipVersion, rules)...)
		} else {
			rules = append(rules, makeRule(r, "", "masq", ipVersion, rules)...)
		}
	}
	logrus.Debugf("\nrules in NATOutgoingChain = %v\n", rules)
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
