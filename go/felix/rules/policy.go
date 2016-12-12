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
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/hashutils"
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
	"strings"
)

// ruleRenderer defined in rules_defs.go.

func (r *ruleRenderer) PolicyToIptablesChains(policyID *proto.PolicyID, policy *proto.Policy, ipVersion uint8) []*iptables.Chain {
	inbound := iptables.Chain{
		Name:  PolicyChainName(PolicyInboundPfx, policyID),
		Rules: r.ProtoRulesToIptablesRules(policy.InboundRules, ipVersion),
	}
	outbound := iptables.Chain{
		Name:  PolicyChainName(PolicyOutboundPfx, policyID),
		Rules: r.ProtoRulesToIptablesRules(policy.OutboundRules, ipVersion),
	}
	return []*iptables.Chain{&inbound, &outbound}
}

func (r *ruleRenderer) ProfileToIptablesChains(profileID *proto.ProfileID, profile *proto.Profile, ipVersion uint8) []*iptables.Chain {
	inbound := iptables.Chain{
		Name:  ProfileChainName(PolicyInboundPfx, profileID),
		Rules: r.ProtoRulesToIptablesRules(profile.InboundRules, ipVersion),
	}
	outbound := iptables.Chain{
		Name:  ProfileChainName(PolicyOutboundPfx, profileID),
		Rules: r.ProtoRulesToIptablesRules(profile.OutboundRules, ipVersion),
	}
	return []*iptables.Chain{&inbound, &outbound}
}

func (r *ruleRenderer) ProtoRulesToIptablesRules(protoRules []*proto.Rule, ipVersion uint8) []iptables.Rule {
	var rules []iptables.Rule
	for _, protoRule := range protoRules {
		rules = append(rules, r.ProtoRuleToIptablesRules(protoRule, ipVersion)...)
	}
	return rules
}

func (r *ruleRenderer) ProtoRuleToIptablesRules(pRule *proto.Rule, ipVersion uint8) []iptables.Rule {
	// TODO(smc) handle > 15 ports in a rule (iptables limitation)
	match := iptables.Match()

	logCxt := log.WithFields(log.Fields{
		"ipVersion": ipVersion,
		"rule":      pRule,
	})

	if pRule.IpVersion != 0 && pRule.IpVersion != proto.IPVersion(ipVersion) {
		logCxt.Debug("Skipping rule because it is for a different IP version.")
		return nil
	}

	// First, process positive (non-negated) match criteria.

	if pRule.Protocol != nil {
		switch p := pRule.Protocol.NumberOrName.(type) {
		case *proto.Protocol_Name:
			logCxt.WithField("protoName", p.Name).Debug("Adding protocol match")
			match = match.Protocol(p.Name)
		case *proto.Protocol_Number:
			logCxt.WithField("protoNum", p.Number).Debug("Adding protocol match")
			match = match.ProtocolNum(uint8(p.Number))
		}
	}

	if pRule.SrcNet != "" {
		isV6 := strings.Index(pRule.SrcNet, ":") >= 0
		wantV6 := ipVersion == 6
		if wantV6 != isV6 {
			// We're rendering for one IP version but the rule has an CIDR for the other
			// IP version, skip the rule.
			logCxt.Debug("Skipping rule because it has a CIDR for a different IP version.")
			return nil
		}
		// Only include the address if it matches the IP version that we're
		// rendering.
		logCxt.WithField("cidr", pRule.SrcNet).Debug("Adding src CIDR match")
		match = match.SourceNet(pRule.SrcNet)
	}

	for _, ipsetID := range pRule.SrcIpSetIds {
		ipsetName := ""
		if ipVersion == 4 {
			ipsetName = r.IPSetConfigV4.NameForMainIPSet(ipsetID)
		} else {
			ipsetName = r.IPSetConfigV6.NameForMainIPSet(ipsetID)
		}
		logCxt.WithFields(log.Fields{
			"ipsetID":   ipsetID,
			"ipSetName": ipsetName,
		}).Debug("Adding src IP set match")
		match = match.SourceIPSet(ipsetName)
	}

	if len(pRule.SrcPorts) > 0 {
		logCxt.WithFields(log.Fields{
			"ports": pRule.SrcPorts,
		}).Debug("Adding src port match")
		match = match.SourcePortRanges(pRule.SrcPorts)
	}

	if pRule.DstNet != "" {
		isV6 := strings.Index(pRule.DstNet, ":") >= 0
		wantV6 := ipVersion == 6
		if wantV6 != isV6 {
			// We're rendering for one IP version but the rule has an CIDR for the other
			// IP version, skip the rule.
			logCxt.Debug("Skipping rule because it has a CIDR for a different IP version.")
			return nil
		}
		// Only include the address if it matches the IP version that we're
		// rendering.
		logCxt.WithField("cidr", pRule.DstNet).Debug("Adding dst CIDR match")
		match = match.DestNet(pRule.DstNet)
	}

	for _, ipsetID := range pRule.DstIpSetIds {
		ipsetName := ""
		if ipVersion == 4 {
			ipsetName = r.IPSetConfigV4.NameForMainIPSet(ipsetID)
		} else {
			ipsetName = r.IPSetConfigV6.NameForMainIPSet(ipsetID)
		}
		match = match.DestIPSet(ipsetName)
		logCxt.WithFields(log.Fields{
			"ipsetID":   ipsetID,
			"ipSetName": ipsetName,
		}).Debug("Adding dst IP set match")
	}

	if len(pRule.DstPorts) > 0 {
		logCxt.WithFields(log.Fields{
			"ports": pRule.SrcPorts,
		}).Debug("Adding dst port match")
		match = match.DestPortRanges(pRule.DstPorts)
	}

	if ipVersion == 4 {
		switch icmp := pRule.Icmp.(type) {
		case *proto.Rule_IcmpTypeCode:
			logCxt.WithField("icmpTypeCode", icmp).Debug("Adding ICMP type/code match.")
			match = match.ICMPTypeAndCode(
				uint8(icmp.IcmpTypeCode.Type), uint8(icmp.IcmpTypeCode.Code))
		case *proto.Rule_IcmpType:
			logCxt.WithField("icmpType", icmp).Debug("Adding ICMP type-only match.")
			match = match.ICMPType(uint8(icmp.IcmpType))
		}
	} else {
		switch icmp := pRule.Icmp.(type) {
		case *proto.Rule_IcmpTypeCode:
			logCxt.WithField("icmpTypeCode", icmp).Debug("Adding ICMPv6 type/code match.")
			match = match.ICMPV6TypeAndCode(
				uint8(icmp.IcmpTypeCode.Type), uint8(icmp.IcmpTypeCode.Code))
		case *proto.Rule_IcmpType:
			logCxt.WithField("icmpTypeCode", icmp).Debug("Adding ICMPv6 type-only match.")
			match = match.ICMPV6Type(uint8(icmp.IcmpType))
		}
	}

	// Now, the negated versions.

	if pRule.NotProtocol != nil {
		switch p := pRule.NotProtocol.NumberOrName.(type) {
		case *proto.Protocol_Name:
			logCxt.WithField("protoName", p.Name).Debug("Adding protocol match")
			match = match.NotProtocol(p.Name)
		case *proto.Protocol_Number:
			logCxt.WithField("protoNum", p.Number).Debug("Adding protocol match")
			match = match.NotProtocolNum(uint8(p.Number))
		}
	}

	if pRule.NotSrcNet != "" {
		isV6 := strings.Index(pRule.NotSrcNet, ":") >= 0
		wantV6 := ipVersion == 6
		if wantV6 != isV6 {
			// We're rendering for one IP version but the rule has an CIDR for the other
			// IP version, skip the rule.
			logCxt.Debug("Skipping rule because it has a CIDR for a different IP version.")
			return nil
		}
		// Only include the address if it matches the IP version that we're
		// rendering.
		logCxt.WithField("cidr", pRule.NotSrcNet).Debug("Adding src CIDR match")
		match = match.NotSourceNet(pRule.NotSrcNet)
	}

	for _, ipsetID := range pRule.NotSrcIpSetIds {
		ipsetName := ""
		if ipVersion == 4 {
			ipsetName = r.IPSetConfigV4.NameForMainIPSet(ipsetID)
		} else {
			ipsetName = r.IPSetConfigV6.NameForMainIPSet(ipsetID)
		}
		logCxt.WithFields(log.Fields{
			"ipsetID":   ipsetID,
			"ipSetName": ipsetName,
		}).Debug("Adding src IP set match")
		match = match.NotSourceIPSet(ipsetName)
	}

	if len(pRule.NotSrcPorts) > 0 {
		logCxt.WithFields(log.Fields{
			"ports": pRule.NotSrcPorts,
		}).Debug("Adding src port match")
		// TODO(smc) handle > 15 ports
		match = match.NotSourcePortRanges(pRule.NotSrcPorts)
	}

	if pRule.NotDstNet != "" {
		isV6 := strings.Index(pRule.NotDstNet, ":") >= 0
		wantV6 := ipVersion == 6
		if wantV6 != isV6 {
			// We're rendering for one IP version but the rule has an CIDR for the other
			// IP version, skip the rule.
			logCxt.Debug("Skipping rule because it has a CIDR for a different IP version.")
			return nil
		}
		// Only include the address if it matches the IP version that we're
		// rendering.
		logCxt.WithField("cidr", pRule.NotDstNet).Debug("Adding dst CIDR match")
		match = match.NotDestNet(pRule.NotDstNet)
	}

	for _, ipsetID := range pRule.NotDstIpSetIds {
		ipsetName := ""
		if ipVersion == 4 {
			ipsetName = r.IPSetConfigV4.NameForMainIPSet(ipsetID)
		} else {
			ipsetName = r.IPSetConfigV6.NameForMainIPSet(ipsetID)
		}
		match = match.NotDestIPSet(ipsetName)
		logCxt.WithFields(log.Fields{
			"ipsetID":   ipsetID,
			"ipSetName": ipsetName,
		}).Debug("Adding dst IP set match")
	}

	if len(pRule.NotDstPorts) > 0 {
		logCxt.WithFields(log.Fields{
			"ports": pRule.NotSrcPorts,
		}).Debug("Adding dst port match")
		match = match.NotDestPortRanges(pRule.NotDstPorts)
	}

	if ipVersion == 4 {
		switch icmp := pRule.NotIcmp.(type) {
		case *proto.Rule_NotIcmpTypeCode:
			logCxt.WithField("icmpTypeCode", icmp).Debug("Adding ICMP type/code match.")
			match = match.NotICMPTypeAndCode(
				uint8(icmp.NotIcmpTypeCode.Type), uint8(icmp.NotIcmpTypeCode.Code))
		case *proto.Rule_NotIcmpType:
			logCxt.WithField("icmpType", icmp).Debug("Adding ICMP type-only match.")
			match = match.NotICMPType(uint8(icmp.NotIcmpType))
		}
	} else {
		switch icmp := pRule.NotIcmp.(type) {
		case *proto.Rule_NotIcmpTypeCode:
			logCxt.WithField("icmpTypeCode", icmp).Debug("Adding ICMPv6 type/code match.")
			match = match.NotICMPV6TypeAndCode(
				uint8(icmp.NotIcmpTypeCode.Type), uint8(icmp.NotIcmpTypeCode.Code))
		case *proto.Rule_NotIcmpType:
			logCxt.WithField("icmpTypeCode", icmp).Debug("Adding ICMPv6 type-only match.")
			match = match.NotICMPV6Type(uint8(icmp.NotIcmpType))
		}
	}

	// TODO(smc) Implement log action.
	// TODO(smc) Implement log prefix.
	switch pRule.Action {
	case "", "allow":
		return []iptables.Rule{
			{
				Match:  match,
				Action: iptables.SetMarkAction{r.IptablesMarkAccept},
			},
			{
				Match:  iptables.Match().MarkSet(r.IptablesMarkAccept),
				Action: iptables.ReturnAction{},
			},
		}
	case "next-tier":
		return []iptables.Rule{
			{
				Match:  match,
				Action: iptables.SetMarkAction{r.IptablesMarkNextTier},
			},
			{
				Match:  iptables.Match().MarkSet(r.IptablesMarkNextTier),
				Action: iptables.ReturnAction{},
			},
		}
	case "deny":
		return []iptables.Rule{
			{
				Match:  match,
				Action: iptables.DropAction{},
			},
		}
	}
	log.WithField("action", pRule.Action).Panic("Unknown rule action")
	return nil
}

func PolicyChainName(prefix string, polID *proto.PolicyID) string {
	return hashutils.GetLengthLimitedID(
		prefix,
		polID.Tier+"/"+polID.Name,
		iptables.MaxChainNameLength,
	)
}

func ProfileChainName(prefix string, profID *proto.ProfileID) string {
	return hashutils.GetLengthLimitedID(
		prefix,
		profID.Name,
		iptables.MaxChainNameLength,
	)
}
