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
	"errors"
	"strings"

	log "github.com/Sirupsen/logrus"

	"github.com/projectcalico/felix/hashutils"
	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
)

// ruleRenderer defined in rules_defs.go.

func (r *DefaultRuleRenderer) PolicyToIptablesChains(policyID *proto.PolicyID, policy *proto.Policy, ipVersion uint8) []*iptables.Chain {
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

func (r *DefaultRuleRenderer) ProfileToIptablesChains(profileID *proto.ProfileID, profile *proto.Profile, ipVersion uint8) []*iptables.Chain {
	inbound := iptables.Chain{
		Name:  ProfileChainName(ProfileInboundPfx, profileID),
		Rules: r.ProtoRulesToIptablesRules(profile.InboundRules, ipVersion),
	}
	outbound := iptables.Chain{
		Name:  ProfileChainName(ProfileOutboundPfx, profileID),
		Rules: r.ProtoRulesToIptablesRules(profile.OutboundRules, ipVersion),
	}
	return []*iptables.Chain{&inbound, &outbound}
}

func (r *DefaultRuleRenderer) ProtoRulesToIptablesRules(protoRules []*proto.Rule, ipVersion uint8) []iptables.Rule {
	var rules []iptables.Rule
	for _, protoRule := range protoRules {
		rules = append(rules, r.ProtoRuleToIptablesRules(protoRule, ipVersion)...)
	}
	return rules
}

func (r *DefaultRuleRenderer) ProtoRuleToIptablesRules(pRule *proto.Rule, ipVersion uint8) []iptables.Rule {
	rs := []iptables.Rule{}
	ruleCopy := *pRule

	// iptables only supports one source and one destination match in a rule (irrespective of
	// negation).  If we have more than one of either, we'll render blocks of rules for the
	// ones that won't fit.
	numSrcMatches := len(pRule.SrcNet) + len(pRule.NotSrcNet)
	numDstMatches := len(pRule.DstNet) + len(pRule.NotDstNet)
	var usingCIDRBlocks bool
	markAllBlocksPass := r.IptablesMarkScratch0
	markThisBlockPass := r.IptablesMarkScratch1
	if numSrcMatches > 1 || numDstMatches > 1 {
		// We need to render CIDR match blocks.
		var markBitsToSetInitially uint32
		if len(pRule.SrcNet) <= 1 && len(pRule.DstNet) <= 1 {
			// All of the positive CIDR matches fit in the final rule so we're only
			// using the blocks to render negative matches.  Pre-set the AllBlocks
			// bit; then the negative rules will unset it if they match.
			markBitsToSetInitially = markAllBlocksPass
		} else {
			// There are at least some positive matches.  Leave the AllBlocks bit
			// set to 0.  The first positive match block will set it directly if it
			// matches.
			markBitsToSetInitially = 0
		}
		rs = append(rs,
			iptables.Rule{
				Action: iptables.SetMaskedMarkAction{
					Mark: markBitsToSetInitially,
					Mask: markAllBlocksPass | markThisBlockPass,
				},
			},
		)
		usingCIDRBlocks = true
		doneFirstPositiveMatchBlock := false

		appendCIDRMatchBlock := func(cidrs []string, srcOrDst srcOrDst) {
			// Implementation a positive match requires us to implement a logical
			// "or" operation within the block and then and that with the result from
			// the previous block.
			//
			// As an optimization, if rendering the first block, we simply set the
			// "AllBlocks" bit if one of our rules matches.
			//
			// If we're not the first block, that doesn't work since the "AllBlocks"
			// bit may already be set.  In that case, we write to a scratch "ThisBlock"
			// bit, calculate the "and" at the end of the block and write that back
			// to the "AllBlocks" bit.
			var markToSet uint32
			if doneFirstPositiveMatchBlock {
				// This isn't the first block, we need to use a scratch bit to
				// store the result.
				markToSet = markThisBlockPass
			} else {
				// Optimization: since we're the first block, directly use the
				// "AllBlocks" bit to store our result.
				markToSet = markAllBlocksPass
			}

			// Render the per-CIDR rules.
			for _, cidr := range cidrs {
				rs = append(rs, iptables.Rule{
					Match:  srcOrDst.MatchNet(cidr),
					Action: iptables.SetMarkAction{Mark: markToSet},
				})
			}
			if doneFirstPositiveMatchBlock {
				// This isn't the first block, copy the scratch bit back to the
				// AllBlocks bit.
				rs = append(rs, iptables.Rule{
					Match:  iptables.Match().MarkClear(markThisBlockPass),
					Action: iptables.ClearMarkAction{Mark: markAllBlocksPass},
				})
			}
			doneFirstPositiveMatchBlock = true
		}

		appendNegatedCIDRMatchBlock := func(cidrs []string, srcOrDst srcOrDst) {
			// To implement a negated match we emit a rule per CIDR that does a positive
			// match on the CIDR and *clears* the AllMatches bit if the packet matches.
			// This gives the desired "not any" behaviour.
			for _, cidr := range cidrs {
				rule := iptables.Rule{
					Match:  srcOrDst.MatchNet(cidr),
					Action: iptables.ClearMarkAction{Mark: markAllBlocksPass},
				}
				rs = append(rs, rule)
			}
		}

		if len(pRule.SrcNet) > 1 {
			// More than one positive match on source IP, need to render a block.  We
			// prioritise the positive match over the negative match and avoid
			// rendering a block if it'd only contain one IP.
			appendCIDRMatchBlock(pRule.SrcNet, src)
			// Since we're using a block for this, nil out the match.
			ruleCopy.SrcNet = nil
		}

		if len(pRule.DstNet) > 1 {
			// More than one positive match on dest IP, need to render a block.  We
			// prioritise the positive match over the negative match and avoid
			// rendering a block if it'd only contain one IP.
			appendCIDRMatchBlock(pRule.DstNet, dst)
			// Since we're using a block for this, nil out the match.
			ruleCopy.DstNet = nil
		}

		if len(pRule.NotSrcNet) > 0 && numSrcMatches > 1 {
			// We have some negated source CIDR matches and the total number of source
			// CIDR matches won't fit in the rule.  Render a block of rules to do the
			// negated match.
			appendNegatedCIDRMatchBlock(pRule.NotSrcNet, src)
			// Since we're using a block for this, nil out the match.
			ruleCopy.NotSrcNet = nil
		}

		if len(pRule.NotDstNet) > 0 && numDstMatches > 1 {
			// We have some negated dest CIDR matches and the total number of dest
			// CIDR matches won't fit in the rule.  Render a block of rules to do the
			// negated match.
			appendNegatedCIDRMatchBlock(pRule.NotDstNet, dst)
			// Since we're using a block for this, nil out the match.
			ruleCopy.NotDstNet = nil
		}
	}

	// iptables has a 15-port limit on the number of ports that can be in a single multiport
	// match.  In case a user has supplied a longer port list, break up the source and dest port
	// lists into blocks of 15 and render the cross-product of the rules.  We only need to do
	// that for the non-negated matches, because match criteria in a single rule are ANDed
	// together.  For negated matches, we can just use more than one multiport in the same
	// rule.
	for _, srcPorts := range SplitPortList(pRule.SrcPorts) {
		for _, dstPorts := range SplitPortList(pRule.DstPorts) {
			ruleCopy.SrcPorts = srcPorts
			ruleCopy.DstPorts = dstPorts

			logCxt := log.WithFields(log.Fields{
				"ipVersion": ipVersion,
				"rule":      ruleCopy,
			})
			match, err := r.CalculateRuleMatch(&ruleCopy, ipVersion)
			if err == SkipRule {
				logCxt.Debug("Rule skipped.")
				return nil
			}
			if usingCIDRBlocks {
				// The CIDR matches in the rule overflowed and we rendered them
				// as additional rules, which set the markAllBlocksPass bit on
				// success.  Add a match on that bit to the calculated rule.
				match = match.MarkSet(markAllBlocksPass)
			}
			markBit, actions := r.CalculateActions(&ruleCopy, ipVersion)
			if markBit != 0 {
				// The rule needs to do more than one action. Render a rule that
				// executes the match criteria and sets the given mark bit if it
				// matches, then render the actions as separate rules below.
				rs = append(rs, iptables.Rule{
					Match:  match,
					Action: iptables.SetMarkAction{Mark: markBit},
				})
				match = iptables.Match().MarkSet(markBit)
			}
			for _, action := range actions {
				rs = append(rs, iptables.Rule{
					Match:  match,
					Action: action,
				})
			}
		}
	}
	return rs
}

// srcOrDst is an enum for selecting source or destination rule rendering.
type srcOrDst int

const (
	src srcOrDst = iota
	dst
)

// MatchNet returns a new SourceNet or DestNet MatchCriteria for the given CIDR.
func (sod srcOrDst) MatchNet(cidr string) iptables.MatchCriteria {
	if sod == src {
		return iptables.Match().SourceNet(cidr)
	}
	return iptables.Match().DestNet(cidr)
}

// SplitPortList splits the input list of ports into groups containing up to 15 port numbers.
// It always returns at least one (possibly empty) split.
//
// The requirement to split into groups of 15, comes from iptables' limit on the number of ports
// "slots" in a multiport match.  A single port takes up one slot, a range of ports requires 2.
func SplitPortList(ports []*proto.PortRange) (splits [][]*proto.PortRange) {
	slotsAvailableInCurrentSplit := 15
	currentSplit := 0
	splits = append(splits, []*proto.PortRange{})
	for _, portRange := range ports {
		// First figure out how many slots adding this PortRange would require.
		var numSlotsRequired int
		if portRange.First == portRange.Last {
			numSlotsRequired = 1
		} else {
			numSlotsRequired = 2
		}
		if slotsAvailableInCurrentSplit < numSlotsRequired {
			// Adding this port to the current split would take it over the 15 slot
			// limit, start a new split.
			slotsAvailableInCurrentSplit = 15
			splits = append(splits, []*proto.PortRange{})
			currentSplit += 1
		}
		splits[currentSplit] = append(splits[currentSplit], portRange)
		slotsAvailableInCurrentSplit -= numSlotsRequired
	}
	return
}

func (r *DefaultRuleRenderer) CalculateActions(pRule *proto.Rule, ipVersion uint8) (mark uint32, actions []iptables.Action) {
	actions = []iptables.Action{}

	switch pRule.Action {
	case "", "allow":
		// Allow needs to set the accept mark, and then return to the calling chain for
		// further processing.
		mark = r.IptablesMarkAccept
		actions = append(actions, iptables.ReturnAction{})
	case "next-tier", "pass":
		// pass (called next-tier in the API for historical reasons) needs to set the pass
		// mark, and then return to the calling chain for further processing.
		mark = r.IptablesMarkPass
		actions = append(actions, iptables.ReturnAction{})
	case "deny":
		// Deny maps to DROP.
		actions = append(actions, iptables.DropAction{})
	case "log":
		// This rule should log.
		actions = append(actions, iptables.LogAction{
			Prefix: r.IptablesLogPrefix,
		})
	default:
		log.WithField("action", pRule.Action).Panic("Unknown rule action")
	}
	return
}

var SkipRule = errors.New("Rule skipped")

func (r *DefaultRuleRenderer) CalculateRuleMatch(pRule *proto.Rule, ipVersion uint8) (iptables.MatchCriteria, error) {
	match := iptables.Match()

	logCxt := log.WithFields(log.Fields{
		"ipVersion": ipVersion,
		"rule":      pRule,
	})

	if pRule.IpVersion != 0 && pRule.IpVersion != proto.IPVersion(ipVersion) {
		logCxt.Debug("Skipping rule because it is for a different IP version.")
		return nil, SkipRule
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

	var containsV4, containsV6 bool
	scanIPVersions := func(nets []string) {
		for _, n := range nets {
			if strings.Contains(n, ":") {
				containsV6 = true
			} else {
				containsV4 = true
			}
		}
	}

	if len(pRule.SrcNet) > 0 {
		scanIPVersions(pRule.SrcNet)
		logCxt.WithField("cidr", pRule.SrcNet).Debug("Adding src CIDR match")
		match = match.SourceNet(pRule.SrcNet[0])
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

	if len(pRule.DstNet) > 0 {
		scanIPVersions(pRule.DstNet)
		logCxt.WithField("cidr", pRule.DstNet).Debug("Adding dst CIDR match")
		match = match.DestNet(pRule.DstNet[0])
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

	if len(pRule.NotSrcNet) > 0 {
		scanIPVersions(pRule.NotSrcNet)
		logCxt.WithField("cidr", pRule.NotSrcNet).Debug("Adding src CIDR match")
		match = match.NotSourceNet(pRule.NotSrcNet[0])
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
		for _, portSplit := range SplitPortList(pRule.NotSrcPorts) {
			match = match.NotSourcePortRanges(portSplit)
		}
	}

	if len(pRule.NotDstNet) > 0 {
		scanIPVersions(pRule.NotDstNet)
		logCxt.WithField("cidr", pRule.NotDstNet).Debug("Adding dst CIDR match")
		match = match.NotDestNet(pRule.NotDstNet[0])
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
		for _, portSplit := range SplitPortList(pRule.NotDstPorts) {
			match = match.NotDestPortRanges(portSplit)
		}
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

	if containsV4 && containsV6 {
		return nil, SkipRule
	}
	if ipVersion == 4 && containsV6 {
		return nil, SkipRule
	}
	if ipVersion == 6 && containsV4 {
		return nil, SkipRule
	}

	return match, nil
}

func PolicyChainName(prefix PolicyChainNamePrefix, polID *proto.PolicyID) string {
	return hashutils.GetLengthLimitedID(
		string(prefix),
		polID.Name,
		iptables.MaxChainNameLength,
	)
}

func ProfileChainName(prefix ProfileChainNamePrefix, profID *proto.ProfileID) string {
	return hashutils.GetLengthLimitedID(
		string(prefix),
		profID.Name,
		iptables.MaxChainNameLength,
	)
}
