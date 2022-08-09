// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.
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
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/hashutils"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
)

// ruleRenderer defined in rules_defs.go.

func (r *DefaultRuleRenderer) PolicyToIptablesChains(policyID *proto.PolicyID, policy *proto.Policy, ipVersion uint8) []*iptables.Chain {
	inbound := iptables.Chain{
		Name:  PolicyChainName(PolicyInboundPfx, policyID),
		Rules: r.ProtoRulesToIptablesRules(policy.InboundRules, ipVersion, fmt.Sprintf("Policy %s ingress", policyID.Name)),
	}
	outbound := iptables.Chain{
		Name:  PolicyChainName(PolicyOutboundPfx, policyID),
		Rules: r.ProtoRulesToIptablesRules(policy.OutboundRules, ipVersion, fmt.Sprintf("Policy %s egress", policyID.Name)),
	}
	return []*iptables.Chain{&inbound, &outbound}
}

func (r *DefaultRuleRenderer) ProfileToIptablesChains(profileID *proto.ProfileID, profile *proto.Profile, ipVersion uint8) (inbound, outbound *iptables.Chain) {
	inbound = &iptables.Chain{
		Name:  ProfileChainName(ProfileInboundPfx, profileID),
		Rules: r.ProtoRulesToIptablesRules(profile.InboundRules, ipVersion, fmt.Sprintf("Profile %s ingress", profileID.Name)),
	}
	outbound = &iptables.Chain{
		Name:  ProfileChainName(ProfileOutboundPfx, profileID),
		Rules: r.ProtoRulesToIptablesRules(profile.OutboundRules, ipVersion, fmt.Sprintf("Profile %s egress", profileID.Name)),
	}
	return
}

func (r *DefaultRuleRenderer) ProtoRulesToIptablesRules(protoRules []*proto.Rule, ipVersion uint8, chainComments ...string) []iptables.Rule {
	var rules []iptables.Rule
	for _, protoRule := range protoRules {
		rules = append(rules, r.ProtoRuleToIptablesRules(protoRule, ipVersion)...)
	}
	if len(chainComments) > 0 {
		if len(rules) == 0 {
			rules = append(rules, iptables.Rule{})
		}
		rules[0].Comment = append(rules[0].Comment, chainComments...)
	}
	return rules
}
func filterNets(mixedCIDRs []string, ipVersion uint8) (filtered []string, filteredAll bool) {
	if len(mixedCIDRs) == 0 {
		return nil, false
	}
	wantV6 := ipVersion == 6
	filteredAll = true
	for _, net := range mixedCIDRs {
		isV6 := strings.Contains(net, ":")
		if isV6 != wantV6 {
			continue
		}
		filtered = append(filtered, net)
		filteredAll = false
	}
	return
}

// FilterRuleToIPVersion: If the rule applies to the given IP version, returns a copy of the rule
// excluding the CIDRs that are not of the given IP version. If the rule does not apply to the
// given IP version at all, returns nil.
func FilterRuleToIPVersion(ipVersion uint8, pRule *proto.Rule) *proto.Rule {
	// Filter the CIDRs to the IP version that we're rendering.  In general, we should have an
	// explicit IP version in the rule and all CIDRs should match it (and calicoctl, for
	// example, enforces that).  However, we try to handle a rule gracefully if it's missing a
	// version.
	//
	// We do that by rendering the rule, filtered to only have CIDRs of the right version,
	// unless filtering the rule would completely remove one of its match fields.
	//
	// That handles the mainline case well, where the IP version is missing but the rule is
	// otherwise consistent since we'll render the rule only for the matching version.
	//
	// It also handles rules like "allow from 10.0.0.1,feed::beef" in an intuitive way.  Only
	// rules of the form "allow from 10.0.0.1,feed::beef to 10.0.0.2" will get filtered out,
	// and only for IPv6, where there's no obvious meaning to the rule.

	ruleCopy := *pRule
	var filteredAll bool

	logCxt := log.WithFields(log.Fields{
		"ipVersion": ipVersion,
		"rule":      pRule,
	})

	if pRule.IpVersion != 0 && pRule.IpVersion != proto.IPVersion(ipVersion) {
		logCxt.Debug("Skipping rule because it is for a different IP version.")
		return nil
	}

	ruleCopy.SrcNet, filteredAll = filterNets(pRule.SrcNet, ipVersion)
	if filteredAll {
		return nil
	}
	ruleCopy.NotSrcNet, filteredAll = filterNets(pRule.NotSrcNet, ipVersion)
	if filteredAll {
		return nil
	}
	ruleCopy.DstNet, filteredAll = filterNets(pRule.DstNet, ipVersion)
	if filteredAll {
		return nil
	}
	ruleCopy.NotDstNet, filteredAll = filterNets(pRule.NotDstNet, ipVersion)
	if filteredAll {
		return nil
	}
	return &ruleCopy
}

func (r *DefaultRuleRenderer) ProtoRuleToIptablesRules(pRule *proto.Rule, ipVersion uint8) []iptables.Rule {

	ruleCopy := FilterRuleToIPVersion(ipVersion, pRule)
	if ruleCopy == nil {
		return nil
	}
	// There are a few areas where our data model doesn't fit with iptables, requiring us to
	// render multiple iptables rules for one of our rules:
	//
	//     - iptables has a 15-port limit on the number of ports that can be in a single "multiport"
	//       match.  Although we can have more than one multiport match in a single rule, they would
	//       be and-ed together, when our datamodel calls for them to be or-ed instead.
	//
	//     - iptables only supports a single source and a single destination CIDR match in a given
	//       rule, irrespective of negation (i.e. you can't have src==<CIDR1> && src!=<CIDR2>.
	//       Our datamodel allows for a list of positive and a list of negative CIDR matches.
	//
	//     - our datamodel includes named ports, which we render as (IP, port) IP sets, these are
	//       or-ed with the numeric ports; the "or" operation can't be done in a single rule.
	//
	// To work around these limitations, where needed, we break the rule into blocks,
	// each of which implements a part of the match as follows:
	//
	//     rule to initialise mark bits
	//     positive matches on source ports
	//     positive matches on dest ports
	//     positive matches on source address
	//     positive matches on dest address
	//     negated matches on source address
	//     negated matches on dest address
	//     rule containing rest of match criteria
	//
	// We use one match bit to record whether all the blocks accept the packet and one as a
	// scratch bit for each block to use.  As an invariant, at the end of each block, the
	// "all blocks pass" bit should only be set if all previous blocks match the packet.
	//
	// We do some optimisations to keep the number of rules down:
	//
	//    - if there is only one positive CIDR match, we don't render a block and we add the match
	//      to the final rule
	//
	//    - if the first block implements a positive match then we have it write directly to the
	//      "AllBlocks" bit instead of using the scratch bit and copying; this is why all the
	//      positive blocks are rendered first.
	//
	//    - negative match blocks don't use the scratch bit, they simply clear the "AllBlocks" bit
	//      immediately if any of their rules match.
	//
	// The matchBlockBuilder wraps up the above logic:
	matchBlockBuilder := matchBlockBuilder{
		markAllBlocksPass: r.IptablesMarkScratch0,
		markThisBlockPass: r.IptablesMarkScratch1,
	}

	// Port matches.  We only need to render blocks of ports if, in total, there's more than one
	// source or more than one destination match that needs to be or-ed together.
	//
	// Split the port list into blocks of 15, as per iptables limit and add in the number of
	// named ports.
	var ipSetConfig *ipsets.IPVersionConfig
	if ipVersion == 4 {
		ipSetConfig = r.IPSetConfigV4
	} else {
		ipSetConfig = r.IPSetConfigV6
	}
	srcPortSplits := SplitPortList(ruleCopy.SrcPorts)
	if len(srcPortSplits)+len(ruleCopy.SrcNamedPortIpSetIds) > 1 {
		// Render a block for the source ports.
		matchBlockBuilder.AppendPortMatchBlock(ipSetConfig, ruleCopy.Protocol, srcPortSplits, ruleCopy.SrcNamedPortIpSetIds, src)
		// And remove them from the rule since they're already handled.
		ruleCopy.SrcPorts = nil
		ruleCopy.SrcNamedPortIpSetIds = nil
	}
	dstPortSplits := SplitPortList(ruleCopy.DstPorts)
	if len(dstPortSplits)+len(ruleCopy.DstNamedPortIpSetIds) > 1 {
		// Render a block for the destination ports.
		matchBlockBuilder.AppendPortMatchBlock(ipSetConfig, ruleCopy.Protocol, dstPortSplits, ruleCopy.DstNamedPortIpSetIds, dst)
		// And remove them from the rule since they're already handled.
		ruleCopy.DstPorts = nil
		ruleCopy.DstNamedPortIpSetIds = nil
	}

	// If there's more than one positive source/destination CIDR match, we have to render a block.
	// Otherwise, if there's exactly one, we'll include it in the main rule below.
	if len(ruleCopy.SrcNet) > 1 {
		matchBlockBuilder.AppendCIDRMatchBlock(ruleCopy.SrcNet, src)
		// Since we're using a block for this, nil out the match.
		ruleCopy.SrcNet = nil
	}
	if len(ruleCopy.DstNet) > 1 {
		matchBlockBuilder.AppendCIDRMatchBlock(ruleCopy.DstNet, dst)
		// Since we're using a block for this, nil out the match.
		ruleCopy.DstNet = nil
	}
	// Now, work out if we need to render a block for the src/dst negative CIDR matches.  We need
	// to do that if:
	//
	//    - there are negative matches to render, and
	//    - either the positive match is taking up the single slot in the "main" rule, or,
	//      there's more than one negated match.
	//
	// Figure that out by counting all the rules.  If there's a positive match left in the rule then
	// any negative matches will tip the count over 1.  Otherwise, we'll need 2 or more negative
	// matches to make the count more than 1.
	totalSrcMatches := len(ruleCopy.SrcNet) + len(ruleCopy.NotSrcNet)
	if totalSrcMatches > 1 {
		// We have some negated source CIDR matches and the total number of source
		// CIDR matches won't fit in the rule.  Render a block of rules to do the
		// negated match.
		matchBlockBuilder.AppendNegatedCIDRMatchBlock(ruleCopy.NotSrcNet, src)
		// Since we're using a block for this, nil out the match.
		ruleCopy.NotSrcNet = nil
	}
	totalDstMatches := len(ruleCopy.DstNet) + len(ruleCopy.NotDstNet)
	if totalDstMatches > 1 {
		// We have some negated dest CIDR matches and the total number of dest
		// CIDR matches won't fit in the rule.  Render a block of rules to do the
		// negated match.
		matchBlockBuilder.AppendNegatedCIDRMatchBlock(ruleCopy.NotDstNet, dst)
		// Since we're using a block for this, nil out the match.
		ruleCopy.NotDstNet = nil
	}

	// Render the rest of the rule.
	match := r.CalculateRuleMatch(ruleCopy, ipVersion)

	if matchBlockBuilder.UsingMatchBlocks {
		// The CIDR or port matches in the rule overflowed and we rendered them
		// as additional rules, which set the markAllBlocksPass bit on
		// success.  Add a match on that bit to the calculated rule.
		match = match.MarkSingleBitSet(matchBlockBuilder.markAllBlocksPass)
	}
	markBit, actions := r.CalculateActions(ruleCopy, ipVersion)
	rs := matchBlockBuilder.Rules
	if markBit != 0 {
		// The rule needs to do more than one action. Render a rule that
		// executes the match criteria and sets the given mark bit if it
		// matches, then render the actions as separate rules below.
		rs = append(rs, iptables.Rule{
			Match:  match,
			Action: iptables.SetMarkAction{Mark: markBit},
		})
		match = iptables.Match().MarkSingleBitSet(markBit)
	}
	for _, action := range actions {
		rs = append(rs, iptables.Rule{
			Match:  match,
			Action: action,
		})
	}

	// Render rule annotations as comments on each rule.
	for i := range rs {
		for k, v := range pRule.GetMetadata().GetAnnotations() {
			rs[i].Comment = append(rs[i].Comment, fmt.Sprintf("%s=%s", k, v))
		}
	}

	return rs
}

type matchBlockBuilder struct {
	UsingMatchBlocks            bool
	doneFirstPositiveMatchBlock bool

	markAllBlocksPass uint32
	markThisBlockPass uint32

	Rules []iptables.Rule
}

func (r *matchBlockBuilder) AppendPortMatchBlock(
	ipSetConfig *ipsets.IPVersionConfig,
	protocol *proto.Protocol,
	numericPortSplits [][]*proto.PortRange,
	namedPortIPSetIDs []string,
	srcOrDst srcOrDst,
) {
	// Write out the initial "reset" rule if this is the first block.
	r.maybeAppendInitialRule(0)
	// Figure out which bit to set.  See comment in positiveBlockMarkToSet() for details.
	markToSet := r.positiveBlockMarkToSet()

	logCxt := log.WithFields(log.Fields{
		"protocol":     protocol,
		"portSplits":   numericPortSplits,
		"namedPortIDs": namedPortIPSetIDs,
		"srcOrDst":     srcOrDst,
	})
	for _, split := range numericPortSplits {
		m := appendProtocolMatch(iptables.Match(), protocol, logCxt)
		m = srcOrDst.AppendMatchPorts(m, split)
		r.Rules = append(r.Rules, iptables.Rule{
			Match:  m,
			Action: iptables.SetMarkAction{Mark: markToSet},
		})
	}

	for _, namedPortIPSetID := range namedPortIPSetIDs {
		ipsetName := ipSetConfig.NameForMainIPSet(namedPortIPSetID)
		r.Rules = append(r.Rules, iptables.Rule{
			Match:  srcOrDst.MatchIPPortIPSet(ipsetName),
			Action: iptables.SetMarkAction{Mark: markToSet},
		})
	}

	// Append the end-of-block rules.
	r.finishPositiveBlock()
}

func (r *matchBlockBuilder) AppendCIDRMatchBlock(cidrs []string, srcOrDst srcOrDst) {
	// Write out the initial "reset" rule if this is the first block.
	r.maybeAppendInitialRule(0)
	// Figure out which bit to set.  See comment in positiveBlockMarkToSet() for details.
	markToSet := r.positiveBlockMarkToSet()

	// Render the per-CIDR rules.
	for _, cidr := range cidrs {
		r.Rules = append(r.Rules, iptables.Rule{
			Match:  srcOrDst.MatchNet(cidr),
			Action: iptables.SetMarkAction{Mark: markToSet},
		})
	}

	// Append the end-of-block rules.
	r.finishPositiveBlock()
}

func (r *matchBlockBuilder) AppendNegatedCIDRMatchBlock(cidrs []string, srcOrDst srcOrDst) {
	// Write out the initial "reset" rule if this is the first block.  Since this is a negated
	// rule, we want the AllBlocks bit to be set by default .
	r.maybeAppendInitialRule(r.markAllBlocksPass)
	// To implement a negated match we emit a rule per CIDR that does a positive
	// match on the CIDR and *clears* the AllBlocksPass bit if the packet matches.
	// This gives the desired "not any" behaviour.
	for _, cidr := range cidrs {
		r.Rules = append(r.Rules,
			iptables.Rule{
				Match:  srcOrDst.MatchNet(cidr),
				Action: iptables.ClearMarkAction{Mark: r.markAllBlocksPass},
			},
		)
	}
}

func (r *matchBlockBuilder) maybeAppendInitialRule(markBitsToSetInitially uint32) {
	if r.UsingMatchBlocks {
		return
	}
	r.Rules = append(r.Rules,
		iptables.Rule{
			Action: iptables.SetMaskedMarkAction{
				Mark: markBitsToSetInitially,
				Mask: r.markAllBlocksPass | r.markThisBlockPass,
			},
		},
	)
	r.UsingMatchBlocks = true
}

func (r *matchBlockBuilder) positiveBlockMarkToSet() uint32 {
	// Implementing a positive match requires us to implement a logical
	// "or" operation within the block and then "and" that with the result from
	// the previous block.
	//
	// As an optimization, if rendering the first block, we simply set the
	// "AllBlocks" bit if one of our rules matches.
	//
	// If we're not the first block, that doesn't work since the "AllBlocks"
	// bit may already be set.  In that case, we write to a scratch "ThisBlock"
	// bit, calculate the "and" at the end of the block and write that back
	// to the "AllBlocks" bit.
	if !r.doneFirstPositiveMatchBlock {
		// Optimization: since we're the first block, directly use the
		// "AllBlocks" bit to store our result.
		return r.markAllBlocksPass
	}

	// This isn't the first block, we need to use a scratch bit to
	// store the result.
	return r.markThisBlockPass
}

func (r *matchBlockBuilder) finishPositiveBlock() {
	if !r.doneFirstPositiveMatchBlock {
		// First positive block, we don't need to write any rules to calculate the AllBlocks bit
		// because we optimized that out by setting the Allblocks bit directly from the matching
		// rule.
		r.doneFirstPositiveMatchBlock = true
		return
	}
	// This isn't the first block, write a rule to do:
	//
	//     <AllBlocks bit> &&= <ThisBlock bit>
	//
	r.Rules = append(r.Rules, iptables.Rule{
		Match:  iptables.Match().MarkClear(r.markThisBlockPass),
		Action: iptables.ClearMarkAction{Mark: r.markAllBlocksPass},
	})
}

// srcOrDst is an enum for selecting source or destination rule rendering.
type srcOrDst int

const (
	src srcOrDst = iota
	dst
)

// MatchNet returns a new SourceNet or DestNet MatchCriteria for the given CIDR.
func (sod srcOrDst) MatchNet(cidr string) iptables.MatchCriteria {
	switch sod {
	case src:
		return iptables.Match().SourceNet(cidr)
	case dst:
		return iptables.Match().DestNet(cidr)
	}
	log.WithField("srcOrDst", sod).Panic("Unknown source or dest type.")
	return nil
}

func (sod srcOrDst) AppendMatchPorts(m iptables.MatchCriteria, pr []*proto.PortRange) iptables.MatchCriteria {
	switch sod {
	case src:
		return m.SourcePortRanges(pr)
	case dst:
		return m.DestPortRanges(pr)
	}
	log.WithField("srcOrDst", sod).Panic("Unknown source or dest type.")
	return nil
}

func (sod srcOrDst) MatchIPPortIPSet(setID string) iptables.MatchCriteria {
	switch sod {
	case src:
		return iptables.Match().SourceIPPortSet(setID)
	case dst:
		return iptables.Match().DestIPPortSet(setID)
	}
	log.WithField("srcOrDst", sod).Panic("Unknown source or dest type.")
	return nil
}

// SplitPortList splits the input list of ports into groups containing up to 15 port numbers.
// If the input list is empty, it returns an empty slice.
//
// The requirement to split into groups of 15, comes from iptables' limit on the number of ports
// "slots" in a multiport match.  A single port takes up one slot, a range of ports requires 2.
func SplitPortList(ports []*proto.PortRange) (splits [][]*proto.PortRange) {
	slotsAvailableInCurrentSplit := 15
	var split []*proto.PortRange
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
			splits = append(splits, split)
			slotsAvailableInCurrentSplit = 15
			split = nil
		}
		split = append(split, portRange)
		slotsAvailableInCurrentSplit -= numSlotsRequired
	}
	if split != nil {
		splits = append(splits, split)
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
		// Deny maps to DROP/REJECT.
		actions = append(actions, r.DropActionOverride)
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

func appendProtocolMatch(match iptables.MatchCriteria, protocol *proto.Protocol, logCxt *log.Entry) iptables.MatchCriteria {
	if protocol == nil {
		return match
	}
	switch p := protocol.NumberOrName.(type) {
	case *proto.Protocol_Name:
		logCxt.WithField("protoName", p.Name).Debug("Adding protocol match")
		match = match.Protocol(p.Name)
	case *proto.Protocol_Number:
		logCxt.WithField("protoNum", p.Number).Debug("Adding protocol match")
		match = match.ProtocolNum(uint8(p.Number))
	default:
		logCxt.WithField("protocol", protocol).Panic("Unknown protocol type")
	}
	return match
}

func (r *DefaultRuleRenderer) CalculateRuleMatch(pRule *proto.Rule, ipVersion uint8) iptables.MatchCriteria {
	match := iptables.Match()

	logCxt := log.WithFields(log.Fields{
		"ipVersion": ipVersion,
		"rule":      pRule,
	})

	// First, process positive (non-negated) match criteria.
	match = appendProtocolMatch(match, pRule.Protocol, logCxt)

	if len(pRule.SrcNet) == 1 {
		logCxt.WithField("cidr", pRule.SrcNet[0]).Debug("Adding src CIDR match")
		match = match.SourceNet(pRule.SrcNet[0])
	} else if len(pRule.SrcNet) > 1 {
		log.WithField("rule", pRule).Panic(
			"CalculateRuleMatch() passed more than one CIDR in SrcNet.")
	}

	nameForIPSet := func(ipsetID string) string {
		if ipVersion == 4 {
			return r.IPSetConfigV4.NameForMainIPSet(ipsetID)
		} else {
			return r.IPSetConfigV6.NameForMainIPSet(ipsetID)
		}
	}

	for _, ipsetID := range pRule.SrcIpSetIds {
		ipsetName := nameForIPSet(ipsetID)
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

	if len(pRule.SrcNamedPortIpSetIds) > 1 {
		log.WithField("rule", pRule).Panic(
			"Bug: More than one source IP set ID left in rule.")
	}
	for _, np := range pRule.SrcNamedPortIpSetIds {
		ipsetName := nameForIPSet(np)
		logCxt.WithFields(log.Fields{
			"namedPort": np,
			"ipsetName": ipsetName,
		}).Debug("Adding source named port match")
		match = match.SourceIPPortSet(ipsetName)
	}

	if len(pRule.DstNet) == 1 {
		logCxt.WithField("cidr", pRule.DstNet[0]).Debug("Adding dest CIDR match")
		match = match.DestNet(pRule.DstNet[0])
	} else if len(pRule.DstNet) > 1 {
		log.WithField("rule", pRule).Panic(
			"CalculateRuleMatch() passed more than one CIDR in DstNet.")
	}

	for _, ipsetID := range pRule.DstIpSetIds {
		ipsetName := nameForIPSet(ipsetID)
		match = match.DestIPSet(ipsetName)
		logCxt.WithFields(log.Fields{
			"ipsetID":   ipsetID,
			"ipSetName": ipsetName,
		}).Debug("Adding dst IP set match")
	}

	for _, ipsetID := range pRule.DstIpPortSetIds {
		ipsetName := nameForIPSet(ipsetID)
		match = match.DestIPPortSet(ipsetName)
		logCxt.WithFields(log.Fields{
			"ipsetID":   ipsetID,
			"ipSetName": ipsetName,
		}).Debug("Adding dst IP+port set match")
	}

	if len(pRule.DstPorts) > 0 {
		logCxt.WithFields(log.Fields{
			"ports": pRule.SrcPorts,
		}).Debug("Adding dst port match")
		match = match.DestPortRanges(pRule.DstPorts)
	}

	if len(pRule.DstNamedPortIpSetIds) > 1 {
		log.WithField("rule", pRule).Panic(
			"Bug: More than one source IP set ID left in rule.")
	}
	for _, np := range pRule.DstNamedPortIpSetIds {
		ipsetName := nameForIPSet(np)
		logCxt.WithFields(log.Fields{
			"namedPort": np,
			"ipsetName": ipsetName,
		}).Debug("Adding dest named port match")
		match = match.DestIPPortSet(ipsetName)
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

	if len(pRule.NotSrcNet) == 1 {
		logCxt.WithField("cidr", pRule.NotSrcNet[0]).Debug("Adding !src CIDR match")
		match = match.NotSourceNet(pRule.NotSrcNet[0])
	} else if len(pRule.NotSrcNet) > 1 {
		log.WithField("rule", pRule).Panic("CalculateRuleMatch() passed more than one CIDR in NotSrcNet.")
	}

	for _, ipsetID := range pRule.NotSrcIpSetIds {
		ipsetName := nameForIPSet(ipsetID)
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

	for _, np := range pRule.NotSrcNamedPortIpSetIds {
		ipsetName := nameForIPSet(np)
		logCxt.WithFields(log.Fields{
			"namedPort": np,
			"ipsetName": ipsetName,
		}).Debug("Adding negated source named port match")
		match = match.NotSourceIPPortSet(ipsetName)
	}

	if len(pRule.NotDstNet) == 1 {
		logCxt.WithField("cidr", pRule.NotDstNet[0]).Debug("Adding !dst CIDR match")
		match = match.NotDestNet(pRule.NotDstNet[0])
	} else if len(pRule.NotDstNet) > 1 {
		log.WithField("rule", pRule).Panic("CalculateRuleMatch() passed more than one CIDR in NotDstNet.")
	}

	for _, ipsetID := range pRule.NotDstIpSetIds {
		ipsetName := nameForIPSet(ipsetID)
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

	for _, np := range pRule.NotDstNamedPortIpSetIds {
		ipsetName := nameForIPSet(np)
		logCxt.WithFields(log.Fields{
			"namedPort": np,
			"ipsetName": ipsetName,
		}).Debug("Adding negated dest named port match")
		match = match.NotDestIPPortSet(ipsetName)
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
	return match
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
