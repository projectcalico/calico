// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
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
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/hash"
)

// ruleRenderer defined in rules_defs.go.

func (r *DefaultRuleRenderer) PolicyToIptablesChains(policyID *types.PolicyID, policy *proto.Policy, ipVersion uint8) []*generictables.Chain {
	if model.KindIsStaged(policyID.Kind) {
		logrus.Debugf("Skip programming staged policy %v", policyID.Name)
		return nil
	}

	// Build an appropriate comment for the policy.
	var commentIngress, commentEgress string
	if policyID.Namespace == "" {
		commentIngress = fmt.Sprintf("%s %s ingress", policyID.Kind, policyID.Name)
		commentEgress = fmt.Sprintf("%s %s egress", policyID.Kind, policyID.Name)
	} else {
		commentIngress = fmt.Sprintf("%s %s/%s ingress", policyID.Kind, policyID.Namespace, policyID.Name)
		commentEgress = fmt.Sprintf("%s %s/%s egress", policyID.Kind, policyID.Namespace, policyID.Name)
	}

	inbound := generictables.Chain{
		Name: PolicyChainName(PolicyInboundPfx, policyID, r.nft),
		Rules: r.ProtoRulesToIptablesRules(
			policy.InboundRules,
			ipVersion, RuleOwnerTypePolicy,
			RuleDirIngress,
			policyID,
			policy.Tier,
			policy.Untracked,
			commentIngress,
		),
	}
	outbound := generictables.Chain{
		Name: PolicyChainName(PolicyOutboundPfx, policyID, r.nft),
		// Note that the policy name also includes the tier, so it does not need to be separately specified.
		Rules: r.ProtoRulesToIptablesRules(
			policy.OutboundRules,
			ipVersion, RuleOwnerTypePolicy,
			RuleDirEgress,
			policyID,
			policy.Tier,
			policy.Untracked,
			commentEgress,
		),
	}
	return []*generictables.Chain{&inbound, &outbound}
}

func (r *DefaultRuleRenderer) ProfileToIptablesChains(profileID *types.ProfileID, profile *proto.Profile, ipVersion uint8) (inbound, outbound *generictables.Chain) {
	// Profiles are not related to any tier.
	tier := ""
	inbound = &generictables.Chain{
		Name: ProfileChainName(ProfileInboundPfx, profileID, r.nft),
		Rules: r.ProtoRulesToIptablesRules(
			profile.InboundRules,
			ipVersion,
			RuleOwnerTypeProfile,
			RuleDirIngress,
			profileID,
			tier,
			false,
			fmt.Sprintf("Profile %s ingress", profileID.Name),
		),
	}
	outbound = &generictables.Chain{
		Name: ProfileChainName(ProfileOutboundPfx, profileID, r.nft),
		Rules: r.ProtoRulesToIptablesRules(
			profile.OutboundRules,
			ipVersion, RuleOwnerTypeProfile,
			RuleDirEgress,
			profileID,
			tier,
			false,
			fmt.Sprintf("Profile %s egress", profileID.Name),
		),
	}
	return
}

func (r *DefaultRuleRenderer) ProtoRulesToIptablesRules(
	protoRules []*proto.Rule,
	ipVersion uint8,
	owner RuleOwnerType,
	dir RuleDir,
	id types.IDMaker,
	tier string,
	untracked bool,
	chainComments ...string,
) []generictables.Rule {
	var rules []generictables.Rule
	for ii, protoRule := range protoRules {
		// TODO (Matt): Need rule hash when that's cleaned up.
		rules = append(rules, r.ProtoRuleToIptablesRules(protoRule, ipVersion, owner, dir, ii, id, tier, untracked)...)
	}

	// Strip off any return rules at the end of the chain.  No matter their
	// match criteria, they're effectively no-ops.
	for len(rules) > 0 {
		if _, ok := rules[len(rules)-1].Action.(generictables.ReturnActionMarker); ok {
			rules = rules[:len(rules)-1]
		} else {
			break
		}
	}
	if len(chainComments) > 0 {
		if len(rules) == 0 {
			rules = append(rules, generictables.Rule{})
		}
		rules[0].Comment = append(rules[0].Comment, chainComments...)
	}
	return rules
}

func filterNets(mixedCIDRs []string, ipVersion uint8, isNegated bool) (filtered []string, filteredAll bool) {
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

		// Check for catch-all CIDR in negated context, which creates logical contradictions
		if isNegated && isCatchAllCIDR(net, ipVersion) {
			logrus.WithFields(logrus.Fields{
				"cidr":      net,
				"ipVersion": ipVersion,
				"negated":   isNegated,
			}).Warn("Ignoring rule with negated catch-all CIDR to prevent iptables logical contradiction")
			// Return filteredAll=true to indicate the entire rule should be dropped
			return nil, true
		}

		filtered = append(filtered, net)
		filteredAll = false
	}
	return
}

// isCatchAllCIDR returns true if the CIDR represents "all addresses" for the given IP version.
// This is used to detect problematic negated matches that would create logical contradictions.
func isCatchAllCIDR(cidr string, ipVersion uint8) bool {
	return (ipVersion == 4 && cidr == "0.0.0.0/0") || (ipVersion == 6 && cidr == "::/0")
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

	ruleCopy := googleproto.Clone(pRule).(*proto.Rule)
	var filteredAll bool

	logCxt := logrus.WithFields(logrus.Fields{
		"ipVersion": ipVersion,
		"rule":      pRule,
	})

	if pRule.IpVersion != 0 && pRule.IpVersion != proto.IPVersion(ipVersion) {
		logCxt.Debug("Skipping rule because it is for a different IP version.")
		return nil
	}

	ruleCopy.SrcNet, filteredAll = filterNets(pRule.SrcNet, ipVersion, false)
	if filteredAll {
		return nil
	}
	ruleCopy.NotSrcNet, filteredAll = filterNets(pRule.NotSrcNet, ipVersion, true)
	if filteredAll {
		return nil
	}
	ruleCopy.DstNet, filteredAll = filterNets(pRule.DstNet, ipVersion, false)
	if filteredAll {
		return nil
	}
	ruleCopy.NotDstNet, filteredAll = filterNets(pRule.NotDstNet, ipVersion, true)
	if filteredAll {
		return nil
	}
	return ruleCopy
}

func (r *DefaultRuleRenderer) ProtoRuleToIptablesRules(
	pRule *proto.Rule,
	ipVersion uint8,
	owner RuleOwnerType,
	dir RuleDir,
	idx int,
	id types.IDMaker,
	tier string,
	untracked bool,
) []generictables.Rule {
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
		actions:           r.ActionFactory,
		newMatch:          r.NewMatch,
		markAllBlocksPass: r.MarkScratch0,
		markThisBlockPass: r.MarkScratch1,
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

	rs := matchBlockBuilder.Rules
	rules := r.CombineMatchAndActionsForProtoRule(ruleCopy, match, owner, dir, idx, id, tier, untracked)
	rs = append(rs, rules...)
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

	newMatch func() generictables.MatchCriteria
	actions  generictables.ActionFactory

	Rules []generictables.Rule
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

	logCxt := logrus.WithFields(logrus.Fields{
		"protocol":     protocol,
		"portSplits":   numericPortSplits,
		"namedPortIDs": namedPortIPSetIDs,
		"srcOrDst":     srcOrDst,
	})
	for _, split := range numericPortSplits {
		m := appendProtocolMatch(r.newMatch(), protocol, logCxt)
		m = srcOrDst.AppendMatchPorts(m, split)
		r.Rules = append(r.Rules, generictables.Rule{
			Match:  m,
			Action: r.actions.SetMark(markToSet),
		})
	}

	for _, namedPortIPSetID := range namedPortIPSetIDs {
		ipsetName := ipSetConfig.NameForMainIPSet(namedPortIPSetID)
		r.Rules = append(r.Rules, generictables.Rule{
			Match:  srcOrDst.MatchIPPortIPSet(r.newMatch(), ipsetName),
			Action: r.actions.SetMark(markToSet),
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
		r.Rules = append(r.Rules, generictables.Rule{
			Match:  srcOrDst.MatchNet(r.newMatch(), cidr),
			Action: r.actions.SetMark(markToSet),
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
			generictables.Rule{
				Match:  srcOrDst.MatchNet(r.newMatch(), cidr),
				Action: r.actions.ClearMark(r.markAllBlocksPass),
			},
		)
	}
}

func (r *matchBlockBuilder) maybeAppendInitialRule(markBitsToSetInitially uint32) {
	if r.UsingMatchBlocks {
		return
	}
	r.Rules = append(r.Rules,
		generictables.Rule{
			Action: r.actions.SetMaskedMark(
				markBitsToSetInitially,
				r.markAllBlocksPass|r.markThisBlockPass,
			),
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
	r.Rules = append(r.Rules, generictables.Rule{
		Match:  r.newMatch().MarkClear(r.markThisBlockPass),
		Action: r.actions.ClearMark(r.markAllBlocksPass),
	})
}

// srcOrDst is an enum for selecting source or destination rule rendering.
type srcOrDst int

const (
	src srcOrDst = iota
	dst
)

// MatchNet returns a new SourceNet or DestNet generictables.MatchCriteria for the given CIDR.
func (sod srcOrDst) MatchNet(m generictables.MatchCriteria, cidr string) generictables.MatchCriteria {
	switch sod {
	case src:
		return m.SourceNet(cidr)
	case dst:
		return m.DestNet(cidr)
	}
	logrus.WithField("srcOrDst", sod).Panic("Unknown source or dest type.")
	return nil
}

func (sod srcOrDst) AppendMatchPorts(m generictables.MatchCriteria, pr []*proto.PortRange) generictables.MatchCriteria {
	switch sod {
	case src:
		return m.SourcePortRanges(pr)
	case dst:
		return m.DestPortRanges(pr)
	}
	logrus.WithField("srcOrDst", sod).Panic("Unknown source or dest type.")
	return nil
}

func (sod srcOrDst) MatchIPPortIPSet(m generictables.MatchCriteria, setID string) generictables.MatchCriteria {
	switch sod {
	case src:
		return m.SourceIPPortSet(setID)
	case dst:
		return m.DestIPPortSet(setID)
	}
	logrus.WithField("srcOrDst", sod).Panic("Unknown source or dest type.")
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

// CombineMatchAndActionsForProtoRule takes in the proto.Rule along with the match (and some other parameters) and
// returns as set of rules. The actions that are needed are calculated from the proto.Rule and the parameters, then
// the match given and actions calculated are combined into the returned set of rules.
func (r *DefaultRuleRenderer) CombineMatchAndActionsForProtoRule(
	pRule *proto.Rule,
	match generictables.MatchCriteria,
	owner RuleOwnerType,
	dir RuleDir,
	idx int,
	id types.IDMaker,
	tier string,
	untracked bool,
) []generictables.Rule {
	var rules []generictables.Rule
	var mark uint32

	if pRule.Action == "log" {
		// This rule should log (and possibly do something else too).
		logMatch := r.NewMatch()
		if len(r.LogActionRateLimit) != 0 {
			logMatch = logMatch.Limit(r.LogActionRateLimit, uint16(r.LogActionRateLimitBurst))
		}
		rules = append(rules, generictables.Rule{
			Match:  logMatch,
			Action: r.Log(r.generateLogPrefix(id, tier)),
		})
	}

	nflogGroup := NFLOGOutboundGroup
	if dir == RuleDirIngress {
		nflogGroup = NFLOGInboundGroup
	}

	switch pRule.Action {
	case "", "allow":
		// If this is not a staged policy then allow needs to set the accept mark.
		mark = r.MarkAccept

		// NFLOG the allow - we don't do this for untracked due to the performance hit.
		if !untracked && r.FlowLogsEnabled {
			rules = append(rules, generictables.Rule{
				Match: r.NewMatch(),
				Action: r.Nflog(
					nflogGroup,
					CalculateNFLOGPrefixStr(RuleActionAllow, owner, dir, idx, id),
					0,
				),
			})
		}

		// Return to calling chain for end of policy.
		rules = append(rules, generictables.Rule{Match: r.NewMatch(), Action: r.Return()})
	case "next-tier", "pass":
		// If this is not a staged policy then pass (called next-tier in the API for historical reasons) needs to set
		// the pass mark.
		mark = r.MarkPass

		// NFLOG the pass - we don't do this for untracked due to the performance hit.
		if !untracked && r.FlowLogsEnabled {
			rules = append(rules, generictables.Rule{
				Match: r.NewMatch(),
				Action: r.Nflog(
					nflogGroup,
					CalculateNFLOGPrefixStr(RuleActionPass, owner, dir, idx, id),
					0,
				),
			})
		}

		// Return to calling chain for end of policy.
		rules = append(rules, generictables.Rule{Match: r.NewMatch(), Action: r.Return()})
	case "deny":
		// If this is not a staged policy then deny maps to DROP.
		mark = r.MarkDrop

		// NFLOG the deny - we don't do this for untracked due to the performance hit.
		if !untracked && r.FlowLogsEnabled {
			rules = append(rules, generictables.Rule{
				Match: r.NewMatch(),
				Action: r.Nflog(
					nflogGroup,
					CalculateNFLOGPrefixStr(RuleActionDeny, owner, dir, idx, id),
					0,
				),
			})
		}

		// We defer to DropActions() to allow for "sandbox" mode.
		rules = append(rules, generictables.Rule{
			Match:  r.NewMatch(),
			Action: r.IptablesFilterDenyAction(),
		})
	case "log":
		// Handled above.
	default:
		logrus.WithField("action", pRule.Action).Panic("Unknown rule action")
	}

	finalRules := []generictables.Rule{}
	// if the mark is not set then this is either a staged policy or the rule action is "log".
	if mark != 0 {
		// The rule needs to do more than one action. Render a rule that
		// executes the match criteria and sets the given mark bit if it
		// matches, then render the actions as separate rules below.
		finalRules = append(finalRules, generictables.Rule{
			Match:  match,
			Action: r.SetMark(mark),
		})
		match = r.NewMatch().MarkSingleBitSet(mark)
	}

	for _, rule := range rules {
		rule.Match = r.CombineMatches(rule.Match, match)
		finalRules = append(finalRules, rule)
	}

	return finalRules
}

var logPrefixRE = regexp.MustCompile("%[tknp]")

// generateLogPrefix returns a log prefix string with known specifiers replaced by their corresponding values.
// If no known specifiers are present, the log prefix is returned as-is.
// Supported specifiers in the log prefix format string:
//
//	%t - Tier name
//	%k - Kind (short names like gnp for GlobalNetworkPolicies)
//	%n - Policy or profile name.
//	%p - Policy or profile name including namespace:
//	     - namespace/name for namespaced kinds.
//	     - name for non namespaced kinds.
func (r *DefaultRuleRenderer) generateLogPrefix(id types.IDMaker, tier string) string {
	logPrefix := "calico-packet"
	if len(r.LogPrefix) != 0 {
		logPrefix = r.LogPrefix
	}

	if !strings.Contains(logPrefix, "%") {
		return logPrefix
	}

	var kind, name, namespace string
	switch v := id.(type) {
	case *types.PolicyID:
		kind = v.KindShortName()
		name = v.Name
		namespace = v.Namespace
	case *types.ProfileID:
		kind = "pro"
		name = v.Name
	default:
		kind = "unknown"
		name = "unknown"
	}

	return logPrefixRE.ReplaceAllStringFunc(logPrefix, func(specifier string) string {
		switch specifier {
		case "%k":
			return kind
		case "%p":
			if len(namespace) != 0 {
				return fmt.Sprintf("%s/%s", namespace, name)
			}
			return name
		case "%n":
			return name
		case "%t":
			return tier
		default:
			return specifier
		}
	})
}

func appendProtocolMatch(match generictables.MatchCriteria, protocol *proto.Protocol, logCxt *logrus.Entry) generictables.MatchCriteria {
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

func (r *DefaultRuleRenderer) CalculateRuleMatch(pRule *proto.Rule, ipVersion uint8) generictables.MatchCriteria {
	match := r.NewMatch()

	logCxt := logrus.WithFields(logrus.Fields{
		"ipVersion": ipVersion,
		"rule":      pRule,
	})

	// First, process positive (non-negated) match criteria.
	match = appendProtocolMatch(match, pRule.Protocol, logCxt)

	if len(pRule.SrcNet) == 1 {
		logCxt.WithField("cidr", pRule.SrcNet[0]).Debug("Adding src CIDR match")
		match = match.SourceNet(pRule.SrcNet[0])
	} else if len(pRule.SrcNet) > 1 {
		logrus.WithField("rule", pRule).Panic(
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
		logCxt.WithFields(logrus.Fields{
			"ipsetID":   ipsetID,
			"ipSetName": ipsetName,
		}).Debug("Adding src IP set match")
		match = match.SourceIPSet(ipsetName)
	}

	if len(pRule.SrcPorts) > 0 {
		logCxt.WithFields(logrus.Fields{
			"ports": pRule.SrcPorts,
		}).Debug("Adding src port match")
		match = match.SourcePortRanges(pRule.SrcPorts)
	}

	if len(pRule.SrcNamedPortIpSetIds) > 1 {
		logrus.WithField("rule", pRule).Panic(
			"Bug: More than one source IP set ID left in rule.")
	}
	for _, np := range pRule.SrcNamedPortIpSetIds {
		ipsetName := nameForIPSet(np)
		logCxt.WithFields(logrus.Fields{
			"namedPort": np,
			"ipsetName": ipsetName,
		}).Debug("Adding source named port match")
		match = match.SourceIPPortSet(ipsetName)
	}

	if len(pRule.DstNet) == 1 {
		logCxt.WithField("cidr", pRule.DstNet[0]).Debug("Adding dest CIDR match")
		match = match.DestNet(pRule.DstNet[0])
	} else if len(pRule.DstNet) > 1 {
		logrus.WithField("rule", pRule).Panic(
			"CalculateRuleMatch() passed more than one CIDR in DstNet.")
	}

	for _, ipsetID := range pRule.DstIpSetIds {
		ipsetName := nameForIPSet(ipsetID)
		match = match.DestIPSet(ipsetName)
		logCxt.WithFields(logrus.Fields{
			"ipsetID":   ipsetID,
			"ipSetName": ipsetName,
		}).Debug("Adding dst IP set match")
	}

	for _, ipsetID := range pRule.DstIpPortSetIds {
		ipsetName := nameForIPSet(ipsetID)
		match = match.DestIPPortSet(ipsetName)
		logCxt.WithFields(logrus.Fields{
			"ipsetID":   ipsetID,
			"ipSetName": ipsetName,
		}).Debug("Adding dst IP+port set match")
	}

	if len(pRule.DstPorts) > 0 {
		logCxt.WithFields(logrus.Fields{
			"ports": pRule.SrcPorts,
		}).Debug("Adding dst port match")
		match = match.DestPortRanges(pRule.DstPorts)
	}

	if len(pRule.DstNamedPortIpSetIds) > 1 {
		logrus.WithField("rule", pRule).Panic(
			"Bug: More than one source IP set ID left in rule.")
	}
	for _, np := range pRule.DstNamedPortIpSetIds {
		ipsetName := nameForIPSet(np)
		logCxt.WithFields(logrus.Fields{
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
		logrus.WithField("rule", pRule).Panic("CalculateRuleMatch() passed more than one CIDR in NotSrcNet.")
	}

	for _, ipsetID := range pRule.NotSrcIpSetIds {
		ipsetName := nameForIPSet(ipsetID)
		logCxt.WithFields(logrus.Fields{
			"ipsetID":   ipsetID,
			"ipSetName": ipsetName,
		}).Debug("Adding src IP set match")
		match = match.NotSourceIPSet(ipsetName)
	}

	if len(pRule.NotSrcPorts) > 0 {
		logCxt.WithFields(logrus.Fields{
			"ports": pRule.NotSrcPorts,
		}).Debug("Adding src port match")
		for _, portSplit := range SplitPortList(pRule.NotSrcPorts) {
			match = match.NotSourcePortRanges(portSplit)
		}
	}

	for _, np := range pRule.NotSrcNamedPortIpSetIds {
		ipsetName := nameForIPSet(np)
		logCxt.WithFields(logrus.Fields{
			"namedPort": np,
			"ipsetName": ipsetName,
		}).Debug("Adding negated source named port match")
		match = match.NotSourceIPPortSet(ipsetName)
	}

	if len(pRule.NotDstNet) == 1 {
		logCxt.WithField("cidr", pRule.NotDstNet[0]).Debug("Adding !dst CIDR match")
		match = match.NotDestNet(pRule.NotDstNet[0])
	} else if len(pRule.NotDstNet) > 1 {
		logrus.WithField("rule", pRule).Panic("CalculateRuleMatch() passed more than one CIDR in NotDstNet.")
	}

	for _, ipsetID := range pRule.NotDstIpSetIds {
		ipsetName := nameForIPSet(ipsetID)
		match = match.NotDestIPSet(ipsetName)
		logCxt.WithFields(logrus.Fields{
			"ipsetID":   ipsetID,
			"ipSetName": ipsetName,
		}).Debug("Adding dst IP set match")
	}

	if len(pRule.NotDstPorts) > 0 {
		logCxt.WithFields(logrus.Fields{
			"ports": pRule.NotSrcPorts,
		}).Debug("Adding dst port match")
		for _, portSplit := range SplitPortList(pRule.NotDstPorts) {
			match = match.NotDestPortRanges(portSplit)
		}
	}

	for _, np := range pRule.NotDstNamedPortIpSetIds {
		ipsetName := nameForIPSet(np)
		logCxt.WithFields(logrus.Fields{
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

func PolicyChainName(prefix PolicyChainNamePrefix, polID *types.PolicyID, nft bool) string {
	maxLen := iptables.MaxChainNameLength
	if nft {
		maxLen = nftables.MaxChainNameLength
	}
	return hash.GetLengthLimitedID(
		string(prefix),
		polID.ID(),
		maxLen,
	)
}

func ProfileChainName(prefix ProfileChainNamePrefix, profID *types.ProfileID, nft bool) string {
	maxLen := iptables.MaxChainNameLength
	if nft {
		maxLen = nftables.MaxChainNameLength
	}
	return hash.GetLengthLimitedID(
		string(prefix),
		profID.Name,
		maxLen,
	)
}
