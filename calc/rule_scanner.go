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
package calc

import (
	log "github.com/Sirupsen/logrus"

	"fmt"

	"github.com/projectcalico/felix/multidict"
	"github.com/projectcalico/felix/set"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/selector"
)

// RuleScanner scans the rules sent to it by the ActiveRulesCalculator, looking for tags and
// selectors. It calculates the set of active tags and selectors and emits events when they become
// active/inactive.
//
// Previously, Felix tracked tags and selectors separately, with a separate tag and label index.
// However, we found that had a high occupancy cost.  The current code uses a shared index and
// maps tags onto labels, so a tag named tagName, becomes a label tagName="".  The RuleScanner
// maps tags to label selectors of the form "has(tagName)", taking advantage of the mapping.
// Such a selector is almost equivalent to having the tag; the only case where the behaviour would
// differ is if the user was using the same name for a tag and a label and the label and tags
// of the same name were applied to different endpoints.  Since tags are being deprecated, we can
// live with that potential aliasing issue in return for a significant occupancy improvement at
// high scale.
//
// The RuleScanner also emits events when rules are updated:  since the input rule
// structs contain tags and selectors but downstream, we only care about IP sets, the
// RuleScanner converts rules from model.Rule objects to calc.ParsedRule objects.
// The latter share most fields, but the tags and selector fields are replaced by lists of
// IP sets.
//
// The RuleScanner only calculates which selectors and tags are active/inactive.  It doesn't
// match endpoints against tags/selectors.  (That is done downstream in a labelindex.InheritIndex
// created in NewCalculationGraph.)
type RuleScanner struct {
	// selectorsByUID maps from the selector's hash back to the selector.
	selectorsByUID map[string]selector.Selector
	// activeUidsByResource maps from policy or profile ID to "set" of selector UIDs
	rulesIDToUIDs multidict.IfaceToString
	// activeResourcesByUid maps from selector UID back to the "set" of resources using it.
	uidsToRulesIDs multidict.StringToIface

	OnSelectorActive   func(selector selector.Selector)
	OnSelectorInactive func(selector selector.Selector)

	RulesUpdateCallbacks rulesUpdateCallbacks
}

func NewRuleScanner() *RuleScanner {
	calc := &RuleScanner{
		selectorsByUID: make(map[string]selector.Selector),
		rulesIDToUIDs:  multidict.NewIfaceToString(),
		uidsToRulesIDs: multidict.NewStringToIface(),
	}
	return calc
}

func (rs *RuleScanner) OnProfileActive(key model.ProfileRulesKey, profile *model.ProfileRules) {
	parsedRules := rs.updateRules(key, profile.InboundRules, profile.OutboundRules, false)
	rs.RulesUpdateCallbacks.OnProfileActive(key, parsedRules)
}

func (rs *RuleScanner) OnProfileInactive(key model.ProfileRulesKey) {
	rs.updateRules(key, nil, nil, false)
	rs.RulesUpdateCallbacks.OnProfileInactive(key)
}

func (rs *RuleScanner) OnPolicyActive(key model.PolicyKey, policy *model.Policy) {
	parsedRules := rs.updateRules(key, policy.InboundRules, policy.OutboundRules, policy.DoNotTrack)
	rs.RulesUpdateCallbacks.OnPolicyActive(key, parsedRules)
}

func (rs *RuleScanner) OnPolicyInactive(key model.PolicyKey) {
	rs.updateRules(key, nil, nil, false)
	rs.RulesUpdateCallbacks.OnPolicyInactive(key)
}

func (rs *RuleScanner) updateRules(key interface{}, inbound, outbound []model.Rule, untracked bool) (parsedRules *ParsedRules) {
	log.Debugf("Scanning rules (%v in, %v out) for key %v",
		len(inbound), len(outbound), key)
	// Extract all the new selectors/tags.
	currentUIDToSel := make(map[string]selector.Selector)
	parsedInbound := make([]*ParsedRule, len(inbound))
	for ii, rule := range inbound {
		parsed, allSels := ruleToParsedRule(&rule)
		parsedInbound[ii] = parsed
		for _, sel := range allSels {
			currentUIDToSel[sel.UniqueID()] = sel
		}
	}
	parsedOutbound := make([]*ParsedRule, len(outbound))
	for ii, rule := range outbound {
		parsed, allSels := ruleToParsedRule(&rule)
		parsedOutbound[ii] = parsed
		for _, sel := range allSels {
			currentUIDToSel[sel.UniqueID()] = sel
		}
	}
	parsedRules = &ParsedRules{
		InboundRules:  parsedInbound,
		OutboundRules: parsedOutbound,
		Untracked:     untracked,
	}

	// Figure out which selectors/tags are new.
	addedUids := set.New()
	for uid := range currentUIDToSel {
		log.Debugf("Checking if UID %v is new.", uid)
		if !rs.rulesIDToUIDs.Contains(key, uid) {
			log.Debugf("UID %v is new", uid)
			addedUids.Add(uid)
		}
	}

	// Figure out which selectors/tags are no-longer in use.
	removedUids := set.New()
	rs.rulesIDToUIDs.Iter(key, func(uid string) {
		if _, ok := currentUIDToSel[uid]; !ok {
			log.Debugf("Removed UID: %v", uid)
			removedUids.Add(uid)
		}
	})

	// Add the new into the index, triggering events as we discover
	// newly-active tags/selectors.
	addedUids.Iter(func(item interface{}) error {
		uid := item.(string)
		rs.rulesIDToUIDs.Put(key, uid)
		if !rs.uidsToRulesIDs.ContainsKey(uid) {
			sel := currentUIDToSel[uid]
			rs.selectorsByUID[uid] = sel
			log.Debugf("Selector became active: %v -> %v",
				uid, sel)
			// This selector just became active, trigger event.
			rs.OnSelectorActive(sel)
		}
		rs.uidsToRulesIDs.Put(uid, key)
		return nil
	})

	// And remove the old, triggering events as we clean up unused
	// selectors/tags.
	removedUids.Iter(func(item interface{}) error {
		uid := item.(string)
		rs.rulesIDToUIDs.Discard(key, uid)
		rs.uidsToRulesIDs.Discard(uid, key)
		if !rs.uidsToRulesIDs.ContainsKey(uid) {
			log.Debugf("Selector/tag became inactive: %v", uid)
			sel := rs.selectorsByUID[uid]
			delete(rs.selectorsByUID, uid)

			// This selector just became inactive, trigger event.
			log.Debugf("Selector became inactive: %v -> %v",
				uid, sel)
			rs.OnSelectorInactive(sel)
		}
		return nil
	})
	return
}

type ParsedRules struct {
	InboundRules  []*ParsedRule
	OutboundRules []*ParsedRule

	// Untracked is true if these rules should not be "conntracked".
	Untracked bool
}

// Rule is like a backend.model.Rule, except the tag and selector matches are
// replaced with pre-calculated ipset IDs.
type ParsedRule struct {
	Action string

	IPVersion *int

	Protocol *numorstring.Protocol

	SrcNet      *net.IPNet
	SrcPorts    []numorstring.Port
	DstNet      *net.IPNet
	DstPorts    []numorstring.Port
	ICMPType    *int
	ICMPCode    *int
	SrcIPSetIDs []string
	DstIPSetIDs []string

	NotProtocol    *numorstring.Protocol
	NotSrcNet      *net.IPNet
	NotSrcPorts    []numorstring.Port
	NotDstNet      *net.IPNet
	NotDstPorts    []numorstring.Port
	NotICMPType    *int
	NotICMPCode    *int
	NotSrcIPSetIDs []string
	NotDstIPSetIDs []string
}

func ruleToParsedRule(rule *model.Rule) (parsedRule *ParsedRule, allTagOrSels []selector.Selector) {
	src, dst, notSrc, notDst := extractTagsAndSelectors(rule)

	parsedRule = &ParsedRule{
		Action: rule.Action,

		IPVersion: rule.IPVersion,

		Protocol: rule.Protocol,

		SrcNet:      rule.SrcNet,
		SrcPorts:    rule.SrcPorts,
		DstNet:      rule.DstNet,
		DstPorts:    rule.DstPorts,
		ICMPType:    rule.ICMPType,
		ICMPCode:    rule.ICMPCode,
		SrcIPSetIDs: selectors(src).ToUIDs(),
		DstIPSetIDs: selectors(dst).ToUIDs(),

		NotProtocol:    rule.NotProtocol,
		NotSrcNet:      rule.NotSrcNet,
		NotSrcPorts:    rule.NotSrcPorts,
		NotDstNet:      rule.NotDstNet,
		NotDstPorts:    rule.NotDstPorts,
		NotICMPType:    rule.NotICMPType,
		NotICMPCode:    rule.NotICMPCode,
		NotSrcIPSetIDs: selectors(notSrc).ToUIDs(),
		NotDstIPSetIDs: selectors(notDst).ToUIDs(),
	}

	allTagOrSels = append(allTagOrSels, src...)
	allTagOrSels = append(allTagOrSels, dst...)
	allTagOrSels = append(allTagOrSels, notSrc...)
	allTagOrSels = append(allTagOrSels, notDst...)

	return
}

func extractTagsAndSelectors(rule *model.Rule) (src, dst, notSrc, notDst []selector.Selector) {
	appendTagSelector := func(slice []selector.Selector, tagName string) []selector.Selector {
		if tagName == "" {
			return slice
		}
		sel, err := selFromTag(tagName)
		if err != nil {
			// This shouldn't happen because the data should have been validated
			// further back in the pipeline.
			log.WithField("tag", tagName).Panic(
				"Failed to convert tag to selector; but tag should have been " +
					"validated already.")
		}
		return append(slice, sel)
	}

	appendSelector := func(slice []selector.Selector, rawSelector string) []selector.Selector {
		if rawSelector == "" {
			return slice
		}
		sel, err := selector.Parse(rawSelector)
		if err != nil {
			// This shouldn't happen because the data should have been validated
			// further back in the pipeline.
			log.WithField("selector", rawSelector).Panic(
				"Failed to parse selector that should have been validated already.")
		}
		return append(slice, sel)
	}

	src = appendTagSelector(src, rule.SrcTag)
	src = appendSelector(src, rule.SrcSelector)

	dst = appendTagSelector(dst, rule.DstTag)
	dst = appendSelector(dst, rule.DstSelector)

	notSrc = appendTagSelector(notSrc, rule.NotSrcTag)
	notSrc = appendSelector(notSrc, rule.NotSrcSelector)

	notDst = appendTagSelector(notDst, rule.NotDstTag)
	notDst = appendSelector(notDst, rule.NotDstSelector)

	return
}

func selFromTag(tag string) (selector.Selector, error) {
	return selector.Parse(fmt.Sprintf("has(%s)", tag))
}

type selectors []selector.Selector

func (ss selectors) ToUIDs() []string {
	if len(ss) == 0 {
		return nil
	}
	uids := make([]string, len(ss))
	for i, sel := range ss {
		uids[i] = sel.UniqueID()
	}
	return uids
}
