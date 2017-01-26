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
	"github.com/projectcalico/felix/multidict"
	"github.com/projectcalico/felix/set"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/hash"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/selector"
)

// RuleScanner calculates which selectors and tags are in use by the active rules (calculated
// by the ActiveRulesCalculator).  I.e. which tags and selectors are in the rules and need to
// be rendered to the dataplane (as IP sets, for example).
//
// The RuleScanner emits events via the attached callbacks when tags/selectors become
// active/inactive.  It also emits events when rules are updated:  since the input rule
// structs contain tags and selectors but downstream, we only care about IP sets, the
// RuleScanner converts rules from model.Rule objects to calc.ParsedRule objects.
// The latter share most fields, but the tags and selector fields are replaced by lists of
// IP sets.
//
// The RuleScanner only calculates which selectors and tags are active/inactive.  It doesn't
// match endpoints against tags/selectors.  (That is done downstream in a labelindex.InheritIndex
// created in NewCalculationGraph.)
type RuleScanner struct {
	// selectorsByUid maps from a selector's UID to the selector itself.
	tagsOrSelsByUID map[string]tagOrSel
	// activeUidsByResource maps from policy or profile ID to "set" of selector UIDs
	rulesIDToUIDs multidict.IfaceToString
	// activeResourcesByUid maps from selector UID back to the "set" of resources using it.
	uidsToRulesIDs multidict.StringToIface

	OnSelectorActive   func(selector selector.Selector)
	OnSelectorInactive func(selector selector.Selector)
	OnTagActive        func(tag string)
	OnTagInactive      func(tag string)

	RulesUpdateCallbacks rulesUpdateCallbacks
}

func NewRuleScanner() *RuleScanner {
	calc := &RuleScanner{
		tagsOrSelsByUID: make(map[string]tagOrSel),
		rulesIDToUIDs:   multidict.NewIfaceToString(),
		uidsToRulesIDs:  multidict.NewStringToIface(),
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
	currentUIDToTagOrSel := make(map[string]tagOrSel)
	parsedInbound := make([]*ParsedRule, len(inbound))
	for ii, rule := range inbound {
		parsed, allToS, err := ruleToParsedRule(&rule)
		if err != nil {
			log.Fatalf("Bad selector in %v: %v", key, err)
		}
		parsedInbound[ii] = parsed
		for _, tos := range allToS {
			currentUIDToTagOrSel[tos.uid] = tos
		}
	}
	parsedOutbound := make([]*ParsedRule, len(outbound))
	for ii, rule := range outbound {
		parsed, allToS, err := ruleToParsedRule(&rule)
		if err != nil {
			log.Fatalf("Bad selector in %v: %v", key, err)
		}
		parsedOutbound[ii] = parsed
		for _, tos := range allToS {
			currentUIDToTagOrSel[tos.uid] = tos
		}
	}
	parsedRules = &ParsedRules{
		InboundRules:  parsedInbound,
		OutboundRules: parsedOutbound,
		Untracked:     untracked,
	}

	// Figure out which selectors/tags are new.
	addedUids := set.New()
	for uid := range currentUIDToTagOrSel {
		log.Debugf("Checking if UID %v is new.", uid)
		if !rs.rulesIDToUIDs.Contains(key, uid) {
			log.Debugf("UID %v is new", uid)
			addedUids.Add(uid)
		}
	}

	// Figure out which selectors/tags are no-longer in use.
	removedUids := set.New()
	rs.rulesIDToUIDs.Iter(key, func(uid string) {
		if _, ok := currentUIDToTagOrSel[uid]; !ok {
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
			tagOrSel := currentUIDToTagOrSel[uid]
			rs.tagsOrSelsByUID[uid] = tagOrSel
			if tagOrSel.selector != nil {
				sel := tagOrSel.selector
				log.Debugf("Selector became active: %v -> %v",
					uid, sel)
				// This selector just became active, trigger event.
				rs.OnSelectorActive(sel)
			} else {
				tag := tagOrSel.tag
				log.Debugf("Tag became active: %v -> %v",
					uid, tag)
				rs.OnTagActive(tag)
			}
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
			tagOrSel := rs.tagsOrSelsByUID[uid]
			delete(rs.tagsOrSelsByUID, uid)
			if tagOrSel.selector != nil {
				// This selector just became inactive, trigger event.
				sel := tagOrSel.selector
				log.Debugf("Selector became inactive: %v -> %v",
					uid, sel)
				rs.OnSelectorInactive(sel)
			} else {
				tag := tagOrSel.tag
				log.Debugf("Tag became inactive: %v -> %v",
					uid, tag)
				rs.OnTagInactive(tag)
			}
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

	LogPrefix string
}

func ruleToParsedRule(rule *model.Rule) (parsedRule *ParsedRule, allTagOrSels []tagOrSel, err error) {
	src, dst, notSrc, notDst, err := extractTagsAndSelectors(rule)
	if err != nil {
		return
	}

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
		SrcIPSetIDs: tosSlice(src).ToUIDs(),
		DstIPSetIDs: tosSlice(dst).ToUIDs(),

		NotProtocol:    rule.NotProtocol,
		NotSrcNet:      rule.NotSrcNet,
		NotSrcPorts:    rule.NotSrcPorts,
		NotDstNet:      rule.NotDstNet,
		NotDstPorts:    rule.NotDstPorts,
		NotICMPType:    rule.NotICMPType,
		NotICMPCode:    rule.NotICMPCode,
		NotSrcIPSetIDs: tosSlice(notSrc).ToUIDs(),
		NotDstIPSetIDs: tosSlice(notDst).ToUIDs(),

		LogPrefix: rule.LogPrefix,
	}

	allTagOrSels = append(allTagOrSels, src...)
	allTagOrSels = append(allTagOrSels, dst...)
	allTagOrSels = append(allTagOrSels, notSrc...)
	allTagOrSels = append(allTagOrSels, notDst...)

	return
}

func extractTagsAndSelectors(rule *model.Rule) (src, dst, notSrc, notDst []tagOrSel, err error) {
	if rule.SrcTag != "" {
		src = append(src, tagOrSelFromTag(rule.SrcTag))
	}
	if rule.DstTag != "" {
		dst = append(dst, tagOrSelFromTag(rule.DstTag))
	}
	if rule.NotSrcTag != "" {
		notSrc = append(notSrc, tagOrSelFromTag(rule.NotSrcTag))
	}
	if rule.NotDstTag != "" {
		notDst = append(notDst, tagOrSelFromTag(rule.NotDstTag))
	}
	var tos tagOrSel
	if rule.SrcSelector != "" {
		tos, err = tagOrSelFromSel(rule.SrcSelector)
		if err != nil {
			return
		}
		src = append(src, tos)
	}
	if rule.DstSelector != "" {
		tos, err = tagOrSelFromSel(rule.DstSelector)
		if err != nil {
			return
		}
		dst = append(dst, tos)
	}
	if rule.NotSrcSelector != "" {
		tos, err = tagOrSelFromSel(rule.NotSrcSelector)
		if err != nil {
			return
		}
		notSrc = append(notSrc, tos)
	}
	if rule.NotDstSelector != "" {
		tos, err = tagOrSelFromSel(rule.NotDstSelector)
		if err != nil {
			return
		}
		notDst = append(notDst, tos)
	}
	return
}

type tagOrSel struct {
	tag      string
	selector selector.Selector
	uid      string
}

func tagOrSelFromTag(tag string) tagOrSel {
	return tagOrSel{tag: tag, uid: hash.MakeUniqueID("t", tag)}
}

func tagOrSelFromSel(sel string) (tos tagOrSel, err error) {
	parsedSel, err := selector.Parse(sel)
	if err == nil {
		tos = tagOrSel{selector: parsedSel, uid: parsedSel.UniqueId()}
	}
	return
}

type tosSlice []tagOrSel

func (t tosSlice) ToUIDs() []string {
	if len(t) == 0 {
		return nil
	}
	uids := make([]string, len(t))
	for ii, tos := range t {
		uids[ii] = tos.uid
	}
	return uids
}
