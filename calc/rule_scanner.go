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
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/selector"
	"github.com/projectcalico/libcalico-go/lib/set"

	"github.com/projectcalico/felix/labelindex"
	"github.com/projectcalico/felix/multidict"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/hash"
)

// AllSelector is a pre-calculated copy of the "all()" selector.
var AllSelector selector.Selector

func init() {
	var err error
	AllSelector, err = selector.Parse("all()")
	if err != nil {
		log.WithError(err).Panic("Failed to parse all() selector.")
	}
	// Force the selector's cache fields to be pre-populated.
	_ = AllSelector.UniqueID()
	_ = AllSelector.String()
}

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
	// ipSetsByUID maps from the selector's hash back to the selector.
	ipSetsByUID map[string]*IPSetData
	// activeUidsByResource maps from policy or profile ID to "set" of selector UIDs
	rulesIDToUIDs multidict.IfaceToString
	// activeResourcesByUid maps from selector UID back to the "set" of resources using it.
	uidsToRulesIDs multidict.StringToIface

	OnIPSetActive   func(ipSet *IPSetData)
	OnIPSetInactive func(ipSet *IPSetData)

	RulesUpdateCallbacks rulesUpdateCallbacks
}

type IPSetData struct {
	// The selector and named port that this IP set represents.  To represent an unfiltered named
	// port, set selector to "all()".  If NamedPortProtocol == ProtocolNone then
	// this IP set represents a selector only, with no named port component.
	Selector          selector.Selector
	NamedPortProtocol labelindex.IPSetPortProtocol
	NamedPort         string
	cachedUID         string
}

func (d *IPSetData) UniqueID() string {
	if d.cachedUID == "" {
		selID := d.Selector.UniqueID()
		if d.NamedPortProtocol == labelindex.ProtocolNone {
			d.cachedUID = selID
		} else {
			idToHash := selID + "," + d.NamedPortProtocol.String() + "," + d.NamedPort
			d.cachedUID = hash.MakeUniqueID("n", idToHash)
		}
	}
	return d.cachedUID
}

func (d *IPSetData) ProtocolType() proto.IPSetUpdate_IPSetType {
	if d.NamedPortProtocol != labelindex.ProtocolNone {
		return proto.IPSetUpdate_IP_AND_PORT
	}
	return proto.IPSetUpdate_IP
}

func NewRuleScanner() *RuleScanner {
	calc := &RuleScanner{
		ipSetsByUID:    make(map[string]*IPSetData),
		rulesIDToUIDs:  multidict.NewIfaceToString(),
		uidsToRulesIDs: multidict.NewStringToIface(),
	}
	return calc
}

func (rs *RuleScanner) OnProfileActive(key model.ProfileRulesKey, profile *model.ProfileRules) {
	parsedRules := rs.updateRules(key, profile.InboundRules, profile.OutboundRules, false, false)
	rs.RulesUpdateCallbacks.OnProfileActive(key, parsedRules)
}

func (rs *RuleScanner) OnProfileInactive(key model.ProfileRulesKey) {
	rs.updateRules(key, nil, nil, false, false)
	rs.RulesUpdateCallbacks.OnProfileInactive(key)
}

func (rs *RuleScanner) OnPolicyActive(key model.PolicyKey, policy *model.Policy) {
	parsedRules := rs.updateRules(key, policy.InboundRules, policy.OutboundRules, policy.DoNotTrack, policy.PreDNAT)
	rs.RulesUpdateCallbacks.OnPolicyActive(key, parsedRules)
}

func (rs *RuleScanner) OnPolicyInactive(key model.PolicyKey) {
	rs.updateRules(key, nil, nil, false, false)
	rs.RulesUpdateCallbacks.OnPolicyInactive(key)
}

func (rs *RuleScanner) updateRules(key interface{}, inbound, outbound []model.Rule, untracked, preDNAT bool) (parsedRules *ParsedRules) {
	log.Debugf("Scanning rules (%v in, %v out) for key %v",
		len(inbound), len(outbound), key)
	// Extract all the new selectors/tags.
	currentUIDToIPSet := make(map[string]*IPSetData)
	parsedInbound := make([]*ParsedRule, len(inbound))
	for ii, rule := range inbound {
		parsed, allIPSets := ruleToParsedRule(&rule)
		parsedInbound[ii] = parsed
		for _, ipSet := range allIPSets {
			// Note: there may be more than one entry in allIPSets for the same UID, but that's only
			// the case if the two entries really represent the same IP set so it's OK to coalesce
			// them here.
			currentUIDToIPSet[ipSet.UniqueID()] = ipSet
		}
	}
	parsedOutbound := make([]*ParsedRule, len(outbound))
	for ii, rule := range outbound {
		parsed, allSels := ruleToParsedRule(&rule)
		parsedOutbound[ii] = parsed
		for _, ipSet := range allSels {
			// Note: there may be more than one entry in allIPSets for the same UID, but that's only
			// the case if the two entries really represent the same IP set so it's OK to coalesce
			// them here.
			currentUIDToIPSet[ipSet.UniqueID()] = ipSet
		}
	}
	parsedRules = &ParsedRules{
		InboundRules:  parsedInbound,
		OutboundRules: parsedOutbound,
		Untracked:     untracked,
		PreDNAT:       preDNAT,
	}

	// Figure out which selectors/tags are new.
	addedUids := set.New()
	for uid := range currentUIDToIPSet {
		log.Debugf("Checking if UID %v is new.", uid)
		if !rs.rulesIDToUIDs.Contains(key, uid) {
			log.Debugf("UID %v is new", uid)
			addedUids.Add(uid)
		}
	}

	// Figure out which selectors/tags are no-longer in use.
	removedUids := set.New()
	rs.rulesIDToUIDs.Iter(key, func(uid string) {
		if _, ok := currentUIDToIPSet[uid]; !ok {
			log.Debugf("Removed UID: %v", uid)
			removedUids.Add(uid)
		}
	})

	// Add the new into the index, triggering events as we discover
	// newly-active IP sets.
	addedUids.Iter(func(item interface{}) error {
		uid := item.(string)
		rs.rulesIDToUIDs.Put(key, uid)
		if !rs.uidsToRulesIDs.ContainsKey(uid) {
			ipSet := currentUIDToIPSet[uid]
			rs.ipSetsByUID[uid] = ipSet
			log.Debugf("Selector became active: %v -> %v",
				uid, ipSet)
			// This selector just became active, trigger event.
			rs.OnIPSetActive(ipSet)
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
			sel := rs.ipSetsByUID[uid]
			delete(rs.ipSetsByUID, uid)

			// This selector just became inactive, trigger event.
			log.Debugf("Selector became inactive: %v -> %v",
				uid, sel)
			rs.OnIPSetInactive(sel)
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

	// PreDNAT is true if these rules should be applied before any DNAT.
	PreDNAT bool
}

// Rule is like a backend.model.Rule, except the tag and selector matches are
// replaced with pre-calculated ipset IDs.
type ParsedRule struct {
	Action string

	IPVersion *int

	Protocol *numorstring.Protocol

	SrcNets              []*net.IPNet
	SrcPorts             []numorstring.Port
	SrcNamedPortIPSetIDs []string
	DstNets              []*net.IPNet
	DstPorts             []numorstring.Port
	DstNamedPortIPSetIDs []string
	ICMPType             *int
	ICMPCode             *int
	SrcIPSetIDs          []string
	DstIPSetIDs          []string

	NotProtocol             *numorstring.Protocol
	NotSrcNets              []*net.IPNet
	NotSrcPorts             []numorstring.Port
	NotSrcNamedPortIPSetIDs []string
	NotDstNets              []*net.IPNet
	NotDstPorts             []numorstring.Port
	NotDstNamedPortIPSetIDs []string
	NotICMPType             *int
	NotICMPCode             *int
	NotSrcIPSetIDs          []string
	NotDstIPSetIDs          []string
}

func ruleToParsedRule(rule *model.Rule) (parsedRule *ParsedRule, allTagOrSels []*IPSetData) {
	srcSel, dstSel, notSrcSels, notDstSels := extractTagsAndSelectors(rule)

	// In the datamodel, named ports are included in the list of ports as an "or" match; i.e. the
	// list of ports matches the packet if either one of the numeric ports matches, or one of the
	// named ports matches.  Since we have to render named ports as IP sets, we need to split them
	// out for special handling.
	srcNumericPorts, srcNamedPorts := splitNamedPorts(rule.SrcPorts)
	dstNumericPorts, dstNamedPorts := splitNamedPorts(rule.DstPorts)
	notSrcNumericPorts, notSrcNamedPorts := splitNamedPorts(rule.NotSrcPorts)
	notDstNumericPorts, notDstNamedPorts := splitNamedPorts(rule.NotDstPorts)

	// Named ports on our endpoints have a protocol attached but our rules have the protocol at
	// the top level.  Convert that to a protocol that we can use with the IP set calculation logic.
	namedPortProto := labelindex.ProtocolTCP
	if rule.Protocol != nil && labelindex.ProtocolUDP.MatchesModelProtocol(*rule.Protocol) {
		namedPortProto = labelindex.ProtocolUDP
	}

	// Convert each named port into an IP set definition.  As an optimization, if there's a selector
	// for the relevant direction, we filter the named port by the selector.  Note: we always
	// use the positive (i.e. non-negated) selector, even when filtering the negated named port.
	// This is because the rule as a whole can only match if the positive selector matches the
	// packet so we only need to render port matches for the intersection with that positive
	// selector.
	srcNamedPortIPSets := namedPortsToIPSets(srcNamedPorts, srcSel, namedPortProto)
	dstNamedPortIPSets := namedPortsToIPSets(dstNamedPorts, dstSel, namedPortProto)
	notSrcNamedPortIPSets := namedPortsToIPSets(notSrcNamedPorts, srcSel, namedPortProto)
	notDstNamedPortIPSets := namedPortsToIPSets(notDstNamedPorts, dstSel, namedPortProto)

	srcSelIPSets := selectorsToIPSets(srcSel)
	dstSelIPSets := selectorsToIPSets(dstSel)
	notSrcSelIPSets := selectorsToIPSets(notSrcSels)
	notDstSelIPSets := selectorsToIPSets(notDstSels)

	parsedRule = &ParsedRule{
		Action: rule.Action,

		IPVersion: rule.IPVersion,

		Protocol: rule.Protocol,

		SrcNets:              rule.AllSrcNets(),
		SrcPorts:             srcNumericPorts,
		SrcNamedPortIPSetIDs: ipSetsToUIDs(srcNamedPortIPSets),
		SrcIPSetIDs:          ipSetsToUIDs(srcSelIPSets),

		DstNets:              rule.AllDstNets(),
		DstPorts:             dstNumericPorts,
		DstNamedPortIPSetIDs: ipSetsToUIDs(dstNamedPortIPSets),
		DstIPSetIDs:          ipSetsToUIDs(dstSelIPSets),

		ICMPType: rule.ICMPType,
		ICMPCode: rule.ICMPCode,

		NotProtocol: rule.NotProtocol,

		NotSrcNets:              rule.AllNotSrcNets(),
		NotSrcPorts:             notSrcNumericPorts,
		NotSrcNamedPortIPSetIDs: ipSetsToUIDs(notSrcNamedPortIPSets),
		NotSrcIPSetIDs:          ipSetsToUIDs(notSrcSelIPSets),

		NotDstNets:              rule.AllNotDstNets(),
		NotDstPorts:             notDstNumericPorts,
		NotDstNamedPortIPSetIDs: ipSetsToUIDs(notDstNamedPortIPSets),
		NotDstIPSetIDs:          ipSetsToUIDs(notDstSelIPSets),

		NotICMPType: rule.NotICMPType,
		NotICMPCode: rule.NotICMPCode,
	}

	allTagOrSels = append(allTagOrSels, srcNamedPortIPSets...)
	allTagOrSels = append(allTagOrSels, dstNamedPortIPSets...)
	allTagOrSels = append(allTagOrSels, notSrcNamedPortIPSets...)
	allTagOrSels = append(allTagOrSels, notDstNamedPortIPSets...)
	allTagOrSels = append(allTagOrSels, srcSelIPSets...)
	allTagOrSels = append(allTagOrSels, dstSelIPSets...)
	allTagOrSels = append(allTagOrSels, notSrcSelIPSets...)
	allTagOrSels = append(allTagOrSels, notDstSelIPSets...)

	return
}

func namedPortsToIPSets(namedPorts []string, positiveSelectors []selector.Selector, proto labelindex.IPSetPortProtocol) []*IPSetData {
	var ipSets []*IPSetData
	if len(positiveSelectors) > 1 {
		log.WithField("selectors", positiveSelectors).Panic(
			"More than one positive selector passed to namedPortsToIPSets")
	}
	sel := AllSelector
	if len(positiveSelectors) > 0 {
		sel = positiveSelectors[0]
	}
	for _, namedPort := range namedPorts {
		ipSet := IPSetData{
			Selector:          sel,
			NamedPort:         namedPort,
			NamedPortProtocol: proto,
		}
		ipSets = append(ipSets, &ipSet)
	}
	return ipSets
}

func selectorsToIPSets(selectors []selector.Selector) []*IPSetData {
	var ipSets []*IPSetData
	for _, s := range selectors {
		ipSets = append(ipSets, &IPSetData{
			Selector: s,
		})
	}
	return ipSets
}

func ipSetsToUIDs(ipSets []*IPSetData) []string {
	var ids []string
	for _, ipSet := range ipSets {
		ids = append(ids, ipSet.UniqueID())
	}
	return ids
}

func splitNamedPorts(ports []numorstring.Port) (numericPorts []numorstring.Port, namedPorts []string) {
	for _, p := range ports {
		if p.PortName != "" {
			namedPorts = append(namedPorts, p.PortName)
		} else {
			numericPorts = append(numericPorts, p)
		}
	}
	return
}

func extractTagsAndSelectors(rule *model.Rule) (src, dst, notSrc, notDst []selector.Selector) {
	maybeAppendSelector := func(slice []selector.Selector, tagName string, rawSelector string) []selector.Selector {
		if tagName != "" {
			if rawSelector != "" {
				rawSelector = fmt.Sprintf("(%s) && has(%s)", rawSelector, tagName)
			} else {
				rawSelector = fmt.Sprintf("has(%s)", tagName)
			}
		}
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

	// Since the positive selectors get and-ed together, we can combine each into a single selector.
	// Note: the namedPortsToIPSets method relies on this behaviour.
	src = maybeAppendSelector(src, rule.SrcTag, rule.SrcSelector)
	dst = maybeAppendSelector(dst, rule.DstTag, rule.DstSelector)

	// The negative selectors get or-ed together so we have to render multiple selectors.
	notSrc = maybeAppendSelector(notSrc, rule.NotSrcTag, "")
	notSrc = maybeAppendSelector(notSrc, "", rule.NotSrcSelector)

	notDst = maybeAppendSelector(notDst, rule.NotDstTag, "")
	notDst = maybeAppendSelector(notDst, "", rule.NotDstSelector)

	return
}
