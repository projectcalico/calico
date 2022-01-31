// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/multidict"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/hash"
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

// RuleScanner scans the rules sent to it by the ActiveRulesCalculator, looking for
// selectors. It calculates the set of active selectors and emits events when they become
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
	// ipSetsByUID maps from the IP set's UID to the metadata for that IP set.
	ipSetsByUID map[string]*IPSetData
	// rulesIDToUIDs maps from policy/profile ID to the set of IP set UIDs that are
	// referenced by that policy/profile.
	rulesIDToUIDs multidict.IfaceToString
	// uidsToRulesIDs maps from IP set UID to the set of policy/profile IDs that use it.
	uidsToRulesIDs multidict.StringToIface

	OnIPSetActive   func(ipSet *IPSetData)
	OnIPSetInactive func(ipSet *IPSetData)

	RulesUpdateCallbacks rulesUpdateCallbacks
}

type IPSetData struct {
	// The selector and named port that this IP set represents.  To represent an unfiltered named
	// port, set selector to AllSelector.  If NamedPortProtocol == ProtocolNone then
	// this IP set represents a selector only, with no named port component.
	Selector selector.Selector
	// NamedPortProtocol identifies the protocol (TCP or UDP) for a named port IP set.  It is
	// set to ProtocolNone for a selector-only IP set.
	NamedPortProtocol labelindex.IPSetPortProtocol
	// NamedPort contains the name of the named port represented by this IP set or "" for a
	// selector-only IP set
	NamedPort string
	// The service that this IP set represents, in namespace/name format.
	Service string
	// Type of the ip set to represent for this service. This allows us to create service
	// IP sets with and without port information.
	ServiceIncludePorts bool
	// cachedUID holds the calculated unique ID of this IP set, or "" if it hasn't been calculated
	// yet.
	cachedUID string
}

func (d *IPSetData) UniqueID() string {
	if d.cachedUID == "" {
		if d.Service != "" {
			// Service based IP set.
			if d.ServiceIncludePorts {
				// Service IP set including its ports
				d.cachedUID = hash.MakeUniqueID("svc", d.Service)
			} else {
				// Service IP set with only its CIDR
				d.cachedUID = hash.MakeUniqueID("svcnoport", d.Service)
			}
		} else {
			// Selector / named-port based IP set.
			selID := d.Selector.UniqueID()
			if d.NamedPortProtocol == labelindex.ProtocolNone {
				d.cachedUID = selID
			} else {
				idToHash := selID + "," + d.NamedPortProtocol.String() + "," + d.NamedPort
				d.cachedUID = hash.MakeUniqueID("n", idToHash)
			}
		}
	}
	return d.cachedUID
}

// DataplaneProtocolType returns the dataplane driver protocol type of this IP set.
// One of the proto.IPSetUpdate_IPSetType constants.
func (d *IPSetData) DataplaneProtocolType() proto.IPSetUpdate_IPSetType {
	if d.NamedPortProtocol != labelindex.ProtocolNone {
		return proto.IPSetUpdate_IP_AND_PORT
	}
	if d.Service != "" {
		if d.ServiceIncludePorts {
			return proto.IPSetUpdate_IP_AND_PORT
		}
	}
	return proto.IPSetUpdate_NET
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
	parsedRules := rs.updateRules(key, profile.InboundRules, profile.OutboundRules, false, false, "")
	rs.RulesUpdateCallbacks.OnProfileActive(key, parsedRules)
}

func (rs *RuleScanner) OnProfileInactive(key model.ProfileRulesKey) {
	rs.updateRules(key, nil, nil, false, false, "")
	rs.RulesUpdateCallbacks.OnProfileInactive(key)
}

func (rs *RuleScanner) OnPolicyActive(key model.PolicyKey, policy *model.Policy) {
	parsedRules := rs.updateRules(key, policy.InboundRules, policy.OutboundRules, policy.DoNotTrack, policy.PreDNAT, policy.Namespace)
	rs.RulesUpdateCallbacks.OnPolicyActive(key, parsedRules)
}

func (rs *RuleScanner) OnPolicyInactive(key model.PolicyKey) {
	rs.updateRules(key, nil, nil, false, false, "")
	rs.RulesUpdateCallbacks.OnPolicyInactive(key)
}

func (rs *RuleScanner) updateRules(key interface{}, inbound, outbound []model.Rule, untracked, preDNAT bool, origNamespace string) (parsedRules *ParsedRules) {
	log.Debugf("Scanning rules (%v in, %v out) for key %v",
		len(inbound), len(outbound), key)
	// Extract all the new selectors/named ports.
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
		parsed, allIPSets := ruleToParsedRule(&rule)
		parsedOutbound[ii] = parsed
		for _, ipSet := range allIPSets {
			// Note: there may be more than one entry in allIPSets for the same UID, but that's only
			// the case if the two entries really represent the same IP set so it's OK to coalesce
			// them here.
			currentUIDToIPSet[ipSet.UniqueID()] = ipSet
		}
	}
	parsedRules = &ParsedRules{
		Namespace:     origNamespace,
		InboundRules:  parsedInbound,
		OutboundRules: parsedOutbound,
		Untracked:     untracked,
		PreDNAT:       preDNAT,
	}

	// Figure out which IP sets are new.
	addedUids := set.New()
	for uid := range currentUIDToIPSet {
		log.Debugf("Checking if UID %v is new.", uid)
		if !rs.rulesIDToUIDs.Contains(key, uid) {
			log.Debugf("UID %v is new", uid)
			addedUids.Add(uid)
		}
	}

	// Figure out which IP sets are no-longer in use.
	removedUids := set.New()
	rs.rulesIDToUIDs.Iter(key, func(uid string) {
		if _, ok := currentUIDToIPSet[uid]; !ok {
			log.Debugf("Removed UID: %v", uid)
			removedUids.Add(uid)
		}
	})

	// Add the new into the index, triggering events as we discover newly-active IP sets.
	addedUids.Iter(func(item interface{}) error {
		uid := item.(string)
		rs.rulesIDToUIDs.Put(key, uid)
		if !rs.uidsToRulesIDs.ContainsKey(uid) {
			ipSet := currentUIDToIPSet[uid]
			rs.ipSetsByUID[uid] = ipSet
			log.Debugf("IP set became active: %v -> %v", uid, ipSet)
			// This IP set just became active, send event.
			rs.OnIPSetActive(ipSet)
		}
		rs.uidsToRulesIDs.Put(uid, key)
		return nil
	})

	// And remove the old, triggering events as we clean up unused IP sets.
	removedUids.Iter(func(item interface{}) error {
		uid := item.(string)
		rs.rulesIDToUIDs.Discard(key, uid)
		rs.uidsToRulesIDs.Discard(uid, key)
		if !rs.uidsToRulesIDs.ContainsKey(uid) {
			ipSetData := rs.ipSetsByUID[uid]
			delete(rs.ipSetsByUID, uid)
			// This IP set just became inactive, send event.
			log.Debugf("IP set became inactive: %v -> %v", uid, ipSetData)
			rs.OnIPSetInactive(ipSetData)
		}
		return nil
	})
	return
}

// ParsedRules holds our intermediate representation of either a policy's rules or a profile's
// rules.  As part of its processing, the RuleScanner converts backend rules into ParsedRules.
// Where backend rules contain selectors and named ports, ParsedRules only contain
// IPSet IDs.  The RuleScanner calculates the relevant IDs as it processes the rules and diverts
// the details of the active selectors and named ports to the named port index, which
// figures out the members that should be in those IP sets.
type ParsedRules struct {
	// For NetworkPolicies, Namespace is set to the original namespace of the NetworkPolicy.
	// For GlobalNetworkPolicies and Profiles, "".
	Namespace string

	InboundRules  []*ParsedRule
	OutboundRules []*ParsedRule

	// Untracked is true if these rules should not be "conntracked".
	Untracked bool

	// PreDNAT is true if these rules should be applied before any DNAT.
	PreDNAT bool
}

// ParsedRule is like a backend.model.Rule, except the selector matches and named ports are
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
	DstIPPortSetIDs      []string

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

	// These fields allow us to pass through the raw match criteria from the V3 datamodel,
	// unmodified. The selectors above are formed in the update processor layer by combining the
	// original selectors, namespace selectors an service account matches into one.
	OriginalSrcSelector               string
	OriginalSrcNamespaceSelector      string
	OriginalDstSelector               string
	OriginalDstNamespaceSelector      string
	OriginalNotSrcSelector            string
	OriginalNotDstSelector            string
	OriginalSrcServiceAccountNames    []string
	OriginalSrcServiceAccountSelector string
	OriginalDstServiceAccountNames    []string
	OriginalDstServiceAccountSelector string
	OriginalSrcService                string
	OriginalSrcServiceNamespace       string
	OriginalDstService                string
	OriginalDstServiceNamespace       string

	// These fields allow us to pass through the HTTP match criteria from the V3 datamodel. The iptables dataplane
	// does not implement the match, but other dataplanes such as Dikastes do.
	HTTPMatch *model.HTTPMatch

	Metadata *model.RuleMetadata
}

func ruleToParsedRule(rule *model.Rule) (parsedRule *ParsedRule, allIPSets []*IPSetData) {
	srcSel, dstSel, notSrcSels, notDstSels := extractSelectors(rule)

	// In the datamodel, named ports are included in the list of ports as an "or" match; i.e. the
	// list of ports matches the packet if either one of the numeric ports matches, or one of the
	// named ports matches.  Since we have to render named ports as IP sets, we need to split them
	// out for special handling.
	srcNumericPorts, srcNamedPorts := splitNamedAndNumericPorts(rule.SrcPorts)
	dstNumericPorts, dstNamedPorts := splitNamedAndNumericPorts(rule.DstPorts)
	notSrcNumericPorts, notSrcNamedPorts := splitNamedAndNumericPorts(rule.NotSrcPorts)
	notDstNumericPorts, notDstNamedPorts := splitNamedAndNumericPorts(rule.NotDstPorts)

	// Named ports on our endpoints have a protocol attached but our rules have the protocol at
	// the top level.  Convert that to a protocol that we can use with the IP set calculation logic.
	namedPortProto := labelindex.ProtocolTCP
	if rule.Protocol != nil {
		if labelindex.ProtocolUDP.MatchesModelProtocol(*rule.Protocol) {
			namedPortProto = labelindex.ProtocolUDP
		} else if labelindex.ProtocolSCTP.MatchesModelProtocol(*rule.Protocol) {
			namedPortProto = labelindex.ProtocolSCTP
		}
	}

	// Convert each named port into an IP set definition.  As an optimization, if there's a selector
	// for the relevant direction, we filter the named port by the selector.  Note: we always
	// use the positive (i.e. non-negated) selector, even when filtering the negated named port.
	// This is because the rule as a whole can only match if the positive selector matches the
	// packet so it's safe to render only port matches for the intersection with that positive
	// selector.
	//
	// For negated selectors that property doesn't hold, since the negated matches are combined as,
	//
	//     (not <match-1>) and (not <match-2>) and not...
	//
	// which is equivalent to
	//
	//     not (<match-1> or <match-2>)
	//
	// we'd need the union of <match-1> and <match-2> rather than the intersection.
	srcNamedPortIPSets := namedPortsToIPSets(srcNamedPorts, srcSel, namedPortProto)
	dstNamedPortIPSets := namedPortsToIPSets(dstNamedPorts, dstSel, namedPortProto)
	notSrcNamedPortIPSets := namedPortsToIPSets(notSrcNamedPorts, srcSel, namedPortProto)
	notDstNamedPortIPSets := namedPortsToIPSets(notDstNamedPorts, dstSel, namedPortProto)

	// Optimization: only include the selectors if we haven't already covered them with a named
	// port match above.  If we have some named ports then we've already filtered the named port
	// by the selector above.  If we have numeric ports, we can't make the optimization
	// because we can't filter numeric ports by selector in the same way.
	var srcSelIPSets, dstSelIPSets []*IPSetData
	if len(srcNumericPorts) > 0 || len(srcNamedPorts) == 0 {
		srcSelIPSets = selectorsToIPSets(srcSel)
	}
	if len(dstNumericPorts) > 0 || len(dstNamedPorts) == 0 {
		dstSelIPSets = selectorsToIPSets(dstSel)
	}

	// Include any Service IPSet as well.
	var dstIPPortSets []*IPSetData
	if rule.DstService != "" {
		svc := fmt.Sprintf("%s/%s", rule.DstServiceNamespace, rule.DstService)
		dstIPPortSets = append(dstIPPortSets, &IPSetData{Service: svc, ServiceIncludePorts: true})
	}

	if rule.SrcService != "" {
		svc := fmt.Sprintf("%s/%s", rule.SrcServiceNamespace, rule.SrcService)
		srcSelIPSets = append(srcSelIPSets, &IPSetData{Service: svc, ServiceIncludePorts: false})
	}

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
		DstIPPortSetIDs:      ipSetsToUIDs(dstIPPortSets),

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

		// Pass through original values of some fields for the policy API.
		OriginalSrcSelector:               rule.OriginalSrcSelector,
		OriginalSrcNamespaceSelector:      rule.OriginalSrcNamespaceSelector,
		OriginalDstSelector:               rule.OriginalDstSelector,
		OriginalDstNamespaceSelector:      rule.OriginalDstNamespaceSelector,
		OriginalNotSrcSelector:            rule.OriginalNotSrcSelector,
		OriginalNotDstSelector:            rule.OriginalNotDstSelector,
		OriginalSrcServiceAccountNames:    rule.OriginalSrcServiceAccountNames,
		OriginalSrcServiceAccountSelector: rule.OriginalSrcServiceAccountSelector,
		OriginalDstServiceAccountNames:    rule.OriginalDstServiceAccountNames,
		OriginalDstServiceAccountSelector: rule.OriginalDstServiceAccountSelector,
		OriginalSrcService:                rule.SrcService,
		OriginalSrcServiceNamespace:       rule.SrcServiceNamespace,
		OriginalDstService:                rule.DstService,
		OriginalDstServiceNamespace:       rule.DstServiceNamespace,
		HTTPMatch:                         rule.HTTPMatch,

		// Pass through metadata (used by iptables backend)
		Metadata: rule.Metadata,
	}

	allIPSets = append(allIPSets, srcNamedPortIPSets...)
	allIPSets = append(allIPSets, dstNamedPortIPSets...)
	allIPSets = append(allIPSets, notSrcNamedPortIPSets...)
	allIPSets = append(allIPSets, notDstNamedPortIPSets...)
	allIPSets = append(allIPSets, srcSelIPSets...)
	allIPSets = append(allIPSets, dstSelIPSets...)
	allIPSets = append(allIPSets, dstIPPortSets...)
	allIPSets = append(allIPSets, notSrcSelIPSets...)
	allIPSets = append(allIPSets, notDstSelIPSets...)

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

func splitNamedAndNumericPorts(ports []numorstring.Port) (numericPorts []numorstring.Port, namedPorts []string) {
	for _, p := range ports {
		if p.PortName != "" {
			namedPorts = append(namedPorts, p.PortName)
		} else {
			numericPorts = append(numericPorts, p)
		}
	}
	return
}

// extractSelectors extracts the selector matches from the rule and converts them
// to selector.Selector objects.  Where it is likely to make the resulting IP sets smaller (or
// fewer in number), it tries to combine multiple match criteria into a single selector.
//
// Returns at most one positive src/dst selector in src/dst.  The named port logic above relies on
// this.  We still return a slice for those values in order to make it easier to use the utility
// functions uniformly.
func extractSelectors(rule *model.Rule) (src, dst, notSrc, notDst []selector.Selector) {
	// Calculate a minimal set of selectors.  combineMatchesIfPossible will try to combine the
	// negative matches into that single selector, if possible.
	srcRawSel, notSrcSel := combineMatchesIfPossible(rule.SrcSelector, rule.NotSrcSelector)
	dstRawSel, notDstSel := combineMatchesIfPossible(rule.DstSelector, rule.NotDstSelector)

	parseAndAppendSelectorIfNonZero := func(slice []selector.Selector, rawSelector string) []selector.Selector {
		if rawSelector == "" {
			return slice
		}
		sel, err := selector.Parse(rawSelector)
		if err != nil {
			// Should have been validated further back in the pipeline.
			log.WithField("selector", rawSelector).Panic(
				"Failed to parse selector that should have been validated already.")
		}
		return append(slice, sel)
	}
	src = parseAndAppendSelectorIfNonZero(src, srcRawSel)
	dst = parseAndAppendSelectorIfNonZero(dst, dstRawSel)
	notSrc = parseAndAppendSelectorIfNonZero(notSrc, notSrcSel)
	notDst = parseAndAppendSelectorIfNonZero(notDst, notDstSel)

	return
}

func combineMatchesIfPossible(positiveSel, negatedSel string) (string, string) {
	if positiveSel == "" {
		// There were no positive matches, we can't do any further optimization.
		return positiveSel, negatedSel
	}

	// We have a positive selector so the rule is limited to matching known endpoints.
	// Instead of rendering a second (and third) selector for the negative match criteria, use them
	// to filter down the positive selector.
	//
	// If we have no positive selector, this optimization wouldn't be valid because, in that
	// case, the negative match criteria should match packets that come from outside the
	// set of known endpoints too.
	if negatedSel != "" {
		positiveSel = fmt.Sprintf("(%s) && (!(%s))", positiveSel, negatedSel)
		negatedSel = ""
	}
	return positiveSel, negatedSel
}
