//+build windows

// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package policysets

import (
	"strings"

	hns "github.com/Microsoft/hcsshim"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/dataplane/windows/ipsets"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/set"
)

// PolicySets manages a whole plane of policies/profiles
type PolicySets struct {
	policySetIdToPolicySet map[string]*policySet

	IpSets []*ipsets.IPSets

	resyncRequired bool
}

func NewPolicySets(ipsets []*ipsets.IPSets) *PolicySets {
	return &PolicySets{
		policySetIdToPolicySet: map[string]*policySet{},
		IpSets:                 ipsets,
	}
}

// AddOrReplacePolicySet is responsible for the creation (or replacement) of a Policy set
// and it is capable of processing either Profiles or Policies from the datastore.
func (s *PolicySets) AddOrReplacePolicySet(setId string, policy interface{}) {
	log.WithField("setID", setId).Info("Processing add/replace of Policy set")

	// Process the policy/profile from the datastore and convert it into
	// equivalent rules which can be communicated to hns for enforcement in the
	// dataplane. We compute these rules up front and cache them to avoid needing
	// to recompute them each time the policy is applied to an endpoint. We also
	// keep track of any IP sets which were referenced by the policy/profile so that
	// we can easily tell which Policy sets are impacted when a IP set is modified.
	var rules []*hns.ACLPolicy
	var policyIpSetIds set.Set

	setMetadata := PolicySetMetadata{
		SetId: setId,
	}

	switch p := policy.(type) {
	case *proto.Policy:
		// Incoming datastore object is a Policy
		rules = s.convertPolicyToRules(setId, p.InboundRules, p.OutboundRules)
		policyIpSetIds = getReferencedIpSetIds(p.InboundRules, p.OutboundRules)
		setMetadata.Type = PolicySetTypePolicy
	case *proto.Profile:
		// Incoming datastore object is a Profile
		rules = s.convertPolicyToRules(setId, p.InboundRules, p.OutboundRules)
		policyIpSetIds = getReferencedIpSetIds(p.InboundRules, p.OutboundRules)
		setMetadata.Type = PolicySetTypeProfile
	}

	// Create the struct and store it off
	policySet := &policySet{
		PolicySetMetadata: setMetadata,
		Policy:            policy,
		Members:           set.FromArray(rules),
		IpSetIds:          policyIpSetIds,
	}
	s.policySetIdToPolicySet[setMetadata.SetId] = policySet
}

// RemovePolicySet is responsible for the removal of a Policy set
func (s *PolicySets) RemovePolicySet(setId string) {
	log.WithField("setId", setId).Info("Processing removal of Policy set")
	delete(s.policySetIdToPolicySet, setId)
}

// GetPolicySetRules receives a list of Policy set ids and it computes the complete
// set of resultant hns rules which are needed to enforce all of the Policy sets. As
// the Policy sets are processed, we increment a priority number and assign it to each rule
// from the current set. By incremening the rule priority for each set, we ensure that all of
// the sets will be enforced and considered by the dataplane in the order intended by felix.
// Once all rules are gathered, we add a final pair of rules to default deny any traffic which
// has not matched any rules from any Policy sets.
func (s *PolicySets) GetPolicySetRules(setIds []string) (rules []*hns.ACLPolicy) {
	// Rules from the first set will receive the default rule priority
	currentPriority := rulePriority

	for _, setId := range setIds {
		log.WithField("setId", setId).Debug("Gathering rules for policy set")

		policySet := s.policySetIdToPolicySet[setId]
		if policySet == nil {
			log.WithField("setId", setId).Error("Unable to find Policy set, this set will be skipped")
			continue
		}

		policySet.Members.Iter(func(item interface{}) error {
			member := item.(*hns.ACLPolicy)
			member.Priority = currentPriority
			rules = append(rules, member)
			return nil
		})

		// Increment the priority so that rules from the next set will be 'weaker' priority
		// and therefore considered only after this current set of rules has failed to match.
		currentPriority += 1
	}

	// Apply a default block rule for each direction at the end of the policy
	rules = append(rules, s.NewRule(true, currentPriority), s.NewRule(false, currentPriority))

	// Finally, for RS3 only, add default allow rules with a host-scope to allow traffic through
	// the host windows firewall
	rules = append(rules, s.NewHostRule(true), s.NewHostRule(false))

	return
}

// ProcessIpSetUpdate locates any Policy set(s) which reference the provided IP set, and causes
// those Policy sets to be recomputed (to ensure any rule address conditions are using the latest
// addres values from the IP set). A list of the Policy sets which were found and recomputed are
// is returned to the caller.
func (s *PolicySets) ProcessIpSetUpdate(ipSetId string) []string {
	log.WithField("IPSetId", ipSetId).Info("IP set has changed, looking for associated policies")
	stalePolicies := s.getPoliciesByIpSetId(ipSetId)
	if len(stalePolicies) == 0 {
		return nil
	}

	log.WithFields(log.Fields{"IPSetId": ipSetId, "Policies": stalePolicies}).Info("Associated policies need to be refreshed")
	for _, policyId := range stalePolicies {
		policySet := s.policySetIdToPolicySet[policyId]
		if policySet == nil {
			log.WithFields(log.Fields{"IPSetId": ipSetId, "Policy": policyId}).Error("Unable to find Policy set, this set will be skipped")
			continue
		}

		s.AddOrReplacePolicySet(policySet.PolicySetMetadata.SetId, policySet.Policy)
	}

	// Return the policies which were recalculated as a result of this update
	return stalePolicies
}

// getPoliciesByIpSetId locates any Policy set(s) which reference the provided IP set
func (s *PolicySets) getPoliciesByIpSetId(ipSetId string) (policies []string) {
	for policySetId, policySet := range s.policySetIdToPolicySet {
		policySet.IpSetIds.Iter(func(item interface{}) error {
			id := item.(string)
			if id == ipSetId {
				policies = append(policies, policySetId)
			}
			return nil
		})
	}
	return
}

// getReferencedIpSetIds returns all of the IP sets which are referenced by the provided
// inbound and outbound proto Rules.
func getReferencedIpSetIds(inboundRules []*proto.Rule, outboundRules []*proto.Rule) set.Set {
	var rules []*proto.Rule
	rules = append(rules, inboundRules...)
	rules = append(rules, outboundRules...)

	ipSetIds := set.New()
	for _, rule := range rules {
		ipSetIds.AddAll(rule.SrcIpSetIds)
		ipSetIds.AddAll(rule.DstIpSetIds)
	}

	return ipSetIds
}

// convertPolicyToRules converts the provided inbound and outbound proto rules into hns rules.
func (s *PolicySets) convertPolicyToRules(policyId string, inboundRules []*proto.Rule, outboundRules []*proto.Rule) (hnsRules []*hns.ACLPolicy) {
	log.WithField("policyId", policyId).Debug("ConvertPolicyToRules")

	inbound := s.protoRulesToHnsRules(policyId, inboundRules, true)
	hnsRules = append(hnsRules, inbound...)

	outbound := s.protoRulesToHnsRules(policyId, outboundRules, false)
	hnsRules = append(hnsRules, outbound...)

	for _, rule := range hnsRules {
		log.WithFields(log.Fields{"policyId": policyId, "rule": rule}).Debug("ConvertPolicyToRules final rule output")
	}

	return
}

// protoRulesToHnsRules converts a set of proto rules into hns rules.
func (s *PolicySets) protoRulesToHnsRules(policyId string, protoRules []*proto.Rule, isInbound bool) (rules []*hns.ACLPolicy) {
	log.WithField("policyId", policyId).Debug("protoRulesToHnsRules")

	for _, protoRule := range protoRules {
		hnsRules, err := s.protoRuleToHnsRules(policyId, protoRule, isInbound)
		if err != nil {
			switch err {
			case SkipRule:
				log.WithField("rule", protoRule).Info("Rule was skipped")
			default:
				log.WithField("rule", protoRule).Infof("Rule could not be converted, error: %v", err)
			}
			continue
		}
		rules = append(rules, hnsRules...)
	}

	return
}

// protoRuleToHnsRules converts a proto rule into equivalent hns rules (one or more resultant rules). For Windows RS3,
// there are a few limitations to be aware of:
//
// The following types of rules are not supported in this release and will be logged+skipped:
// Rules with: Negative match criteria, Actions other than 'allow' or 'deny', Port ranges, and ICMP type/codes.
//
func (s *PolicySets) protoRuleToHnsRules(policyId string, pRule *proto.Rule, isInbound bool) ([]*hns.ACLPolicy, error) {
	log.WithField("policyId", policyId).Debug("protoRuleToHnsRules")

	// Check IpVersion
	if pRule.IpVersion != 0 && pRule.IpVersion != proto.IPVersion(ipVersion) {
		log.WithField("rule", pRule).Info("Skipping rule because it is for an unsupported IP version.")
		return nil, SkipRule
	}

	// Skip rules with negative match criteria, these are not supported in this version
	if ruleHasNegativeMatches(pRule) {
		log.WithField("rule", pRule).Info("Skipping rule because it contains negative matches (currently unsupported).")
		return nil, SkipRule
	}

	// Skip rules with port ranges, only a single port is supported in this version
	if portsContainRanges(pRule.SrcPorts) || portsContainRanges(pRule.DstPorts) {
		log.WithField("rule", pRule).Info("Skipping rule because it contains port ranges (currently unsupported).")
		return nil, SkipRule
	}

	// Skip rules with ICMP type/codes, these are not supported
	if pRule.Icmp != nil {
		log.WithField("rule", pRule).Info("Skipping rule because it contains ICMP type or code (currently unsupported).")
		return nil, SkipRule
	}

	// Skip rules with name port ipsets
	if len(pRule.SrcNamedPortIpSetIds) > 0 || len(pRule.DstNamedPortIpSetIds) > 0 {
		log.WithField("rule", pRule).Info("Skipping rule because it contains named port ipsets (currently unsupported).")
		return nil, SkipRule
	}

	// Filter the Src and Dst CIDRs to only the IP version that we're rendering
	var filteredAll bool
	ruleCopy := *pRule

	ruleCopy.SrcNet, filteredAll = filterNets(pRule.SrcNet, ipVersion)
	if filteredAll {
		return nil, SkipRule
	}

	ruleCopy.NotSrcNet, filteredAll = filterNets(pRule.NotSrcNet, ipVersion)
	if filteredAll {
		return nil, SkipRule
	}

	ruleCopy.DstNet, filteredAll = filterNets(pRule.DstNet, ipVersion)
	if filteredAll {
		return nil, SkipRule
	}

	ruleCopy.NotDstNet, filteredAll = filterNets(pRule.NotDstNet, ipVersion)
	if filteredAll {
		return nil, SkipRule
	}

	// Log with the rule details for context
	logCxt := log.WithField("rule", ruleCopy)

	// Start with a new empty hns aclPolicy (rule)
	var aclPolicies []*hns.ACLPolicy
	aclPolicy := s.NewRule(isInbound, rulePriority)

	//
	// Action
	//
	switch strings.ToLower(ruleCopy.Action) {
	case "", "allow":
		aclPolicy.Action = hns.Allow
	case "deny":
		aclPolicy.Action = hns.Block
	case "next-tier", "pass", "log":
		logCxt.WithField("action", ruleCopy.Action).Info("This rule action is not supported, rule will be skipped")
		return nil, SkipRule
	default:
		logCxt.WithField("action", ruleCopy.Action).Panic("Unknown rule action")
	}

	//
	// Source ports
	//
	if len(ruleCopy.SrcPorts) > 0 {
		// Windows RS3 limitation, single port
		ports := uint16(ruleCopy.SrcPorts[0].First)

		if isInbound {
			aclPolicy.RemotePort = ports
			logCxt.WithField("RemotePort", aclPolicy.RemotePort).Debug("Adding Source Ports as RemotePort condition")
		} else {
			aclPolicy.LocalPort = ports
			logCxt.WithField("LocalPort", aclPolicy.LocalPort).Debug("Adding Source Ports as LocalPort condition")
		}
	}

	//
	// Destination Ports
	//
	if len(ruleCopy.DstPorts) > 0 {
		// Windows RS3 limitation, single port (start port)
		ports := uint16(ruleCopy.DstPorts[0].First)

		if isInbound {
			aclPolicy.LocalPort = ports
			logCxt.WithField("LocalPort", aclPolicy.LocalPort).Debug("Adding Destination Ports as LocalPort condition")
		} else {
			aclPolicy.RemotePort = ports
			logCxt.WithField("RemotePort", aclPolicy.RemotePort).Debug("Adding Destination Ports as RemotePort condition")
		}
	}

	//
	// Protocol
	//
	if ruleCopy.Protocol != nil {
		switch p := ruleCopy.Protocol.NumberOrName.(type) {
		case *proto.Protocol_Name:
			logCxt.WithField("protoName", p.Name).Debug("Adding Protocol Name condition")
			aclPolicy.Protocol = protocolNameToNumber(p.Name)
		case *proto.Protocol_Number:
			logCxt.WithField("protoNum", p.Number).Debug("Adding Protocol number condition")
			aclPolicy.Protocol = uint16(p.Number)
		}
	}

	//
	// Source Neworks and IPSets
	//
	localAddresses := []string{""} // ensures slice always has at least one value
	remoteAddresses := []string{""}

	srcAddresses := ruleCopy.SrcNet

	if len(ruleCopy.SrcIpSetIds) > 0 {
		ipsetAddresses, err := s.getIPSetAddresses(ruleCopy.SrcIpSetIds)
		if err != nil {
			logCxt.Info("SrcIpSetIds could not be resolved, rule will be skipped")
			return nil, SkipRule
		}
		srcAddresses = append(srcAddresses, ipsetAddresses...)
	}

	if len(srcAddresses) > 0 {
		if isInbound {
			remoteAddresses = srcAddresses
			logCxt.WithField("RemoteAddress", remoteAddresses).Debug("Adding Source Networks/IPsets as RemoteAddress conditions")
		} else {
			localAddresses = srcAddresses
			logCxt.WithField("LocalAddress", localAddresses).Debug("Adding Source Networks/IPsets as LocalAddress conditions")
		}
	}

	//
	// Destination Networks and IPSets
	//
	dstAddresses := ruleCopy.DstNet

	if len(ruleCopy.DstIpSetIds) > 0 {
		ipsetAddresses, err := s.getIPSetAddresses(ruleCopy.DstIpSetIds)
		if err != nil {
			logCxt.Info("DstIpSetIds could not be resolved, rule will be skipped")
			return nil, SkipRule
		}
		dstAddresses = append(dstAddresses, ipsetAddresses...)
	}

	if len(dstAddresses) > 0 {
		if isInbound {
			localAddresses = dstAddresses
			logCxt.WithField("LocalAddress", localAddresses).Debug("Adding Destination Networks/IPsets as LocalAddress condition")
		} else {
			remoteAddresses = dstAddresses
			logCxt.WithField("RemoteAddress", remoteAddresses).Debug("Adding Destination Networks/IPsets as RemoteAddress condition")
		}
	}

	// For Windows RS3 only, there is a dataplane restriction of a single address/cidr per
	// source or destination condition. The behavior below will be removed in
	// the next iteration, but for now we have to break up the source and destination
	// ip address combinations and represent them using multiple rules
	for _, localAddr := range localAddresses {
		for _, remoteAddr := range remoteAddresses {
			newPolicy := *aclPolicy
			newPolicy.LocalAddresses = localAddr
			newPolicy.RemoteAddresses = remoteAddr
			// Add this rule to the rules being returned
			aclPolicies = append(aclPolicies, &newPolicy)
		}
	}

	return aclPolicies, nil
}

func ruleHasNegativeMatches(pRule *proto.Rule) bool {
	if len(pRule.NotSrcNet) > 0 || len(pRule.NotDstNet) > 0 {
		return true
	}
	if len(pRule.NotSrcPorts) > 0 || len(pRule.NotDstPorts) > 0 {
		return true
	}
	if len(pRule.NotSrcIpSetIds) > 0 || len(pRule.NotDstIpSetIds) > 0 {
		return true
	}
	if len(pRule.NotSrcNamedPortIpSetIds) > 0 || len(pRule.NotDstNamedPortIpSetIds) > 0 {
		return true
	}
	if pRule.NotProtocol != nil {
		return true
	}
	if pRule.NotIcmp != nil {
		return true
	}
	return false
}

func portsContainRanges(ports []*proto.PortRange) bool {
	if len(ports) > 1 {
		return true
	}

	for _, portRange := range ports {
		if portRange.First != portRange.Last {
			return true
		}
	}
	return false
}

// getIPSetAddresses retrieves all of the ip addresses (members) referenced by the provided
// IP sets.
func (s *PolicySets) getIPSetAddresses(setIds []string) ([]string, error) {
	var addresses []string
	var found bool

	for _, ipsetId := range setIds {
		found = false
		for _, ipSets := range s.IpSets {
			ipSet := ipSets.GetIPSetMembers(ipsetId)
			if ipSet == nil {
				continue
			}
			addresses = append(addresses, ipSet...)
			found = true
			break
		}

		if !found {
			log.WithField("ipsetId", ipsetId).Info("IPSet could not be found")
			return nil, MissingSet
		}
	}

	return addresses, nil
}

// protocolNameToNumber converts a protocol name to its numeric representation (returned as string)
func protocolNameToNumber(protocolName string) uint16 {
	switch strings.ToLower(protocolName) {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	case "icmpv6":
		return 58
	case "sctp":
		return 132
	case "udplite":
		return 136
	default:
		return 256 // any (as understood by hns)
	}
}

// NewRule returns a new hns switch rule object instantiated with default values.
func (s *PolicySets) NewRule(isInbound bool, priority uint16) *hns.ACLPolicy {
	direction := hns.Out
	if isInbound {
		direction = hns.In
	}

	return &hns.ACLPolicy{
		Type:      hns.ACL,
		RuleType:  hns.Switch,
		Action:    hns.Block,
		Direction: direction,
		Protocol:  256, // Any, only required for RS3
		Priority:  priority,
	}
}

// NewHostRule returns a new hns rule object scoped to the host. This is only
// temporarily required for compatibility with RS3.
func (s *PolicySets) NewHostRule(isInbound bool) *hns.ACLPolicy {
	direction := hns.Out
	if isInbound {
		direction = hns.In
	}

	return &hns.ACLPolicy{
		Type:      hns.ACL,
		RuleType:  hns.Host,
		Action:    hns.Allow,
		Direction: direction,
		Priority:  100,
		Protocol:  256, // Any
	}
}

// filterNets filters out any addresses which are not of the requested ipVersion.
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
