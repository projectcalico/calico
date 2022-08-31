// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/iputils"

	"github.com/projectcalico/calico/felix/dataplane/windows/hns"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// IPSetCache is our interface to the IP sets tracker.
type IPSetCache interface {
	GetIPSetMembers(ipsetID string) []string
}

// HNSAPI in an interface containing only the parts of the HNS API that we use here.
type HNSAPI interface {
	GetHNSSupportedFeatures() hns.HNSSupportedFeatures
}

// PolicySets manages a whole plane of policies/profiles
type PolicySets struct {
	IpSets []IPSetCache

	supportedFeatures      hns.HNSSupportedFeatures
	policySetIdToPolicySet map[string]*policySet

	// staticACLRules contains the list of static endpoint ACL rules.
	staticACLRules []*hns.ACLPolicy
}

func NewPolicySets(hns HNSAPI, ipsets []IPSetCache, reader StaticRulesReader) *PolicySets {
	supportedFeatures := hns.GetHNSSupportedFeatures()
	return &PolicySets{
		policySetIdToPolicySet: map[string]*policySet{},

		IpSets:            ipsets,
		supportedFeatures: supportedFeatures,
		staticACLRules:    readStaticRules(reader),
	}
}

// AddOrReplacePolicySet is responsible for the creation (or replacement) of a Policy set
// and it is capable of processing either Profiles or Policies from the datastore.
func (s *PolicySets) AddOrReplacePolicySet(setId string, policy interface{}) {
	log.WithField("setID", setId).Info("Processing add/replace of Policy set")

	// Process the policy/profile from the datastore and convert it into
	// equivalent rules which can be communicated to HNS for enforcement in the
	// dataplane. We compute these rules up front and cache them to avoid needing
	// to recompute them each time the policy is applied to an endpoint. We also
	// keep track of any IP sets which were referenced by the policy/profile so that
	// we can easily tell which Policy sets are impacted when a IP set is modified.
	var rules []*hns.ACLPolicy
	var policyIpSetIds set.Set[string]

	setMetadata := PolicySetMetadata{
		SetId: setId,
	}

	switch p := policy.(type) {
	case *proto.Policy:
		// Incoming datastore object is a Policy
		log.Debug("Policy set represents a Policy")
		rules = s.convertPolicyToRules(setId, p.InboundRules, p.OutboundRules)
		policyIpSetIds = getReferencedIpSetIds(p.InboundRules, p.OutboundRules)
		setMetadata.Type = PolicySetTypePolicy
	case *proto.Profile:
		// Incoming datastore object is a Profile
		log.Debug("Policy set represents a Profile")
		rules = s.convertPolicyToRules(setId, p.InboundRules, p.OutboundRules)
		policyIpSetIds = getReferencedIpSetIds(p.InboundRules, p.OutboundRules)
		setMetadata.Type = PolicySetTypeProfile
	default:
		log.WithField("policySet", p).Error("BUG: Unknown type of policy")
		return
	}

	// Create the struct and store it off
	policySet := &policySet{
		PolicySetMetadata: setMetadata,
		Policy:            policy,
		Members:           rules,
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
// set of resultant HNS rules that are needed to enforce all of the Policy sets for the
// specified direction.
func (s *PolicySets) GetPolicySetRules(setIds []string, isInbound bool) (rules []*hns.ACLPolicy) {
	// Rules from the first set will receive the default rule priority
	currentPriority := PolicyRuleBasePriority

	direction := hns.Out
	if isInbound {
		direction = hns.In
	}

	debug := log.GetLevel() >= log.DebugLevel

	// Append static rules first.
	for _, r := range s.staticACLRules {
		if r.Direction == direction {
			rules = append(rules, r)
		}
	}

	var lastRule *hns.ACLPolicy
	for _, setId := range setIds {
		if debug {
			log.WithFields(log.Fields{"setId": setId, "isInbound": isInbound}).Debug(
				"Gathering per-direction rules for policy set")
		}

		policySet := s.policySetIdToPolicySet[setId]
		if policySet == nil {
			log.WithField("setId", setId).Error("Unable to find Policy set, replacing with a deny rule")
			break
		}

		for _, member := range policySet.Members {
			if member.Direction != direction {
				continue
			}

			if lastRule != nil && lastRule.Action != member.Action {
				// If we write two HNS rules at the same priority, HNS has a different tie-break algorithm
				// to Calico.  Hence, to get Calico's first-rule-wins behaviour we need to increment the priority
				// between rules that it's not safe to re-order.  It's certainly not safe to re-order rules
				// that have different actions.
				currentPriority += 1
				if debug {
					log.Debugf("Switching from %v to %v, incremented priority to %v",
						lastRule.Action, member.Action, currentPriority)
				}
			}

			// Take a copy so we can mutate the priority.
			memberCopy := *member
			memberCopy.Priority = currentPriority
			rules = append(rules, &memberCopy)

			lastRule = &memberCopy
		}
	}

	// Apply a default block rule for this direction at the end of the policy
	currentPriority++
	rules = append(rules, s.NewRule(isInbound, currentPriority))

	// Finally, for RS3 only, add default allow rule with a host-scope to allow traffic through
	// the host windows firewall
	rules = append(rules, s.NewHostRule(isInbound))

	return
}

// ProcessIpSetUpdate locates any Policy set(s) which reference the provided IP set, and causes
// those Policy sets to be recomputed (to ensure any rule address conditions are using the latest
// address values from the IP set). A list of the Policy sets which were found and recomputed are
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
		policySet.IpSetIds.Iter(func(id string) error {
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
func getReferencedIpSetIds(inboundRules []*proto.Rule, outboundRules []*proto.Rule) set.Set[string] {
	var rules []*proto.Rule
	rules = append(rules, inboundRules...)
	rules = append(rules, outboundRules...)

	ipSetIds := set.New[string]()
	for _, rule := range rules {
		ipSetIds.AddAll(rule.SrcIpSetIds)
		ipSetIds.AddAll(rule.DstIpSetIds)
		ipSetIds.AddAll(rule.DstIpPortSetIds)
	}

	return ipSetIds
}

// convertPolicyToRules converts the provided inbound and outbound proto rules into hns rules.
func (s *PolicySets) convertPolicyToRules(policyId string, inboundRules []*proto.Rule, outboundRules []*proto.Rule) (hnsRules []*hns.ACLPolicy) {
	log.WithField("policyId", policyId).Debug("Converting policy to HNS rules.")

	inbound := s.protoRulesToHnsRules(policyId, inboundRules, true)
	hnsRules = append(hnsRules, inbound...)

	outbound := s.protoRulesToHnsRules(policyId, outboundRules, false)
	hnsRules = append(hnsRules, outbound...)

	if log.GetLevel() >= log.DebugLevel {
		for _, rule := range hnsRules {
			log.WithFields(log.Fields{"policyId": policyId, "rule": rule}).Debug("ConvertPolicyToRules final rule output")
		}
	}

	return
}

// protoRulesToHnsRules converts a set of proto rules into HNS rules.
func (s *PolicySets) protoRulesToHnsRules(policyId string, protoRules []*proto.Rule, isInbound bool) (rules []*hns.ACLPolicy) {
	log.WithField("policyId", policyId).Debug("protoRulesToHnsRules")
	const ipPortsPerRule = 4000
	for _, protoRule := range protoRules {
		hnsRules, err := s.protoRuleToHnsRules(policyId, protoRule, isInbound, ipPortsPerRule)
		if err != nil {
			switch err {
			case ErrNotSupported:
				log.WithField("rule", protoRule).Warn("Skipped rule because it's not supported on Windows.")
			case ErrRuleIsNoOp:
				// For example, an IPv6 rule on IPv4.
				log.WithField("rule", protoRule).Debug("Skipping no-op rule.")
				continue
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
// Rules with: Negative match criteria, Actions other than 'allow' or 'deny'and ICMP type/codes.
//
func (s *PolicySets) protoRuleToHnsRules(policyId string, pRule *proto.Rule, isInbound bool, ipPortsPerRule int) ([]*hns.ACLPolicy, error) {
	log.WithField("policyId", policyId).Debug("protoRuleToHnsRules")

	// Check IpVersion
	if pRule.IpVersion != 0 && pRule.IpVersion != proto.IPVersion(ipVersion) {
		log.WithField("rule", pRule).Info("Skipping rule because it is for an unsupported IP version.")
		return nil, ErrNotSupported
	}

	// Skip rules with negative match criteria, these are not supported in this version
	if ruleHasNegativeMatches(pRule) {
		log.WithField("rule", pRule).Info("Skipping rule because it contains negative matches (currently unsupported).")
		return nil, ErrNotSupported
	}

	// Skip rules with ICMP type/codes, these are not supported
	if pRule.Icmp != nil {
		log.WithField("rule", pRule).Info("Skipping rule because it contains ICMP type or code (currently unsupported).")
		return nil, ErrNotSupported
	}

	// Skip rules with name port ipsets
	if len(pRule.SrcNamedPortIpSetIds) > 0 || len(pRule.DstNamedPortIpSetIds) > 0 {
		log.WithField("rule", pRule).Info("Skipping rule because it contains named port ipsets (currently unsupported).")
		return nil, ErrNotSupported
	}

	// Filter the Src and Dst CIDRs to only the IP version that we're rendering
	var filteredAll bool
	ruleCopy := *pRule

	ruleCopy.SrcNet, filteredAll = filterNets(pRule.SrcNet, ipVersion)
	if filteredAll {
		return nil, ErrRuleIsNoOp
	}

	ruleCopy.NotSrcNet, filteredAll = filterNets(pRule.NotSrcNet, ipVersion)
	if filteredAll {
		return nil, ErrRuleIsNoOp
	}

	ruleCopy.DstNet, filteredAll = filterNets(pRule.DstNet, ipVersion)
	if filteredAll {
		return nil, ErrRuleIsNoOp
	}

	ruleCopy.NotDstNet, filteredAll = filterNets(pRule.NotDstNet, ipVersion)
	if filteredAll {
		return nil, ErrRuleIsNoOp
	}

	// Log with the rule details for context
	logCxt := log.WithField("rule", ruleCopy)

	// Start with a new empty hns aclPolicy (rule)
	var aclPolicies []*hns.ACLPolicy
	aclPolicy := s.NewRule(isInbound, PolicyRuleBasePriority)

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
		return nil, ErrNotSupported
	default:
		logCxt.WithField("action", ruleCopy.Action).Panic("Unknown rule action")
	}

	//
	// DstIpPort sets - these cannot co-exist with other fields, so do them first and short-circuit if set.
	//
	if len(ruleCopy.DstIpPortSetIds) > 0 {
		ipsetMembers, err := s.getIPSetAddresses(ruleCopy.DstIpPortSetIds)
		if err != nil {
			logCxt.Warn("DstIpPortSetIds could not be resolved, rule will be skipped")
			return nil, err
		}

		parseIPPortMember := func(m string) (string, uint16, string) {
			// Split out address.
			splits := strings.Split(m, ",")
			addr := splits[0]
			protoPort := splits[1]

			// Split port and protocol.
			splits = strings.Split(protoPort, ":")
			protocol := protocolNameToNumber(splits[0])
			port := splits[1]
			return addr, protocol, port
		}

		// Each member includes both an address and a port.
		// However, we can combine all addresses across all members that share the same proto+port into a single rule.
		type policyMembers struct {
			proto uint16
			port  string
			addrs []string
		}

		// We need to consolidate addrs based on ports/protocols, so use a map to lookup.
		membersByPort := map[string]*policyMembers{}

		// We need to ensure the ordering of generated rules is deterministic, so use a slice.
		orderedPolicyMembers := []*policyMembers{}
		for _, m := range ipsetMembers {
			// The member should be of the format <IP>,(tcp|udp):<port number>
			addr, proto, port := parseIPPortMember(m)
			var pm *policyMembers
			pm = membersByPort[fmt.Sprintf("%d/%s", proto, port)]
			if pm == nil {
				pm = &policyMembers{proto: proto, port: port}
				membersByPort[fmt.Sprintf("%d/%s", proto, port)] = pm
				orderedPolicyMembers = append(orderedPolicyMembers, pm)
			}
			pm.addrs = append(pm.addrs, addr)
		}

		for i, m := range orderedPolicyMembers {
			newPolicy := *aclPolicy
			newPolicy.RemoteAddresses = strings.Join(m.addrs, ",")
			newPolicy.RemotePorts = m.port
			newPolicy.Protocol = m.proto
			if s.supportedFeatures.Acl.AclRuleId {
				newPolicy.Id = fmt.Sprintf("%s-%s-%d", policyId, ruleCopy.RuleId, i)
			}
			aclPolicies = append(aclPolicies, &newPolicy)
		}

		// DstIpPortSetIds are mutually exclusive with other fields - if specified, then no other rule match criteria can be.
		// The API validates against this, so simply return here.
		return aclPolicies, nil
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
	// Source Networks and IPSets
	//
	var localAddresses []string
	var remoteAddresses []string

	srcAddresses := ruleCopy.SrcNet

	if len(ruleCopy.SrcIpSetIds) > 0 {
		ipsetAddresses, err := s.getIPSetAddresses(ruleCopy.SrcIpSetIds)
		if err != nil {
			logCxt.Warn("SrcIpSetIds could not be resolved, rule will be skipped")
			return nil, err
		}

		if len(srcAddresses) > 0 {
			// We have both CIDRs in the rule and an IPset.  Our model is that each match criteria should be ANDed
			// together so that means that we need to intersect the CIDRs with the IP set addresses.
			logCxt.Debug("Both source CIDRs and IPsets in rule, intersecting them")
			srcAddresses = iputils.IntersectCIDRs(srcAddresses, ipsetAddresses)
			if len(srcAddresses) == 0 {
				logCxt.Debug("No overlap between source CIDRs and IPsets, skipping rule")
				return nil, ErrRuleIsNoOp
			}
		} else {
			srcAddresses = ipsetAddresses
		}
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
			logCxt.Warn("DstIpSetIds could not be resolved, rule will be skipped")
			return nil, err
		}

		if len(dstAddresses) > 0 {
			// We have both CIDRs in the rule and an IPset.  Our model is that each match criteria should be ANDed
			// together so that means that we need to intersect the CIDRs with the IP set addresses.
			logCxt.Debug("Both dest CIDRs and IPsets in rule, intersecting them")
			dstAddresses = iputils.IntersectCIDRs(dstAddresses, ipsetAddresses)
			if len(dstAddresses) == 0 {
				logCxt.Debug("No overlap between dest CIDRs and IPsets, skipping rule")
				return nil, ErrRuleIsNoOp
			}
		} else {
			dstAddresses = ipsetAddresses
		}
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

	// Windows RS4+ supports multiple CIDRs and port ranges in a rule but Microsoft recommended
	// limiting the number of entries per rule to a few thousand(say 4000 for now).
	// Break up larger sets of ports/CIDRs into chunks and render one rule for each combination
	var remotePortChunks [][]*proto.PortRange
	var localPortChunks [][]*proto.PortRange
	i := 0
	debug := log.GetLevel() >= log.DebugLevel

	localAddrChunks := SplitIPList(localAddresses, ipPortsPerRule)
	remoteAddrChunks := SplitIPList(remoteAddresses, ipPortsPerRule)
	// assign src/dstPortsChunks based on traffic direction
	if isInbound {
		remotePortChunks = SplitPortList(pRule.SrcPorts, ipPortsPerRule)
		localPortChunks = SplitPortList(pRule.DstPorts, ipPortsPerRule)
	} else {
		localPortChunks = SplitPortList(pRule.SrcPorts, ipPortsPerRule)
		remotePortChunks = SplitPortList(pRule.DstPorts, ipPortsPerRule)
	}

	for _, localAddr := range localAddrChunks {
		localAddrs := strings.Join(localAddr, ",")

		// iterate loop for each chunk of source port and append them in aclpolicy
		for _, lPorts := range localPortChunks {
			localPorts := appendPortsinList(lPorts)

			for _, remoteAddr := range remoteAddrChunks {
				remoteAddrs := strings.Join(remoteAddr, ",")

				// iterate loop for each chunk of destination port and append them in aclpolicy
				for _, rPorts := range remotePortChunks {
					remotePorts := appendPortsinList(rPorts)

					newPolicy := *aclPolicy
					// Give each sub-rule a unique ID.
					if s.supportedFeatures.Acl.AclRuleId {
						newPolicy.Id = fmt.Sprintf("%s-%s-%d", policyId, ruleCopy.RuleId, i)
						i++
					}
					// assign ports chunks in aclpolicy
					newPolicy.LocalPorts = localPorts
					newPolicy.RemotePorts = remotePorts
					// assign addresses chunks in aclpolicy
					newPolicy.LocalAddresses = localAddrs
					newPolicy.RemoteAddresses = remoteAddrs
					// Add this rule to the rules being returned
					if debug {
						log.WithField("rule", newPolicy).Debug("Expanded rule for local/remote addr.")
					}
					aclPolicies = append(aclPolicies, &newPolicy)
				}
			}
		}
	}

	return aclPolicies, nil
}

func appendPortsinList(dPorts []*proto.PortRange) (listPorts string) {
	dstPorts := make([]string, len(dPorts))
	for ii, port := range dPorts {
		dstPorts[ii] = protoPortToHCSPort(port)
	}
	listPorts = strings.Join(dstPorts, ",")
	return
}

// convert proto.PortRange format port into HCS format port
func protoPortToHCSPort(port *proto.PortRange) string {
	portNum := ""
	if port.First == port.Last {
		portNum = fmt.Sprintf("%d", port.First)
	} else {
		portNum = fmt.Sprintf("%d-%d", port.First, port.Last)
	}
	return portNum
}

// This function will create chunks of ports/ports range with chunksize
func SplitPortList(ports []*proto.PortRange, chunkSize int) (splits [][]*proto.PortRange) {

	if len(ports) == 0 {
		splits = append(splits, []*proto.PortRange{})
	}
	for i := 0; i < len(ports); i += chunkSize {
		last := i + chunkSize

		if last > len(ports) {
			last = len(ports)
		}

		splits = append(splits, ports[i:last])
	}
	return
}

// This function will create chunks of IP addresses/Cidr with chunksize
func SplitIPList(ipAddrs []string, chunkSize int) (splits [][]string) {

	if len(ipAddrs) == 0 {
		splits = append(splits, []string{})
	}
	for i := 0; i < len(ipAddrs); i += chunkSize {
		last := i + chunkSize

		if last > len(ipAddrs) {
			last = len(ipAddrs)
		}

		splits = append(splits, ipAddrs[i:last])
	}

	return
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
			return nil, ErrMissingIPSet
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

// NewRule returns a new HNS switch rule object instantiated with default values.
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

// NewHostRule returns a new hns rule object scoped to the host.
func (s *PolicySets) NewHostRule(isInbound bool) *hns.ACLPolicy {
	direction := hns.Out
	if isInbound {
		direction = hns.In
	}

	var priority uint16 = 0

	if !s.supportedFeatures.Acl.AclNoHostRulePriority {
		log.Debugf("This HNS version requires host rule priority to be specified. Adding priority=100 to Host rules.")
		priority = 100
	}

	return &hns.ACLPolicy{
		Type:      hns.ACL,
		RuleType:  hns.Host,
		Action:    hns.Allow,
		Direction: direction,
		Protocol:  256, // Any
		Priority:  priority,
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
