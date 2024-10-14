// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package windataplane

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bits-and-blooms/bitset"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dataplane/windows/hns"
	"github.com/projectcalico/calico/felix/dataplane/windows/policysets"
	"github.com/projectcalico/calico/felix/iputils"
)

func flattenTiers(tiers [][]*hns.ACLPolicy) []*hns.ACLPolicy {
	if len(tiers) == 0 {
		log.Panic("Ran out of rules")
	}

	if log.GetLevel() >= log.DebugLevel {
		for i, t := range tiers {
			for _, rule := range t {
				log.WithFields(log.Fields{"rule": rule}).Infof("flattener: tier %d", i)
			}
		}
	}

	lastTier := tiers[len(tiers)-1]
	log.Debugf("flattener: last tier is %+v", lastTier)
	if log.GetLevel() >= log.DebugLevel {
		for _, rule := range lastTier {
			log.WithFields(log.Fields{"rule": rule}).Info("flattener: lastTier")
		}
	}
	// For last tier, no further flattening is required.
	// However, there could still be rules with `pass` action
	// which should be `passed` to `default-deny`. Pre-process
	// last tier before running flattenTiersRecurse.
	for _, r := range lastTier {
		if r.Action == policysets.ActionPass {
			log.Debug("flattener: setting pass rules in last tier to block")
			r.Action = hns.Block
		}
	}

	return flattenTiersRecurse(tiers)
}

func flattenTiersRecurse(tiers [][]*hns.ACLPolicy) []*hns.ACLPolicy {
	if len(tiers) == 0 {
		log.Panic("Ran out of rules")
	}
	if len(tiers) == 1 {
		log.Debugf("flattener: only 1 tier, returning it: %v", tiers[0])
		return tiers[0]
	}

	foundPass := false

	oldFirstTier := tiers[0]
	log.Debugf("flattener: old first tier: %+v", oldFirstTier)
	if log.GetLevel() >= log.DebugLevel {
		for _, rule := range oldFirstTier {
			log.WithFields(log.Fields{"rule": rule}).Debug("flattener: old first tier")
		}
	}

	var newFirstTier []*hns.ACLPolicy

	log.Debugf("flattener: loop through rules of old first tier")
	for _, r := range oldFirstTier {
		if r.Action == policysets.ActionPass {
			log.Debugf("flattener: found pass rule in old first tier: %+v", r)
			foundPass = true
			oldSecondTier := tiers[1]
			newFirstTier = appendCombinedRules(newFirstTier, oldSecondTier, r)
		} else {
			newFirstTier = append(newFirstTier, r)
		}
	}

	if !foundPass {
		// There are further tiers but no pass actions so it's impossible to get there.
		log.Debug("flattener: further tiers but no pass rules found, returning old first tier")
		return oldFirstTier
	}

	// We've now coalesced the first and second tiers.
	tiers = tiers[1:]
	tiers[0] = newFirstTier

	return flattenTiersRecurse(tiers)
}

func appendCombinedRules(newRules []*hns.ACLPolicy, secondTier []*hns.ACLPolicy, rule *hns.ACLPolicy) []*hns.ACLPolicy {
	for _, r := range secondTier {
		combinedRule := combineRules(rule, r)
		if combinedRule == nil {
			// Rule would be a no-op
			continue
		}
		newRules = append(newRules, combinedRule)
	}

	return newRules
}

// Calculates r1 && r2 and uses the action/ID from r2.
func combineRules(r1, r2 *hns.ACLPolicy) *hns.ACLPolicy {
	combined := *r2

	if r1.Protocol != 256 {
		if r2.Protocol == 256 {
			combined.Protocol = r1.Protocol
		} else if r1.Protocol != r2.Protocol {
			return nil
		}
	}
	var err error
	combined.LocalAddresses, err = combineCIDRs(r1.LocalAddresses, r2.LocalAddresses)
	if err == policysets.ErrRuleIsNoOp {
		return nil
	}
	combined.RemoteAddresses, err = combineCIDRs(r1.RemoteAddresses, r2.RemoteAddresses)
	if err == policysets.ErrRuleIsNoOp {
		return nil
	}

	combined.LocalPorts, err = combinePorts(r1.LocalPorts, r2.LocalPorts)
	if err == policysets.ErrRuleIsNoOp {
		return nil
	}
	combined.RemotePorts, err = combinePorts(r1.RemotePorts, r2.RemotePorts)
	if err == policysets.ErrRuleIsNoOp {
		return nil
	}

	return &combined
}

func combinePorts(as string, bs string) (string, error) {
	if len(as) == 0 {
		return bs, nil
	}
	if len(bs) == 0 {
		return as, nil
	}

	aBitset := parsePorts(as)
	bBitset := parsePorts(bs)

	aBitset.InPlaceIntersection(bBitset)
	if aBitset.Len() == 0 {
		return "", policysets.ErrRuleIsNoOp
	}

	i := uint(0)
	var outPorts []string
	for {
		startOfRange, valid := aBitset.NextSet(i)
		if !valid {
			break
		}

		afterEndOfRange, valid := aBitset.NextClear(startOfRange + 1)
		if !valid {
			panic("bitset said no end of range")
		}
		endOfRange := afterEndOfRange - 1

		if startOfRange == endOfRange {
			outPorts = append(outPorts, fmt.Sprint(startOfRange))
		} else {
			outPorts = append(outPorts, fmt.Sprintf("%d-%d", startOfRange, endOfRange))
		}

		i = afterEndOfRange + 1
	}

	return strings.Join(outPorts, ","), nil
}

func parsePorts(portsStr string) *bitset.BitSet {
	setOfPorts := bitset.New(2 ^ 16 + 1)
	for _, p := range strings.Split(portsStr, ",") {
		if strings.Contains(p, "-") {
			// Range
			parts := strings.Split(p, "-")
			low, err := strconv.Atoi(parts[0])
			if err != nil {
				panic(err)
			}
			high, err := strconv.Atoi(parts[1])
			if err != nil {
				panic(err)
			}
			for port := low; port <= high; port++ {
				setOfPorts.Set(uint(port))
			}
		} else {
			// Single value
			port, err := strconv.Atoi(p)
			if err != nil {
				panic(err)
			}
			setOfPorts.Set(uint(port))
		}
	}
	return setOfPorts
}

func combineCIDRs(as, bs string) (string, error) {
	if len(as) == 0 {
		return bs, nil
	}
	if len(bs) == 0 {
		return as, nil
	}

	combined := strings.Join(
		iputils.IntersectCIDRs(
			strings.Split(as, ","),
			strings.Split(bs, ",")),
		",",
	)
	if combined == "" {
		return "", policysets.ErrRuleIsNoOp
	}
	return combined, nil
}

func rewritePriorities(policies []*hns.ACLPolicy, limit uint16) {
	if len(policies) <= 1 {
		return
	}

	currentPriority := policysets.PolicyRuleBasePriority
	policies[0].Priority = currentPriority
	lastRule := policies[0]

	// Determine if we should always increment the rule priority.
	// If the number of rules exceeds the max allowed priority (subtracting
	// the base priority) then we assign the same priority to groups of
	// rules that have the same direction and action.
	alwaysIncrementPriority := len(policies) < int(limit-currentPriority)

	if alwaysIncrementPriority {
		for i := 1; i < len(policies); i++ {
			currentPriority++
			policies[i].Priority = currentPriority
		}
	} else {
		for i := 1; i < len(policies); i++ {
			if lastRule.Action != policies[i].Action {
				currentPriority++
			}

			policies[i].Priority = currentPriority
			lastRule = policies[i]
		}
	}
}
