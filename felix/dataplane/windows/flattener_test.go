// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package windataplane

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/dataplane/windows/hns"
	"github.com/projectcalico/calico/felix/dataplane/windows/policysets"
)

func TestFlatten(t *testing.T) {
	RegisterTestingT(t)

	t.Log("Should have no effect on a single tier with no pass rules.")
	rule1 := []*hns.ACLPolicy{
		{Protocol: 256, Action: hns.Block},
		{Protocol: 256, Action: hns.Block},
	}
	tier1 := makeTier(rule1)
	verifyFlatTier([]tierInfo{tier1}, tier1)

	t.Log("Should discard unreachable tiers")
	verifyFlatTier([]tierInfo{tier1, tier1}, tier1)

	t.Log("Should expand a pass rule")
	rulesWithPass := []*hns.ACLPolicy{
		{Protocol: 256, Action: policysets.ActionPass},
		{Protocol: 100, Action: hns.Block},
		{Protocol: 100, Action: hns.Block},
	}
	tierWithPass := makeTier(rulesWithPass)
	expectedRules := []*hns.ACLPolicy{
		// tier1
		{Protocol: 256, Action: hns.Block},
		{Protocol: 256, Action: hns.Block},
		// Remainder of tierWithPass
		{Protocol: 100, Action: hns.Block},
		{Protocol: 100, Action: hns.Block},
	}
	expectedTier := makeTier(expectedRules)
	verifyFlatTier([]tierInfo{tierWithPass, tier1}, expectedTier)

	t.Log("Should combine protocol=any with a specific protocol")
	rules1 := []*hns.ACLPolicy{
		{Protocol: 256, Action: policysets.ActionPass},
	}
	tier1 = makeTier(rules1)
	rules2 := []*hns.ACLPolicy{
		{Protocol: 10, Action: hns.Allow},
	}
	tier2 := makeTier(rules2)
	expectedRules = []*hns.ACLPolicy{
		{Protocol: 10, Action: hns.Allow},
	}
	expectedTier = makeTier(expectedRules)
	verifyFlatTier([]tierInfo{tier1, tier2}, expectedTier)

	t.Log("Should combine CIDRs")
	rules1 = []*hns.ACLPolicy{
		{Action: policysets.ActionPass, LocalAddresses: "10.0.0.0/16"},
		{Action: policysets.ActionPass, LocalAddresses: "10.0.10.0/26"},
	}
	tier1 = makeTier(rules1)
	rules2 = []*hns.ACLPolicy{
		{Action: hns.Allow, LocalAddresses: "10.0.10.0/24"},
	}
	tier2 = makeTier(rules2)
	expectedRules = []*hns.ACLPolicy{
		{Action: hns.Allow, LocalAddresses: "10.0.10.0/24"},
		{Action: hns.Allow, LocalAddresses: "10.0.10.0/26"},
	}
	expectedTier = makeTier(expectedRules)
	verifyFlatTier([]tierInfo{tier1, tier2}, expectedTier)

	t.Log("Should combine another CIDRs")
	rules1 = []*hns.ACLPolicy{
		{Action: policysets.ActionPass, RemoteAddresses: "10.0.0.0/16,11.0.0.0/24"},
		{Action: policysets.ActionPass, RemoteAddresses: "10.0.10.0/26"},
	}
	tier1 = makeTier(rules1)
	rules2 = []*hns.ACLPolicy{
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24,11.0.0.0/8"},
		{Action: hns.Allow, RemoteAddresses: "12.0.0.0/8"},
		{Action: hns.Allow, LocalAddresses: "12.0.0.0/8"},
	}
	tier2 = makeTier(rules2)
	expectedRules = []*hns.ACLPolicy{
		// First pass rule
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24,11.0.0.0/24"},
		{Action: hns.Allow,
			RemoteAddresses: "10.0.0.0/16,11.0.0.0/24",
			LocalAddresses:  "12.0.0.0/8"},
		// Second pass rule
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/26"},
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/26", LocalAddresses: "12.0.0.0/8"},
	}
	expectedTier = makeTier(expectedRules)
	verifyFlatTier([]tierInfo{tier1, tier2}, expectedTier)
	/*Expect(flattenTiers([][]*hns.ACLPolicy{
		{
			{Action: policysets.ActionPass, RemoteAddresses: "10.0.0.0/16,11.0.0.0/24"},
			{Action: policysets.ActionPass, RemoteAddresses: "10.0.10.0/26"},
		},
		{
			{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24,11.0.0.0/8"},
			{Action: hns.Allow, RemoteAddresses: "12.0.0.0/8"},
			{Action: hns.Allow, LocalAddresses: "12.0.0.0/8"},
		},
	})).To(Equal([]*hns.ACLPolicy{
		// First pass rule
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24,11.0.0.0/24",
		{Action: hns.Allow,
			RemoteAddresses: "10.0.0.0/16,11.0.0.0/24",
			LocalAddresses:  "12.0.0.0/8"},
		// Second pass rule
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/26"},
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/26", LocalAddresses: "12.0.0.0/8"},
	}))*/

	/*t.Log("Should combine Ports")
	Expect(flattenTiers([][]*hns.ACLPolicy{
		{
			{Action: policysets.ActionPass, LocalPorts: "1,2,10-15"},
			{Action: policysets.ActionPass, LocalPorts: "10-15"},
		},
		{{Action: hns.Allow, LocalPorts: "2,12-16,55"}},
	})).To(Equal([]*hns.ACLPolicy{
		{Action: hns.Allow, LocalPorts: "2,12-15"},
		{Action: hns.Allow, LocalPorts: "12-15"},
	}))
	Expect(flattenTiers([][]*hns.ACLPolicy{
		{
			{Action: policysets.ActionPass, RemotePorts: "1,2,10-15"},
			{Action: policysets.ActionPass, RemotePorts: "10-15"},
		},
		{{Action: hns.Allow, RemotePorts: "2,12-16,55"}},
	})).To(Equal([]*hns.ACLPolicy{
		{Action: hns.Allow, RemotePorts: "2,12-15"},
		{Action: hns.Allow, RemotePorts: "12-15"},
	}))

	t.Log("Should recurse with non-overlapping pass on second tier")
	Expect(flattenTiers([][]*hns.ACLPolicy{
		{
			{Action: policysets.ActionPass, RemoteAddresses: "10.0.0.0/16,11.0.0.0/24"},
			{Action: policysets.ActionPass, RemoteAddresses: "10.0.10.0/26"},
		},
		{{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24,11.0.0.0/8"},
			{Action: policysets.ActionPass, RemoteAddresses: "12.0.0.0/8"},
			{Action: hns.Allow, LocalAddresses: "12.0.0.0/8"},
		},
		{
			{Action: hns.Allow, RemoteAddresses: "10.0.11.0/28"},
			{Action: hns.Block, RemoteAddresses: "10.0.10.0/28"},
		},
	})).To(Equal([]*hns.ACLPolicy{
		// First pass rule
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24,11.0.0.0/24"},
		{Action: hns.Allow, RemoteAddresses: "10.0.0.0/16,11.0.0.0/24", LocalAddresses: "12.0.0.0/8"},
		// Second pass rule
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/26"},
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/26", LocalAddresses: "12.0.0.0/8"},
	}))

	t.Log("Should recurse with overlapping pass on second tier")
	Expect(flattenTiers([][]*hns.ACLPolicy{
		{
			{Action: policysets.ActionPass, RemoteAddresses: "10.0.0.0/16,11.0.0.0/24"},
			{Action: policysets.ActionPass, RemoteAddresses: "10.0.10.0/26"},
		},
		{{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24,11.0.0.0/8"},
			{Action: policysets.ActionPass, RemoteAddresses: "10.0.10.0/24"},
			{Action: hns.Allow, LocalAddresses: "12.0.0.0/8"},
		},
		{
			{Action: hns.Allow, RemoteAddresses: "10.0.11.0/28"},
			{Action: hns.Block, RemoteAddresses: "10.0.10.0/28"},
		},
	})).To(Equal([]*hns.ACLPolicy{
		// First pass rule
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24,11.0.0.0/24"},
		{Action: hns.Block, RemoteAddresses: "10.0.10.0/28"},
		{Action: hns.Allow, RemoteAddresses: "10.0.0.0/16,11.0.0.0/24", LocalAddresses: "12.0.0.0/8"},
		// Second pass rule
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/26"},
		{Action: hns.Block, RemoteAddresses: "10.0.10.0/28"},
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/26", LocalAddresses: "12.0.0.0/8"},
	}))

	t.Log("Should block with pass in last tier")
	Expect(flattenTiers([][]*hns.ACLPolicy{
		{
			{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24", LocalPorts: "6000"},
			{Action: policysets.ActionPass, RemoteAddresses: "10.0.10.0/24"},
		},
		{
			{Action: hns.Block, RemoteAddresses: "10.0.10.1/32", LocalPorts: "6379"},
			{Action: policysets.ActionPass, RemoteAddresses: "10.0.10.2/32", LocalPorts: "6380, 6381"},
			{Action: hns.Block, RemoteAddresses: "10.0.0.0/8", LocalPorts: "6390-6400"},
		},
	})).To(Equal([]*hns.ACLPolicy{
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24", LocalPorts: "6000"},
		{Action: hns.Block, RemoteAddresses: "10.0.10.1/32", LocalPorts: "6379"},
		{Action: hns.Block, RemoteAddresses: "10.0.10.2/32", LocalPorts: "6380, 6381"},
		{Action: hns.Block, RemoteAddresses: "10.0.10.0/24", LocalPorts: "6390-6400"},
	}))

	t.Log("Should pass to last tier which has only the rule from the profile")
	Expect(flattenTiers([][]*hns.ACLPolicy{
		{
			{Action: hns.Block, RemoteAddresses: "192.168.1.123/32", LocalPorts: "8080"},
			{Action: policysets.ActionPass},
		},
		{
			// This would be the allow rule added for the profile.
			{Action: hns.Allow, Protocol: 256},
		},
	})).To(Equal([]*hns.ACLPolicy{
		{Action: hns.Block, RemoteAddresses: "192.168.1.123/32", LocalPorts: "8080"},
		{Action: hns.Allow},
	}))*/
}

func TestReWritePriority(t *testing.T) {
	RegisterTestingT(t)

	t.Log("Should write incrementing priority")
	policies := []*hns.ACLPolicy{
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24", Priority: 1000},
		{Action: hns.Allow, RemoteAddresses: "10.0.11.0/24", Priority: 1001},
		{Action: hns.Block, RemoteAddresses: "10.0.12.0/24", Priority: 1002},
		{Action: hns.Block, RemoteAddresses: "10.0.13.0/24", Priority: 1003},
	}

	rewritePriorities(policies, policysets.PolicyRuleMaxPriority)
	Expect(policies).To(Equal([]*hns.ACLPolicy{
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24", Priority: 1000},
		{Action: hns.Allow, RemoteAddresses: "10.0.11.0/24", Priority: 1001},
		{Action: hns.Block, RemoteAddresses: "10.0.12.0/24", Priority: 1002},
		{Action: hns.Block, RemoteAddresses: "10.0.13.0/24", Priority: 1003},
	}))

	t.Log("Should write aggregated priority")
	policies = []*hns.ACLPolicy{
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24", Priority: 1000},
		{Action: hns.Allow, RemoteAddresses: "10.0.11.0/24", Priority: 1001},
		{Action: hns.Block, RemoteAddresses: "10.0.12.0/24", Priority: 1002},
		{Action: hns.Block, RemoteAddresses: "10.0.13.0/24", Priority: 1003},
	}

	rewritePriorities(policies, 1004)
	Expect(policies).To(Equal([]*hns.ACLPolicy{
		{Action: hns.Allow, RemoteAddresses: "10.0.10.0/24", Priority: 1000},
		{Action: hns.Allow, RemoteAddresses: "10.0.11.0/24", Priority: 1000},
		{Action: hns.Block, RemoteAddresses: "10.0.12.0/24", Priority: 1001},
		{Action: hns.Block, RemoteAddresses: "10.0.13.0/24", Priority: 1001},
	}))
}

func makeTier(rules []*hns.ACLPolicy) tierInfo {
	return makeTierWithAction(rules, rules, "")
}

func makeTierWithAction(ingressRules, egressRules []*hns.ACLPolicy, defaultAction string) tierInfo {
	return tierInfo{
		ingressRules:  ingressRules,
		egressRules:   egressRules,
		defaultAction: defaultAction,
	}
}

func verifyFlatTier(tiers []tierInfo, expectedTier tierInfo) {
	flatTier := flattenTiers(tiers)
	Expect(flatTier.ingressRules).To(Equal(expectedTier.ingressRules))
	Expect(flatTier.egressRules).To(Equal(expectedTier.egressRules))
	Expect(flatTier.defaultAction).To(Equal(expectedTier.defaultAction))
}
