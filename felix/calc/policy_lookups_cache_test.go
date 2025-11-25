// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

package calc_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	. "github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var (
	// Define a set of policies and profiles - these just contain the bare bones info for the
	// tests.

	// GlobalNetworkPolicy policy1, three variations
	gnp1_t1_0i0e_key = model.PolicyKey{
		Name: "policy-1.2.3",
		Kind: v3.KindGlobalNetworkPolicy,
	}
	gnp1_t1_0i0e = &model.Policy{
		Tier: "tier-1",
	}
	gnp1_t1_1i1e_key = model.PolicyKey{
		Name: "policy-1.2.3",
		Kind: v3.KindGlobalNetworkPolicy,
	}
	gnp1_t1_1i1e = &model.Policy{
		Tier: "tier-1",
		InboundRules: []model.Rule{
			{Action: "allow"},
		},
		OutboundRules: []model.Rule{
			{Action: "deny"},
		},
	}
	prefix_gnp1_t1_i0A = toprefix("API0|gnp/policy-1.2.3")
	ruleID_gnp1_t1_i0A = NewRuleID(v3.KindGlobalNetworkPolicy, "tier-1", "policy-1.2.3", "", 0, rules.RuleDirIngress, rules.RuleActionAllow)
	prefix_gnp1_t1_e0D = toprefix("DPE0|gnp/policy-1.2.3")
	ruleID_gnp1_t1_e0D = NewRuleID(v3.KindGlobalNetworkPolicy, "tier-1", "policy-1.2.3", "", 0, rules.RuleDirEgress, rules.RuleActionDeny)

	gnp1_t1_4i2e_key = model.PolicyKey{
		Name: "policy-1.2.3",
		Kind: v3.KindGlobalNetworkPolicy,
	}
	gnp1_t1_4i2e = &model.Policy{
		Tier: "tier-1",
		InboundRules: []model.Rule{
			{Action: "allow"}, {Action: "deny"}, {Action: "pass"}, {Action: "next-tier"},
		},
		OutboundRules: []model.Rule{
			{Action: "allow"}, {Action: "allow"},
		},
	}
	// prefix_gnp1_t1_i0A defined above
	// ruleID_gnp1_t1_i0A defined above
	prefix_gnp1_t1_i1D = toprefix("DPI1|gnp/policy-1.2.3")
	ruleID_gnp1_t1_i1D = NewRuleID(v3.KindGlobalNetworkPolicy, "tier-1", "policy-1.2.3", "", 1, rules.RuleDirIngress, rules.RuleActionDeny)
	prefix_gnp1_t1_i2N = toprefix("PPI2|gnp/policy-1.2.3")
	ruleID_gnp1_t1_i2N = NewRuleID(v3.KindGlobalNetworkPolicy, "tier-1", "policy-1.2.3", "", 2, rules.RuleDirIngress, rules.RuleActionPass)
	prefix_gnp1_t1_i3P = toprefix("PPI3|gnp/policy-1.2.3")
	ruleID_gnp1_t1_i3P = NewRuleID(v3.KindGlobalNetworkPolicy, "tier-1", "policy-1.2.3", "", 3, rules.RuleDirIngress, rules.RuleActionPass)
	prefix_gnp1_t1_e0A = toprefix("APE0|gnp/policy-1.2.3")
	ruleID_gnp1_t1_e0A = NewRuleID(v3.KindGlobalNetworkPolicy, "tier-1", "policy-1.2.3", "", 0, rules.RuleDirEgress, rules.RuleActionAllow)
	prefix_gnp1_t1_e1A = toprefix("APE1|gnp/policy-1.2.3")
	ruleID_gnp1_t1_e1A = NewRuleID(v3.KindGlobalNetworkPolicy, "tier-1", "policy-1.2.3", "", 1, rules.RuleDirEgress, rules.RuleActionAllow)

	// NetworkPolicy namespace-1/policy-2
	np1_t1_0i1e_key = model.PolicyKey{
		Name:      "policy-2",
		Namespace: "namespace-1",
		Kind:      v3.KindNetworkPolicy,
	}
	np1_t1_0i1e = &model.Policy{
		Tier: "tier-1",
		OutboundRules: []model.Rule{
			{Action: "allow"},
		},
	}
	prefix_np1_t1_e0A = toprefix("APE0|np/namespace-1/policy-2")
	ruleID_np1_t1_e0A = NewRuleID(v3.KindNetworkPolicy, "tier-1", "policy-2", "namespace-1", 0, rules.RuleDirEgress, rules.RuleActionAllow)

	// K8s NetworkPolicy namespace-1/knp.default.policy-1.1
	knp1_t1_1i0e_key = model.PolicyKey{
		Name:      "knp.default.policy-1.1.1.1",
		Namespace: "namespace-1",
		Kind:      model.KindKubernetesNetworkPolicy,
	}
	knp1_t1_1i0e = &model.Policy{
		Tier: "default",
		InboundRules: []model.Rule{
			{Action: "deny"},
		},
	}
	prefix_knp1_t1_i0D = toprefix("DPI0|knp/namespace-1/knp.default.policy-1.1.1.1")
	ruleID_knp1_t1_i0D = NewRuleID(model.KindKubernetesNetworkPolicy, "default", "knp.default.policy-1.1.1.1", "namespace-1", 0, rules.RuleDirIngress, rules.RuleActionDeny)

	// K8s ClusterNetworkPolicy kcnp.kube-admin.policy-1.1
	kcnpAdmin1_t1_1i0e_key = model.PolicyKey{
		Name: "kcnp.kube-admin.policy-1.1.1.1",
		Kind: model.KindKubernetesClusterNetworkPolicy,
	}
	kcnpAdmin1_t1_1i0e = &model.Policy{
		Tier: "kube-admin",
		InboundRules: []model.Rule{
			{Action: "deny"},
		},
	}

	prefix_kcnpAdmin1_t1_i0D = toprefix("DPI0|kcnp/kcnp.kube-admin.policy-1.1.1.1")
	ruleID_kcnpAdmin1_t1_i0D = NewRuleID(
		model.KindKubernetesClusterNetworkPolicy,
		"kube-admin",
		"kcnp.kube-admin.policy-1.1.1.1",
		"",
		0,
		rules.RuleDirIngress,
		rules.RuleActionDeny,
	)

	// K8s ClusterNetworkPolicy kcnp.kube-baseline.policy-1.1
	kcnpBaseline1_t1_1i0e_key = model.PolicyKey{
		Name: "kcnp.kube-baseline.policy-1.1.1.1",
		Kind: model.KindKubernetesClusterNetworkPolicy,
	}
	kcnpBaseline1_t1_1i0e = &model.Policy{
		Tier: "kube-baseline",
		InboundRules: []model.Rule{
			{Action: "deny"},
		},
	}

	prefix_kcnpBaseline1_t1_i0D = toprefix("DPI0|kcnp/kcnp.kube-baseline.policy-1.1.1.1")
	ruleID_kcnpBaseline1_t1_i0D = NewRuleID(
		model.KindKubernetesClusterNetworkPolicy,
		"kube-baseline",
		"kcnp.kube-baseline.policy-1.1.1.1",
		"",
		0,
		rules.RuleDirIngress,
		rules.RuleActionDeny,
	)

	// Profile profile-1
	pr1_1i1e_key = model.ProfileRulesKey{
		ProfileKey: model.ProfileKey{Name: "profile-1"},
	}
	pr1_1i1e = &model.ProfileRules{
		InboundRules: []model.Rule{
			{Action: "deny"},
		},
		OutboundRules: []model.Rule{
			{Action: "deny"},
		},
	}
	prefix_prof_i0D = toprefix("DRI0|profile-1")
	prefix_prof_e0D = toprefix("DRE0|profile-1")
	ruleID_prof_i0D = NewRuleID("", "", "profile-1", "", 0, rules.RuleDirIngress, rules.RuleActionDeny)
	ruleID_prof_e0D = NewRuleID("", "", "profile-1", "", 0, rules.RuleDirEgress, rules.RuleActionDeny)

	// Tier no-matches
	prefix_nomatch_t1_i            = toprefix("DPI|tier-1")
	ruleID_nomatch_t1_i            = NewRuleID("", "tier-1", "", "", 0, rules.RuleDirIngress, rules.RuleActionDeny)
	prefix_nomatch_t1_e            = toprefix("DPE|tier-1")
	ruleID_nomatch_t1_e            = NewRuleID("", "tier-1", "", "", 0, rules.RuleDirEgress, rules.RuleActionDeny)
	prefix_nomatch_td_i            = toprefix("DPI|default")
	ruleID_nomatch_td_i            = NewRuleID("", "default", "", "", 0, rules.RuleDirIngress, rules.RuleActionDeny)
	prefix_nomatch_td_e            = toprefix("DPE|default")
	ruleID_nomatch_td_e            = NewRuleID("", "default", "", "", 0, rules.RuleDirEgress, rules.RuleActionDeny)
	prefix_nomatch_tkcnpAdmin_i    = toprefix("DPI|kube-admin")
	ruleID_nomatch_tkcnpAdmin_i    = NewRuleID("", "kube-admin", "", "", 0, rules.RuleDirIngress, rules.RuleActionDeny)
	prefix_nomatch_tkcnpAdmin_e    = toprefix("DPE|kube-admin")
	ruleID_nomatch_tkcnpAdmin_e    = NewRuleID("", "kube-admin", "", "", 0, rules.RuleDirEgress, rules.RuleActionDeny)
	prefix_nomatch_tkcnpBaseline_i = toprefix("DPI|kube-baseline")
	ruleID_nomatch_tkcnpBaseline_i = NewRuleID("", "kube-baseline", "", "", 0, rules.RuleDirIngress, rules.RuleActionDeny)
	prefix_nomatch_tkcnpBaseline_e = toprefix("DPE|kube-baseline")
	ruleID_nomatch_tkcnpBaseline_e = NewRuleID("", "kube-baseline", "", "", 0, rules.RuleDirEgress, rules.RuleActionDeny)

	// Profile no-matches
	prefix_nomatch_prof_i = toprefix("DRI")
	ruleID_nomatch_prof_i = NewRuleID("", "", "", "", 0, rules.RuleDirIngress, rules.RuleActionDeny)
	prefix_nomatch_prof_e = toprefix("DRE")
	ruleID_nomatch_prof_e = NewRuleID("", "", "", "", 0, rules.RuleDirEgress, rules.RuleActionDeny)
)

var _ = Describe("PolicyLookupsCache tests", func() {
	pc := NewPolicyLookupsCache()

	DescribeTable(
		"Check default rules are installed",
		func(prefix [64]byte, expectedRuleID *RuleID) {
			rid := pc.GetRuleIDFromNFLOGPrefix(prefix)
			Expect(rid).NotTo(BeNil())
			Expect(*rid).To(Equal(*expectedRuleID))
		},
		Entry("Ingress profile no-match", prefix_nomatch_prof_i, ruleID_nomatch_prof_i),
		Entry("Egress profile no-match", prefix_nomatch_prof_e, ruleID_nomatch_prof_e),
	)

	DescribeTable(
		"Check adding/deleting policy installs/uninstalls rules",
		func(key model.PolicyKey, pol *model.Policy, prefix [64]byte, expectedRuleID *RuleID) {
			// Send the policy update and check that the entry is now in the cache
			c := "Querying prefix " + string(prefix[:]) + "\n"
			pc.OnPolicyActive(key, pol)
			rid := pc.GetRuleIDFromNFLOGPrefix(prefix)
			Expect(rid).NotTo(BeNil(), c+pc.Dump(), fmt.Sprintf("Couldn't find prefix: %s", prefix))
			Expect(*rid).To(Equal(*expectedRuleID))

			// Send a policy delete and check that the entry is not in the cache
			pc.OnPolicyInactive(key)
			rid = pc.GetRuleIDFromNFLOGPrefix(prefix)
			Expect(rid).To(BeNil(), c+pc.Dump())
		},
		Entry("GNP1 (0i0e) no match tier-1 ingress", gnp1_t1_0i0e_key, gnp1_t1_0i0e, prefix_nomatch_t1_i, ruleID_nomatch_t1_i),
		Entry("GNP1 (0i0e) no match tier-1 egress", gnp1_t1_0i0e_key, gnp1_t1_0i0e, prefix_nomatch_t1_e, ruleID_nomatch_t1_e),
		Entry("GNP1 (1i1e) i0", gnp1_t1_1i1e_key, gnp1_t1_1i1e, prefix_gnp1_t1_i0A, ruleID_gnp1_t1_i0A),
		Entry("GNP1 (1i1e) e0", gnp1_t1_1i1e_key, gnp1_t1_1i1e, prefix_gnp1_t1_e0D, ruleID_gnp1_t1_e0D),
		Entry("GNP1 (4i2e) i0", gnp1_t1_4i2e_key, gnp1_t1_4i2e, prefix_gnp1_t1_i0A, ruleID_gnp1_t1_i0A),
		Entry("GNP1 (4i2e) i1", gnp1_t1_4i2e_key, gnp1_t1_4i2e, prefix_gnp1_t1_i1D, ruleID_gnp1_t1_i1D),
		Entry("GNP1 (4i2e) i2", gnp1_t1_4i2e_key, gnp1_t1_4i2e, prefix_gnp1_t1_i2N, ruleID_gnp1_t1_i2N),
		Entry("GNP1 (4i2e) i3", gnp1_t1_4i2e_key, gnp1_t1_4i2e, prefix_gnp1_t1_i3P, ruleID_gnp1_t1_i3P),
		Entry("GNP1 (4i2e) e0", gnp1_t1_4i2e_key, gnp1_t1_4i2e, prefix_gnp1_t1_e0A, ruleID_gnp1_t1_e0A),
		Entry("GNP1 (4i2e) e1", gnp1_t1_4i2e_key, gnp1_t1_4i2e, prefix_gnp1_t1_e1A, ruleID_gnp1_t1_e1A),
		Entry("NP1 (0i1e) no match tier-1 ingress", np1_t1_0i1e_key, np1_t1_0i1e, prefix_nomatch_t1_i, ruleID_nomatch_t1_i),
		Entry("NP1 (0i1e) no match tier-1 egress", gnp1_t1_0i0e_key, gnp1_t1_0i0e, prefix_nomatch_t1_e, ruleID_nomatch_t1_e),
		Entry("NP1 (0i1e) i1", np1_t1_0i1e_key, np1_t1_0i1e, prefix_np1_t1_e0A, ruleID_np1_t1_e0A),
		Entry("KNP1 (1i0e) no match default ingress", knp1_t1_1i0e_key, knp1_t1_1i0e, prefix_nomatch_td_i, ruleID_nomatch_td_i),
		Entry("KNP1 (1i0e) no match default egress", knp1_t1_1i0e_key, knp1_t1_1i0e, prefix_nomatch_td_e, ruleID_nomatch_td_e),
		Entry("KNP1 (1i0e) i0", knp1_t1_1i0e_key, knp1_t1_1i0e, prefix_knp1_t1_i0D, ruleID_knp1_t1_i0D),
		Entry("KCNP1_Admin (1i0e) no match default ingress", kcnpAdmin1_t1_1i0e_key, kcnpAdmin1_t1_1i0e, prefix_nomatch_tkcnpAdmin_i, ruleID_nomatch_tkcnpAdmin_i),
		Entry("KCNP1_Admin (1i0e) no match default egress", kcnpAdmin1_t1_1i0e_key, kcnpAdmin1_t1_1i0e, prefix_nomatch_tkcnpAdmin_e, ruleID_nomatch_tkcnpAdmin_e),
		Entry("KCNP1_Admin (1i0e) i0", kcnpAdmin1_t1_1i0e_key, kcnpAdmin1_t1_1i0e, prefix_kcnpAdmin1_t1_i0D, ruleID_kcnpAdmin1_t1_i0D),
		Entry("KCNP1_Baseline (1i0e) no match default ingress", kcnpBaseline1_t1_1i0e_key, kcnpBaseline1_t1_1i0e, prefix_nomatch_tkcnpBaseline_i, ruleID_nomatch_tkcnpBaseline_i),
		Entry("KCNP1_Baseline (1i0e) no match default egress", kcnpBaseline1_t1_1i0e_key, kcnpBaseline1_t1_1i0e, prefix_nomatch_tkcnpBaseline_e, ruleID_nomatch_tkcnpBaseline_e),
		Entry("KCNP1_Baseline (1i0e) i0", kcnpBaseline1_t1_1i0e_key, kcnpBaseline1_t1_1i0e, prefix_kcnpBaseline1_t1_i0D, ruleID_kcnpBaseline1_t1_i0D),
	)

	DescribeTable(
		"Check adding/deleting profile installs/uninstalls rules",
		func(key model.ProfileRulesKey, profile *model.ProfileRules, prefix [64]byte, expectedRuleID *RuleID) {
			// Send the policy update and check that the entry is now in the cache
			c := "Querying prefix " + string(prefix[:]) + "\n"
			pc.OnProfileActive(key, profile)
			rid := pc.GetRuleIDFromNFLOGPrefix(prefix)
			Expect(rid).NotTo(BeNil(), c+pc.Dump())
			Expect(*rid).To(Equal(*expectedRuleID))

			// Send a policy delete and check that the entry is not in the cache
			pc.OnProfileInactive(key)
			rid = pc.GetRuleIDFromNFLOGPrefix(prefix)
			Expect(rid).To(BeNil(), c+pc.Dump())
		},
		Entry("Pr1 (1i1e) i0", pr1_1i1e_key, pr1_1i1e, prefix_prof_i0D, ruleID_prof_i0D),
		Entry("Pr1 (1i1e) e0", pr1_1i1e_key, pr1_1i1e, prefix_prof_e0D, ruleID_prof_e0D),
	)

	It("should handle tier drops when there are multiple policies in the same tier", func() {
		By("Creating policy GNP1 in tier 1")
		pc.OnPolicyActive(gnp1_t1_0i0e_key, gnp1_t1_0i0e)

		By("Checking the default tier drops are cached")
		rid := pc.GetRuleIDFromNFLOGPrefix(prefix_nomatch_t1_i)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_nomatch_t1_i))
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_nomatch_t1_e)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_nomatch_t1_e))

		By("Creating policy NP1 in tier 1")
		pc.OnPolicyActive(np1_t1_0i1e_key, np1_t1_0i1e)

		By("Checking the default tier drops are cached")
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_nomatch_t1_i)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_nomatch_t1_i))
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_nomatch_t1_e)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_nomatch_t1_e))

		By("Deleting policy GNP1 in tier 1")
		pc.OnPolicyInactive(gnp1_t1_0i0e_key)

		By("Checking the default tier drops are cached")
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_nomatch_t1_i)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_nomatch_t1_i))
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_nomatch_t1_e)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_nomatch_t1_e))

		By("Deleting policy NP1 in tier 1")
		pc.OnPolicyInactive(np1_t1_0i1e_key)

		By("Checking the default tier drops are no longer cached")
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_nomatch_t1_i)
		Expect(rid).To(BeNil(), pc.Dump())
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_nomatch_t1_e)
		Expect(rid).To(BeNil(), pc.Dump())
	})

	It("should handle a policy being updated", func() {
		By("Creating policy GNP1 in tier 1")
		pc.OnPolicyActive(gnp1_t1_1i1e_key, gnp1_t1_1i1e)

		By("Checking the ingress and egress rules are cached")
		rid := pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_i0A)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_gnp1_t1_i0A))
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_e0D)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_gnp1_t1_e0D))

		By("Checking that some ingress and egress rules are not yet cached")
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_i1D)
		Expect(rid).To(BeNil(), pc.Dump())
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_e1A)
		Expect(rid).To(BeNil(), pc.Dump())

		By("Creating policy GNP1 in tier 1")
		pc.OnPolicyActive(gnp1_t1_4i2e_key, gnp1_t1_4i2e)

		By("Checking the old ingress rule is still cached (it is unchanged by the update)")
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_i0A)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_gnp1_t1_i0A))

		By("Checking the old egress rule has been replaced (the rule action has changed)")
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_e0D)
		Expect(rid).To(BeNil(), pc.Dump())
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_e0A)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_gnp1_t1_e0A))

		By("Checking the some ingress and egress rules are now cached")
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_i1D)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_gnp1_t1_i1D))
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_e1A)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_gnp1_t1_e1A))

		By("Update policy GNP1 in tier 1 with more rules")
		pc.OnPolicyActive(gnp1_t1_1i1e_key, gnp1_t1_1i1e)

		By("Checking the ingress and egress rules are cached")
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_i0A)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_gnp1_t1_i0A))
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_e0D)
		Expect(rid).NotTo(BeNil(), pc.Dump())
		Expect(*rid).To(Equal(*ruleID_gnp1_t1_e0D))

		By("Checking the some ingress and egress rules are not cached")
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_i1D)
		Expect(rid).To(BeNil(), pc.Dump())
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_e1A)
		Expect(rid).To(BeNil(), pc.Dump())

		By("Update policy GNP1 in tier 1 with no rules")
		pc.OnPolicyActive(gnp1_t1_0i0e_key, gnp1_t1_0i0e)

		By("Checking the ingress and egress rules are not cached")
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_i0A)
		Expect(rid).To(BeNil(), pc.Dump())
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_e0D)
		Expect(rid).To(BeNil(), pc.Dump())
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_i1D)
		Expect(rid).To(BeNil(), pc.Dump())
		rid = pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_e1A)
		Expect(rid).To(BeNil(), pc.Dump())
	})
})

var _ = Describe("RuleID tests", func() {
	DescribeTable(
		"Check flow log name is set correctly",
		func(kind, tier, policy, namespace string, ruleIndex int, ruleDirection rules.RuleDir, ruleAction rules.RuleAction, expectedFPName string) {
			rid := NewRuleID(kind, tier, policy, namespace, ruleIndex, ruleDirection, ruleAction)
			Expect(rid).NotTo(BeNil())
			Expect(rid.GetFlowLogPolicyName()).To(Equal(expectedFPName))
		},
		Entry("Global network policy", v3.KindGlobalNetworkPolicy, "default", "gnp-1", "", 0, rules.RuleDirIngress, rules.RuleActionAllow, "default|gnp-1|allow"),
		Entry("Global network policy in non default tier", v3.KindGlobalNetworkPolicy, "tier-1", "gnp-2", "", 2, rules.RuleDirEgress, rules.RuleActionPass, "tier-1|gnp-2|pass"),
		Entry("Namespaced network policy", v3.KindNetworkPolicy, "default", "np-1", "ns1", 0, rules.RuleDirIngress, rules.RuleActionAllow, "default|ns1/np-1|allow"),
		Entry("Namespaced network policy in non default tier", v3.KindNetworkPolicy, "netsec", "np-2", "ns2", 0, rules.RuleDirIngress, rules.RuleActionAllow, "netsec|ns2/np-2|allow"),
		Entry("Kubernetes network policy", model.KindKubernetesNetworkPolicy, "default", "knp.default.allow.all", "test", 0, rules.RuleDirIngress, rules.RuleActionAllow, "default|test/knp.default.allow.all|allow"),
		Entry("Profile", "", "", "kns.ns3", "ns3", 0, rules.RuleDirIngress, rules.RuleActionAllow, "__PROFILE__|__PROFILE__.kns.ns3|allow"),

		Entry("Staged Global network policy", v3.KindStagedGlobalNetworkPolicy, "default", "gnp-1", "", 0, rules.RuleDirIngress, rules.RuleActionAllow, "default|default.staged:gnp-1|allow"),
		Entry("Staged Global network policy in non default tier", v3.KindStagedGlobalNetworkPolicy, "tier-1", "gnp-2", "", 2, rules.RuleDirEgress, rules.RuleActionPass, "tier-1|tier-1.staged:gnp-2|pass"),
		Entry("Staged Namespaced network policy", v3.KindStagedNetworkPolicy, "default", "np.1", "ns1", 0, rules.RuleDirIngress, rules.RuleActionAllow, "default|ns1/default.staged:np.1|allow"),
		Entry("Staged Namespaced network policy in non default tier", v3.KindStagedNetworkPolicy, "netsec", "np-2", "ns2", 0, rules.RuleDirIngress, rules.RuleActionAllow, "netsec|ns2/netsec.staged:np-2|allow"),
		Entry("Staged Kubernetes network policy", v3.KindStagedKubernetesNetworkPolicy, "default", "knp.default.allow.all", "test", 0, rules.RuleDirIngress, rules.RuleActionAllow, "default|test/staged:knp.default.allow.all|allow"),
	)
})

var _ = Describe("PolicyLookupsCache 64bit id test", func() {
	pc := NewPolicyLookupsCache()

	It("should not create 64bit IDs by default", func() {
		pc.OnPolicyActive(gnp1_t1_4i2e_key, gnp1_t1_4i2e)
		Expect(pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_i1D)).To(Equal(ruleID_gnp1_t1_i1D))
		Expect(pc.GetID64FromNFLOGPrefix(prefix_gnp1_t1_i1D)).To(Equal(uint64(0)))
	})

	It("should create 64bit IDs if enabled", func() {
		pc.SetUseIDs()

		var id64 uint64

		By("injecting policy creates nflong prefix and id64", func() {
			pc.OnPolicyActive(gnp1_t1_4i2e_key, gnp1_t1_4i2e)
			Expect(pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_i1D)).To(Equal(ruleID_gnp1_t1_i1D))
			id64 = pc.GetID64FromNFLOGPrefix(prefix_gnp1_t1_i1D)
			Expect(id64).NotTo(Equal(uint64(0)))
		})

		By("requesting id64 returns expected rule ID", func() {
			Expect(pc.GetRuleIDFromID64(id64)).To(Equal(ruleID_gnp1_t1_i1D))
		})

		By("deleting policy removes nflog prefix and id64", func() {
			pc.OnPolicyInactive(gnp1_t1_4i2e_key)
			Expect(pc.GetRuleIDFromNFLOGPrefix(prefix_gnp1_t1_i1D)).To(BeNil())
			Expect(pc.GetRuleIDFromID64(id64)).To(BeNil())
			Expect(pc.GetID64FromNFLOGPrefix(prefix_gnp1_t1_i1D)).To(Equal(uint64(0)))
		})
	})
})

func toprefix(s string) [64]byte {
	p := [64]byte{}
	copy(p[:], []byte(s))
	return p
}
