// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package rbac_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	rbac_v1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	. "github.com/projectcalico/calico/apiserver/pkg/rbac"
	rbacmock "github.com/projectcalico/calico/apiserver/pkg/rbac/mock"
)

var (
	resourceHostEndpoints = ResourceType{
		APIGroup: "projectcalico.org",
		Resource: "hostendpoints",
	}
	resourceTiers = ResourceType{
		APIGroup: "projectcalico.org",
		Resource: "tiers",
	}
	resourceCalicoNetworkPolicies = ResourceType{
		APIGroup: "projectcalico.org",
		Resource: "networkpolicies",
	}
	resourceGlobalNetworkPolicies = ResourceType{
		APIGroup: "projectcalico.org",
		Resource: "globalnetworkpolicies",
	}
	resourceNetworkSets = ResourceType{
		APIGroup: "projectcalico.org",
		Resource: "networksets",
	}
	resourceGlobalNetworkSets = ResourceType{
		APIGroup: "projectcalico.org",
		Resource: "globalnetworksets",
	}
	resourceKubernetesNetworkPolicies = ResourceType{
		APIGroup: "networking.k8s.io",
		Resource: "networkpolicies",
	}
	resourceLegacyKubernetesNetworkPolicies = ResourceType{
		APIGroup: "extensions",
		Resource: "networkpolicies",
	}
	resourceNamespaces = ResourceType{
		APIGroup: "",
		Resource: "namespaces",
	}
	resourcePods = ResourceType{
		APIGroup: "",
		Resource: "pods",
	}

	tieredPolicyResources = []ResourceType{
		resourceCalicoNetworkPolicies,
		resourceGlobalNetworkPolicies,
	}

	namespacedResources = []ResourceType{
		resourceNetworkSets,
		resourceLegacyKubernetesNetworkPolicies,
		resourceKubernetesNetworkPolicies,
		resourcePods,
		resourceCalicoNetworkPolicies,
	}

	clusterScopedResources = []ResourceType{
		resourceHostEndpoints,
		resourceTiers,
		resourceNamespaces,
		resourceGlobalNetworkSets,
		resourceGlobalNetworkPolicies,
	}

	defaultResourceTypes = []ResourceType{
		resourceHostEndpoints,
		resourceTiers,
		resourceNamespaces,
		resourceNetworkSets,
		resourceGlobalNetworkSets,
		resourceLegacyKubernetesNetworkPolicies,
		resourceKubernetesNetworkPolicies,
		resourcePods,
		resourceCalicoNetworkPolicies,
		resourceGlobalNetworkPolicies,
	}
)

func isOneOf(rt ResourceType, rts ...ResourceType) bool {
	for _, rtss := range rts {
		if rt == rtss {
			return true
		}
	}
	return false
}

var allResourceVerbs []ResourceVerbs

func init() {
	for _, rt := range defaultResourceTypes {
		allResourceVerbs = append(allResourceVerbs, ResourceVerbs{
			rt, AllVerbs,
		})
	}
}

var _ = Describe("RBAC calculator tests", func() {
	var calc Calculator
	var mock *rbacmock.MockClient
	var myUser user.Info

	BeforeEach(func() {
		mock = &rbacmock.MockClient{
			Roles:               map[string][]rbac_v1.PolicyRule{},
			RoleBindings:        map[string][]string{},
			ClusterRoles:        map[string][]rbac_v1.PolicyRule{},
			ClusterRoleBindings: []string{},
			Namespaces:          []string{"ns1", "ns2", "ns3", "ns4", "ns5"},
			Tiers:               []string{"default", "tier1", "tier2", "tier3", "tier4"},
		}
		calc = NewCalculator(mock, mock, mock, mock, mock, mock, mock, 0)
		myUser = &user.DefaultInfo{
			Name:   "my-user",
			UID:    "abcde",
			Groups: []string{},
			Extra:  map[string][]string{},
		}
	})

	It("handles errors in the Namespace enumeration", func() {
		mock.Namespaces = nil
		res, err := calc.CalculatePermissions(myUser, allResourceVerbs)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no Namespaces set"))
		expectPresentButEmpty(res, allResourceVerbs)
	})

	It("handles errors in the ClusterRoleBinding enumeration", func() {
		mock.ClusterRoleBindings = nil
		res, err := calc.CalculatePermissions(myUser, allResourceVerbs)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no ClusterRoleBindings set"))
		expectPresentButEmpty(res, allResourceVerbs)
	})

	It("handles errors in the ClusterRole enumeration from ClusterRoleBinding", func() {
		mock.ClusterRoleBindings = []string{"test"}
		res, err := calc.CalculatePermissions(myUser, allResourceVerbs)
		Expect(err).NotTo(HaveOccurred())
		expectPresentButEmpty(res, allResourceVerbs)
	})

	It("handles errors in the RoleBinding enumeration", func() {
		mock.RoleBindings = nil
		res, err := calc.CalculatePermissions(myUser, allResourceVerbs)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no RoleBindings set"))
		expectPresentButEmpty(res, allResourceVerbs)
	})

	It("handles errors in the ClusterRole enumeration from RoleBinding", func() {
		mock.RoleBindings = map[string][]string{"ns1": {"test"}}
		res, err := calc.CalculatePermissions(myUser, allResourceVerbs)
		Expect(err).NotTo(HaveOccurred())
		expectPresentButEmpty(res, allResourceVerbs)
	})

	It("handles errors in the Role enumeration from RoleBinding", func() {
		mock.RoleBindings = map[string][]string{"ns1": {"/test"}}
		res, err := calc.CalculatePermissions(myUser, allResourceVerbs)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Role(ns1/test) does not exist"))
		expectPresentButEmpty(res, allResourceVerbs)
	})

	It("matches cluster scoped wildcard name matches for all resources", func() {
		mock.ClusterRoleBindings = []string{"all-resources"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"all-resources": {{
				Verbs:     []string{"update", "create", "list", "get"},
				Resources: []string{"*"},
				APIGroups: []string{"*"},
			}},
		}
		res, err := calc.CalculatePermissions(myUser, allResourceVerbs)
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveLen(len(defaultResourceTypes)), "one result for each resource type")

		Describe("all resources", func() {
			for _, resourceType := range defaultResourceTypes {
				Expect(res).To(HaveKey(resourceType), "one result for each resource type")
				Expect(res[resourceNamespaces]).To(haveMatchAllForVerbs(
					VerbUpdate,
					VerbCreate,
					VerbList,
				))
				Expect(res[resourceNamespaces]).To(haveMatchNoneForVerbs(
					VerbPatch,
					VerbDelete,
					VerbWatch,
				))

				// assert get is non-nil. it's value will be different for certain resources as tested independently below
				Expect(res[resourceNamespaces][VerbGet]).ToNot(BeNil())
			}
		})

		Describe("tiered policies", func() {
			for _, resourceType := range tieredPolicyResources {
				Expect(res[resourceType]).To(haveOnlyMatchesForVerbs([]Match{
					{Tier: "default"},
					{Tier: "tier1"},
					{Tier: "tier2"},
					{Tier: "tier3"},
					{Tier: "tier4"},
				}, VerbUpdate, VerbCreate, VerbList, VerbGet), resourceType.String())
			}
		})

		Describe("namespaces", func() {
			Expect(res[resourceNamespaces]).To(haveMatchForVerbs([]Match{
				{Namespace: "ns1"},
				{Namespace: "ns2"},
				{Namespace: "ns3"},
				{Namespace: "ns4"},
				{Namespace: "ns5"},
			}, VerbGet))
		})

		Describe("get tiers", func() {
			Expect(res[resourceTiers]).To(haveMatchForVerbs([]Match{
				{Tier: "default"},
				{Tier: "tier1"},
				{Tier: "tier2"},
				{Tier: "tier3"},
				{Tier: "tier4"},
			}, VerbGet))
		})
	})

	It("matches cluster scoped wildcard tier matches for all resources with get access to limited Tiers", func() {
		gettableTiers := []string{"default", "tier2"}
		mock.ClusterRoleBindings = []string{"all-resources", "get-tiers"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"all-resources": {{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"delete", "patch"},
			}},
			"get-tiers": {{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"tiers"},
				Verbs:         []string{"get"},
				ResourceNames: gettableTiers,
			}},
		}

		res, err := calc.CalculatePermissions(myUser, allResourceVerbs)
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveLen(len(defaultResourceTypes)))
		Describe("all resources", func() {
			for _, resourceType := range defaultResourceTypes {
				Expect(res).To(HaveKey(resourceType), "one result for each resource type")
				Expect(res[resourceType]).To(HaveLen(len(AllVerbs)), "one result for each defined verb")
				if isOneOf(resourceType, resourceTiers) || isOneOf(resourceType, tieredPolicyResources...) {
					// test separately below as they additionally have 'get' permission.
					continue
				}
				Expect(res[resourceType]).To(haveOnlyMatchesForVerbs([]Match{{}}, VerbPatch, VerbDelete), resourceType.String())
			}
		})

		Describe("tiers", func() {
			Expect(res[resourceTiers]).To(haveMatchNoneForVerbs(VerbWatch, VerbCreate, VerbList, VerbUpdate))
			Expect(res[resourceTiers]).To(haveMatchAllForVerbs(VerbDelete, VerbPatch))
			Expect(res[resourceTiers]).To(haveMatchForVerbs([]Match{
				{Tier: "default"},
				{Tier: "tier2"},
			}, VerbGet))
		})

		Describe("tiered policies", func() {
			// Matches for tiered policy should only contain the gettable Tiers.
			for _, resourceType := range tieredPolicyResources {
				Expect(res[resourceType]).To(haveOnlyMatchesForVerbs([]Match{
					{Tier: "default"},
					{Tier: "tier2"},
				}, VerbDelete, VerbPatch), resourceType.String())
			}
		})

		Describe("all other resources", func() {
			for _, resourceType := range []ResourceType{
				resourceHostEndpoints,
				resourceNamespaces,
				resourceNetworkSets,
				resourceGlobalNetworkSets,
				resourceLegacyKubernetesNetworkPolicies,
				resourcePods,
				resourceKubernetesNetworkPolicies,
			} {
				Expect(res[resourceType]).To(haveMatchAllForVerbs(VerbDelete, VerbPatch), resourceType.String())
				Expect(res[resourceType]).To(haveMatchNoneForVerbs(VerbGet, VerbList, VerbUpdate, VerbCreate, VerbWatch))
			}
		})
	})

	It("matches wildcard name matches for all resources in namespace ns1, get access all Tiers and UISettingsGroups", func() {
		mock.ClusterRoleBindings = []string{"get-tiers", "get-uisettingsgroups"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-tiers": {{
				Verbs:     []string{"get"},
				Resources: []string{"tiers"},
				APIGroups: []string{"projectcalico.org"},
			}},
			"get-uisettingsgroups": {{
				Verbs:     []string{"get"},
				Resources: []string{"uisettingsgroups"},
				APIGroups: []string{"projectcalico.org"},
			}},
		}
		mock.RoleBindings = map[string][]string{"ns1": {"/all-resources"}}
		mock.Roles = map[string][]rbac_v1.PolicyRule{
			"ns1/all-resources": {{
				Verbs:     []string{"update", "create", "list"},
				Resources: []string{"*"},
				APIGroups: []string{"*"},
			}},
		}
		// We should only get results for namespaced resources + get for Tiers
		res, err := calc.CalculatePermissions(myUser, allResourceVerbs)
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveLen(len(defaultResourceTypes)))

		Describe("cluster-scoped resources", func() {
			for _, resourceType := range clusterScopedResources {
				Expect(res).To(HaveKey(resourceType), "one result for each resource type")
				Expect(res[resourceType]).To(HaveLen(len(AllVerbs)), "one result for each defined verb")
				if resourceType == resourceNamespaces ||
					resourceType == resourceTiers {
					// test separately below as they additionally have 'get' permission.
					continue
				}
				Expect(res[resourceType]).To(haveMatchNoneForAllVerbs(), resourceType.String())
			}
		})

		Describe("namespaces", func() {
			Expect(res[resourceNamespaces]).To(haveMatchNoneForAllVerbs())
		})

		Describe("tiers", func() {
			Expect(res[resourceTiers]).To(haveOnlyMatchesForVerbs([]Match{
				{Tier: "default"},
				{Tier: "tier1"},
				{Tier: "tier2"},
				{Tier: "tier3"},
				{Tier: "tier4"},
			}, VerbGet))
		})

		Describe("cluster-scoped tiered policy resources", func() {
			for _, resourceType := range []ResourceType{
				resourceGlobalNetworkPolicies,
			} {
				Expect(res[resourceType]).To(haveMatchNoneForAllVerbs(), resourceType.String())
			}
		})

		Describe("namespaced tiered policy resources", func() {
			for _, resourceType := range []ResourceType{
				resourceCalicoNetworkPolicies,
			} {
				Expect(res[resourceType]).To(haveMatchForVerbs([]Match{
					{Namespace: "ns1", Tier: "default"},
					{Namespace: "ns1", Tier: "tier1"},
					{Namespace: "ns1", Tier: "tier2"},
					{Namespace: "ns1", Tier: "tier3"},
					{Namespace: "ns1", Tier: "tier4"},
				}, VerbUpdate, VerbCreate, VerbList), resourceType.String())
				Expect(res[resourceType]).To(haveMatchNoneForVerbs(VerbGet, VerbDelete, VerbPatch, VerbWatch), resourceType.String())
			}
		})

		Describe("namespaced", func() {
			for _, resourceType := range namespacedResources {
				Expect(res[resourceType]).To(HaveLen(len(AllVerbs)))
				if resourceType == resourceCalicoNetworkPolicies {
					Describe("tiered policy resources", func() {
						Expect(res[resourceType]).To(haveMatchForVerbs([]Match{
							{Namespace: "ns1", Tier: "default"},
							{Namespace: "ns1", Tier: "tier1"},
							{Namespace: "ns1", Tier: "tier2"},
							{Namespace: "ns1", Tier: "tier3"},
							{Namespace: "ns1", Tier: "tier4"},
						}, VerbUpdate, VerbCreate, VerbList), resourceType.String())
						Expect(res[resourceType]).To(haveMatchNoneForVerbs(VerbGet, VerbDelete, VerbPatch, VerbWatch), resourceType.String())
					})
				} else {
					Describe("resources (excluding tiered-policy resources", func() {
						Expect(res[resourceType]).To(haveMatchForVerbs([]Match{{Namespace: "ns1"}}, VerbUpdate, VerbCreate, VerbList), resourceType.String())
						Expect(res[resourceType]).To(haveMatchNoneForVerbs(VerbGet, VerbDelete, VerbPatch, VerbWatch), resourceType.String())
					})
				}
			}
		})
	})

	It("matches namespace scoped wildcard name matches for all resources, no get access to any tier", func() {
		mock.RoleBindings = map[string][]string{"ns1": {"/all-resources"}}
		mock.Roles = map[string][]rbac_v1.PolicyRule{
			"ns1/all-resources": {{
				Verbs:     []string{"update", "create", "list"},
				Resources: []string{"*"},
				APIGroups: []string{"*"},
			}},
		}
		// We should only get results for namespaced non-tiered policies
		res, err := calc.CalculatePermissions(myUser, allResourceVerbs)
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveLen(len(defaultResourceTypes)))

		// namespaced resources that aren't tiered policies should have ns matchers
		Describe("namespaced", func() {
			for _, resourceType := range namespacedResources {
				Expect(res[resourceType]).To(HaveLen(len(AllVerbs)), "one result for each defined verb")
				if resourceType == resourceCalicoNetworkPolicies {
					Describe("tiered policy resources", func() {
						Expect(res[resourceType]).To(haveMatchNoneForAllVerbs(), resourceType.String())
					})
				} else {
					Describe("resources (except tiered-policies)", func() {
						Expect(res[resourceType]).To(haveMatchForVerbs([]Match{{Namespace: "ns1"}}, VerbUpdate, VerbCreate, VerbList))
						Expect(res[resourceType]).To(haveMatchNoneForVerbs(VerbGet, VerbDelete, VerbPatch, VerbWatch))
					})
				}
			}
		})

		Describe("cluster-scoped", func() {
			for _, resourceType := range clusterScopedResources {
				Expect(res[resourceType]).To(HaveLen(len(AllVerbs)), "one result for each defined verb")
				Expect(res[resourceType]).To(haveMatchNoneForAllVerbs())
			}
		})
	})

	It("matches namespace scoped wildcard name matches for all resources with get access to limited Tiers", func() {
		gettableTiers := []string{"tier2", "tier3"}
		mock.ClusterRoleBindings = []string{"get-tiers"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-tiers": {{
				Verbs:         []string{"get"},
				Resources:     []string{"tiers"},
				ResourceNames: gettableTiers,
				APIGroups:     []string{"*"},
			}},
		}
		mock.RoleBindings = map[string][]string{"ns1": {"/test"}}
		mock.Roles = map[string][]rbac_v1.PolicyRule{
			"ns1/test": {{
				Verbs:     []string{"delete", "patch", "list", "watch"},
				Resources: []string{"*"},
				APIGroups: []string{"*"},
			}},
		}

		// Since we do not have get access to all Tiers, the wildcard tier match will be expanded. Also the tier
		// resource will be expanded too. So we'd expect:
		// -  Get for each tier (2)
		// -  Delete/Patch/Watch/List for each namespaced tiered policy type in each tier (4 * 2)
		// -  Delete/Patch/Watch/List for other namespaced resource types
		res, err := calc.CalculatePermissions(myUser, allResourceVerbs)
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveLen(len(defaultResourceTypes)))

		Describe("tiers", func() {
			Expect(res[resourceTiers]).To(Equal(map[Verb][]Match{
				VerbGet: {
					{Tier: "tier2"},
					{Tier: "tier3"},
				},
				VerbUpdate: nil,
				VerbCreate: nil,
				VerbList:   nil,
				VerbDelete: nil,
				VerbPatch:  nil,
				VerbWatch:  nil,
			}))
		})

		// namespaced resources that aren't tiered policies should have ns matchers
		Describe("namespaced", func() {
			for _, resourceType := range namespacedResources {
				Expect(res[resourceType]).To(HaveLen(len(AllVerbs)), "one result for each defined verb")
				if resourceType == resourceCalicoNetworkPolicies {
					Describe("tiered policy resources", func() {
						Expect(res[resourceType]).To(Equal(map[Verb][]Match{
							VerbCreate: nil,
							VerbPatch:  {{Tier: "tier2", Namespace: "ns1"}, {Tier: "tier3", Namespace: "ns1"}},
							VerbDelete: {{Tier: "tier2", Namespace: "ns1"}, {Tier: "tier3", Namespace: "ns1"}},
							VerbWatch:  {{Tier: "tier2", Namespace: "ns1"}, {Tier: "tier3", Namespace: "ns1"}},
							VerbGet:    nil,
							VerbUpdate: nil,
							VerbList:   {{Tier: "tier2", Namespace: "ns1"}, {Tier: "tier3", Namespace: "ns1"}},
						}), resourceType.String())
					})
				} else {
					Describe("resources (except tiered-policies)", func() {
						Expect(res[resourceType]).To(Equal(map[Verb][]Match{
							VerbCreate: nil,
							VerbPatch:  {{Namespace: "ns1"}},
							VerbDelete: {{Namespace: "ns1"}},
							VerbWatch:  {{Namespace: "ns1"}},
							VerbGet:    nil,
							VerbUpdate: nil,
							VerbList:   {{Namespace: "ns1"}},
						}), resourceType.String())
					})
				}
			}
		})

		Describe("cluster-scoped", func() {
			for _, resourceType := range clusterScopedResources {
				if resourceType == resourceTiers {
					// handle tiers separately as they have different GET permissions
					continue
				}
				Expect(res[resourceType]).To(haveMatchNoneForAllVerbs(), resourceType.String())
			}
		})
	})

	It("matches namespace scoped wildcard name for CNP + cluster scoped tier-specific CNP + namespace scoped tier-specific CNP, with get access on all Tiers", func() {
		mock.ClusterRoleBindings = []string{"get-tiers", "wildcard-create", "tier1-patch"}
		mock.RoleBindings = map[string][]string{
			"ns2": {"wildcard-delete", "tier2-create", "tier1-patch", "tier2-delete"},
			"ns3": {"tier2-delete", "tier1-listwatch"},
		}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-tiers": {{Verbs: []string{"get"}, Resources: []string{"tiers"}, APIGroups: []string{"projectcalico.org"}}},
			"tier1-patch": {{
				Verbs:         []string{"patch"},
				Resources:     []string{"tier.networkpolicies"},
				APIGroups:     []string{"projectcalico.org"},
				ResourceNames: []string{"tier1.*"},
			}},
			"tier1-listwatch": {{
				Verbs:         []string{"watch", "list"},
				Resources:     []string{"tier.networkpolicies"},
				APIGroups:     []string{"projectcalico.org"},
				ResourceNames: []string{"tier1.*"},
			}},
			"tier2-create": {{
				Verbs:         []string{"create"},
				Resources:     []string{"tier.networkpolicies"},
				APIGroups:     []string{"projectcalico.org"},
				ResourceNames: []string{"tier2.*"},
			}},
			"tier2-delete": {{
				Verbs:         []string{"delete"},
				Resources:     []string{"tier.networkpolicies"},
				APIGroups:     []string{"projectcalico.org"},
				ResourceNames: []string{"tier2.*"},
			}},
			"wildcard-delete": {{
				Verbs:     []string{"delete"},
				Resources: []string{"tier.networkpolicies"},
				APIGroups: []string{"projectcalico.org"},
			}},
			"wildcard-create": {{
				Verbs:     []string{"create"},
				Resources: []string{"tier.networkpolicies"},
				APIGroups: []string{"projectcalico.org"},
			}},
		}

		// Request permissions for calico network policies only.
		res, err := calc.CalculatePermissions(myUser, []ResourceVerbs{{resourceCalicoNetworkPolicies, AllVerbs}})
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveLen(1))
		Expect(res).To(HaveKey(resourceCalicoNetworkPolicies))
		m := res[resourceCalicoNetworkPolicies]
		Expect(m["get"]).To(BeNil())
		Expect(m["update"]).To(BeNil())
		Expect(m["list"]).To(Equal([]Match{{Namespace: "ns3", Tier: "tier1"}}))
		Expect(m["watch"]).To(Equal([]Match{{Namespace: "ns3", Tier: "tier1"}}))
		Expect(m["create"]).To(ConsistOf([]Match{
			{Namespace: "", Tier: "default"},
			{Namespace: "", Tier: "tier1"},
			{Namespace: "", Tier: "tier2"},
			{Namespace: "", Tier: "tier3"},
			{Namespace: "", Tier: "tier4"},
		}))
		Expect(m["delete"]).To(ConsistOf([]Match{
			{Namespace: "ns2", Tier: "default"},
			{Namespace: "ns2", Tier: "tier1"},
			{Namespace: "ns2", Tier: "tier2"},
			{Namespace: "ns2", Tier: "tier3"},
			{Namespace: "ns2", Tier: "tier4"},
			{Namespace: "ns3", Tier: "tier2"},
		}))
		Expect(m["patch"]).To(Equal([]Match{{Namespace: "", Tier: "tier1"}}))
	})

	It("has fully gettable and watchable Tiers, but not listable", func() {
		mock.ClusterRoleBindings = []string{"get-watch-Tiers"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-watch-Tiers": {{
				Verbs:     []string{"get", "watch"},
				Resources: []string{"tiers"},
				APIGroups: []string{"projectcalico.org"},
			}},
		}

		// We should have watch access at cluster scope
		res, err := calc.CalculatePermissions(myUser, []ResourceVerbs{{resourceTiers, AllVerbs}})
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveKey(resourceTiers))
		nps := res[resourceTiers]
		Expect(nps).To(HaveKey(VerbList))
		Expect(nps).To(HaveKey(VerbWatch))
		Expect(nps[VerbList]).To(BeNil())
		Expect(nps[VerbWatch]).To(Equal([]Match{{}}))
	})

	It("has fully gettable Tiers, but no list and limited watch access to Tiers", func() {
		mock.ClusterRoleBindings = []string{"get-tiers", "watch-list-tiers1-2"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-tiers": {{
				Verbs:     []string{"get"},
				Resources: []string{"tiers"},
				APIGroups: []string{"projectcalico.org"},
			}},
			"watch-list-tiers1-2": {{
				Verbs:         []string{"watch"},
				Resources:     []string{"tiers"},
				ResourceNames: []string{"tier1", "tier2"},
				APIGroups:     []string{"projectcalico.org"},
			}},
		}

		// We should have watch access for specific gettable Tiers.
		res, err := calc.CalculatePermissions(myUser, []ResourceVerbs{{resourceTiers, AllVerbs}})
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveKey(resourceTiers))
		nps := res[resourceTiers]
		Expect(nps).To(HaveKey(VerbList))
		Expect(nps).To(HaveKey(VerbWatch))
		Expect(nps[VerbList]).To(BeNil())
		Expect(nps[VerbWatch]).To(Equal([]Match{{Tier: "tier1"}, {Tier: "tier2"}}))
	})

	It("has fully gettable and createable namespaces limited watch access to Namespaces", func() {
		mock.ClusterRoleBindings = []string{"get-create-namespaces", "watch-ns1-2"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-create-namespaces": {{
				Verbs:     []string{"get", "create"},
				Resources: []string{"namespaces"},
				APIGroups: []string{""},
			}},
			"watch-ns1-2": {{
				Verbs:         []string{"watch"},
				Resources:     []string{"namespaces"},
				ResourceNames: []string{"ns1", "ns2"},
				APIGroups:     []string{""},
			}},
		}

		// Namespace gets should be expanded and so whould wathc it cluster-wide watch is not authorized.
		res, err := calc.CalculatePermissions(myUser, []ResourceVerbs{{resourceNamespaces, AllVerbs}})
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveKey(resourceNamespaces))
		nps := res[resourceNamespaces]
		Expect(nps).To(HaveKey(VerbGet))
		Expect(nps).To(HaveKey(VerbCreate))
		Expect(nps).To(HaveKey(VerbWatch))
		Expect(nps[VerbWatch]).To(Equal([]Match{{Namespace: "ns1"}, {Namespace: "ns2"}}))
		Expect(nps[VerbGet]).To(Equal([]Match{{Namespace: "ns1"}, {Namespace: "ns2"}, {Namespace: "ns3"}, {Namespace: "ns4"}, {Namespace: "ns5"}}))
		Expect(nps[VerbCreate]).To(Equal([]Match{{}}))
	})

	It("has watchable networkpolicies in all Tiers and listable in tier1 and tier2", func() {
		mock.ClusterRoleBindings = []string{"get-watch-np"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-watch-np": {{
				Verbs:     []string{"get"},
				Resources: []string{"tiers"},
				APIGroups: []string{"projectcalico.org"},
			}, {
				Verbs:     []string{"watch"},
				Resources: []string{"tier.networkpolicies"},
				APIGroups: []string{"projectcalico.org"},
			}, {
				Verbs:         []string{"list"},
				Resources:     []string{"tier.networkpolicies"},
				ResourceNames: []string{"tier1.*", "tier2.*"},
				APIGroups:     []string{"projectcalico.org"},
			}},
		}

		// We should have watch access for each tier.
		res, err := calc.CalculatePermissions(myUser, []ResourceVerbs{{resourceCalicoNetworkPolicies, AllVerbs}})
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveKey(resourceCalicoNetworkPolicies))
		nps := res[resourceCalicoNetworkPolicies]
		Expect(nps).To(HaveKey(VerbList))
		Expect(nps).To(HaveKey(VerbWatch))
		Expect(nps[VerbList]).To(Equal([]Match{{Tier: "tier1"}, {Tier: "tier2"}}))
		Expect(nps[VerbWatch]).To(Equal([]Match{{Tier: "default"}, {Tier: "tier1"}, {Tier: "tier2"}, {Tier: "tier3"}, {Tier: "tier4"}}))
	})

	It("has listable networkpolicies in all Tiers and watchable in tier1 and tier2", func() {
		mock.ClusterRoleBindings = []string{"get-watch-np"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-watch-np": {{
				Verbs:     []string{"get"},
				Resources: []string{"tiers"},
				APIGroups: []string{"projectcalico.org"},
			}, {
				Verbs:     []string{"list"},
				Resources: []string{"tier.networkpolicies"},
				APIGroups: []string{"projectcalico.org"},
			}, {
				Verbs:         []string{"watch"},
				Resources:     []string{"tier.networkpolicies"},
				ResourceNames: []string{"tier1.*", "tier2.*"},
				APIGroups:     []string{"projectcalico.org"},
			}},
		}

		// List access for each tier, watch access limited to two Tiers.
		res, err := calc.CalculatePermissions(myUser, []ResourceVerbs{{resourceCalicoNetworkPolicies, AllVerbs}})
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveKey(resourceCalicoNetworkPolicies))
		nps := res[resourceCalicoNetworkPolicies]
		Expect(nps).To(HaveKey(VerbList))
		Expect(nps).To(HaveKey(VerbWatch))
		Expect(nps[VerbList]).To(Equal([]Match{{Tier: "default"}, {Tier: "tier1"}, {Tier: "tier2"}, {Tier: "tier3"}, {Tier: "tier4"}}))
		Expect(nps[VerbWatch]).To(Equal([]Match{{Tier: "tier1"}, {Tier: "tier2"}}))
	})

	It("has listable pods/status and gettable pods", func() {
		mock.ClusterRoleBindings = []string{"list-podsstatus", "get-pods"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"list-podsstatus": {{
				Verbs:     []string{"list"},
				Resources: []string{"pods/status"},
				APIGroups: []string{""},
			}},
			"get-pods": {{
				Verbs:     []string{"get"},
				Resources: []string{"pods"},
				APIGroups: []string{""},
			}},
		}

		// Check list/get access for pods and pods/status.
		rpods := resourcePods
		rpodstatus := ResourceType{APIGroup: "", Resource: "pods/status"}
		res, err := calc.CalculatePermissions(myUser, []ResourceVerbs{{rpods, AllVerbs}, {rpodstatus, AllVerbs}})
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveKey(rpods))
		Expect(res).To(HaveKey(rpodstatus))

		pods := res[rpods]
		Expect(pods).To(HaveKey(VerbGet))
		Expect(pods).To(HaveKey(VerbList))
		Expect(pods[VerbGet]).To(Equal([]Match{{}}))
		Expect(pods[VerbList]).To(BeNil())

		podstatus := res[rpodstatus]
		Expect(podstatus).To(HaveKey(VerbGet))
		Expect(podstatus).To(HaveKey(VerbList))
		Expect(podstatus[VerbGet]).To(BeNil())
		Expect(podstatus[VerbList]).To(Equal([]Match{{}}))
	})

	It("has listable/watchable networkpolicies in all Tiers, gettable only in tier2 and tier3", func() {
		mock.ClusterRoleBindings = []string{"get-watch-np"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-watch-np": {{
				Verbs:         []string{"get"},
				Resources:     []string{"tiers"},
				APIGroups:     []string{"projectcalico.org"},
				ResourceNames: []string{"tier2", "tier3"},
			}, {
				Verbs:     []string{"list"},
				Resources: []string{"tier.networkpolicies"},
				APIGroups: []string{"projectcalico.org"},
			}, {
				Verbs:     []string{"watch"},
				Resources: []string{"tier.networkpolicies"},
				APIGroups: []string{"projectcalico.org"},
			}},
		}

		// List/Watch access limited to gettable Tiers.
		res, err := calc.CalculatePermissions(myUser, []ResourceVerbs{{resourceCalicoNetworkPolicies, AllVerbs}})
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveKey(resourceCalicoNetworkPolicies))
		nps := res[resourceCalicoNetworkPolicies]
		Expect(nps).To(HaveKey(VerbList))
		Expect(nps).To(HaveKey(VerbWatch))
		Expect(nps[VerbList]).To(Equal([]Match{{Tier: "tier2"}, {Tier: "tier3"}}))
		Expect(nps[VerbWatch]).To(Equal([]Match{{Tier: "tier2"}, {Tier: "tier3"}}))
	})

	It("requeries the cache for an unknown resource type", func() {
		mock.ClusterRoleBindings = []string{"get-fake"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-fake": {{
				Verbs:     []string{"get"},
				Resources: []string{"dummy0", "dummy1", "dummy2"},
				APIGroups: []string{"fake"},
			}},
		}

		// Query resource "dummy0". This should be cached first iteration of the mock client.
		rt := ResourceType{APIGroup: "fake", Resource: "dummy0"}
		res, err := calc.CalculatePermissions(myUser, []ResourceVerbs{{rt, AllVerbs}})
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveKey(rt))
		nps := res[rt]
		Expect(nps[VerbGet]).To(Equal([]Match{{}}))

		// Query resource "dummy2". This is not in the cache.  A second query will update dummy0 to dummy1, but dummy2
		// will still not be in the cache so will not be permitted.
		rt = ResourceType{APIGroup: "fake", Resource: "dummy2"}
		res, err = calc.CalculatePermissions(myUser, []ResourceVerbs{{rt, AllVerbs}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(HaveKey(rt))
		nps = res[rt]
		Expect(nps[VerbGet]).To(BeNil())

		// Query resource "dummy2" again. This is not in the cache, but a second query will update dummy1 to dummy2.
		rt = ResourceType{APIGroup: "fake", Resource: "dummy2"}
		res, err = calc.CalculatePermissions(myUser, []ResourceVerbs{{rt, AllVerbs}})
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(HaveKey(rt))
		nps = res[rt]
		Expect(nps[VerbGet]).To(Equal([]Match{{}}))

		// Query resource "dummy0". This is not in the cache anymore because the mock client has clocked past it.
		rt = ResourceType{APIGroup: "fake", Resource: "dummy0"}
		res, err = calc.CalculatePermissions(myUser, []ResourceVerbs{{rt, AllVerbs}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(HaveKey(rt))
		nps = res[rt]
		Expect(nps[VerbGet]).To(BeNil())
	})

	It("can marshal and unmarshal a Permissions into json", func() {
		By("marshaling a Permissions struct")
		p := Permissions{
			resourceCalicoNetworkPolicies: map[Verb][]Match{
				VerbGet: {{Tier: "a", Namespace: "b"}},
			},
			resourcePods: map[Verb][]Match{
				VerbList: {{Namespace: "b"}},
			},
		}

		v, err := json.Marshal(p)
		Expect(err).NotTo(HaveOccurred())

		expected := `{
  "networkpolicies.projectcalico.org": {"get": [{"tier": "a", "namespace": "b"}]},
  "pods": {"list": [{"tier": "", "namespace": "b"}]}
}`
		Expect(v).To(MatchJSON(expected))

		By("Unmarshaling the json and comparing to the original")
		p2 := Permissions{}
		err = json.Unmarshal(v, &p2)
		Expect(err).NotTo(HaveOccurred())
		Expect(p2).To(Equal(p))
	})
})

func haveMatchAllForVerbs(expectedVerbs ...Verb) gomegatypes.GomegaMatcher {
	return haveMatchForVerbs([]Match{{}}, expectedVerbs...)
}

func haveMatchNoneForVerbs(expectedVerbs ...Verb) gomegatypes.GomegaMatcher {
	return haveMatchForVerbs(nil, expectedVerbs...)
}

func haveMatchNoneForAllVerbs() gomegatypes.GomegaMatcher {
	return haveOnlyMatchesForVerbs(nil, AllVerbs...)
}

// haveMatchForVerbs asserts that the passed verbs all have matches equal to the passed matches.
// it does nothing to assert on the remaining verbs. this should be done separately, probably with a subsequent call
// to this function.
func haveMatchForVerbs(matches []Match, verbs ...Verb) gomegatypes.GomegaMatcher {
	matchers := []gomegatypes.GomegaMatcher{}
	for _, verb := range verbs {
		matchers = append(matchers, HaveKey(verb))
		matchers = append(matchers, HaveKeyWithValue(verb, matches))
	}

	return SatisfyAll(matchers...)
}

// haveOnlyMatchesForVerbs tests that the passed verbs all have matches equal to the passed matches,
// and that all other known verbs are nil.
func haveOnlyMatchesForVerbs(matches []Match, verbs ...Verb) gomegatypes.GomegaMatcher {
	matchers := []gomegatypes.GomegaMatcher{
		HaveLen(len(AllVerbs)),
	}
	for _, verb := range AllVerbs {
		// all verbs should be present even if not expected
		matchers = append(matchers, HaveKey(verb))
		if contains(verbs, verb) {
			matchers = append(matchers, HaveKeyWithValue(verb, matches))
		} else {
			matchers = append(matchers, HaveKeyWithValue(verb, BeNil()))
		}
	}

	return SatisfyAll(matchers...)
}

func expectPresentButEmpty(p Permissions, rvs []ResourceVerbs) {
	Expect(p).To(HaveLen(len(rvs)))
	for _, rv := range rvs {
		vs, ok := p[rv.ResourceType]
		Expect(ok).To(BeTrue())
		Expect(vs).To(HaveLen(len(rv.Verbs)))
		for _, v := range rv.Verbs {
			m, ok := vs[v]
			Expect(ok).To(BeTrue())
			Expect(m).To(BeNil())
		}
	}
}

func contains[T comparable](elems []T, v T) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}
