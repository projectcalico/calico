// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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

package updateprocessors_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clusternetpol "sigs.k8s.io/network-policy-api/apis/v1alpha2"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("Test the GlobalNetworkPolicy update processor", func() {
	ns1 := "default"
	selector := "mylabel == 'selectme'"

	emptyGNPKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "empty"}
	emptyGNP := apiv3.NewGlobalNetworkPolicy()

	minimalGNPKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "minimal"}
	minimalGNP := apiv3.NewGlobalNetworkPolicy()
	minimalGNP.Spec.PreDNAT = true
	minimalGNP.Spec.ApplyOnForward = true

	fullGNPKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "full"}
	fullGNP := fullGNPv3(ns1, selector)

	// GlobalNetworkPolicies with valid, invalid and 'all()' ServiceAccountSelectors.
	validSASelectorKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "valid-sa-selector"}
	validSASelector := fullGNPv3(ns1, selector)
	validSASelector.Spec.ServiceAccountSelector = "role == 'development'"

	invalidSASelectorKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "invalid-sa-selector"}
	invalidSASelector := fullGNPv3(ns1, selector)
	invalidSASelector.Spec.ServiceAccountSelector = "role 'development'"

	allSASelectorKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "all-sa-selector"}
	allSASelector := fullGNPv3(ns1, selector)
	allSASelector.Spec.ServiceAccountSelector = "all()"

	// GlobalNetworkPolicies with valid, invalid and 'all()' NamespaceSelectors.
	validNSSelectorKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "valid-ns-selector"}
	validNSSelector := fullGNPv3(ns1, selector)
	validNSSelector.Spec.NamespaceSelector = "name == 'testing'"

	invalidNSSelectorKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "invalid-ns-selector"}
	invalidNSSelector := fullGNPv3(ns1, selector)
	invalidNSSelector.Spec.NamespaceSelector = "name 'testing'"

	allNSSelectorKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "all-ns-selector"}
	allNSSelector := fullGNPv3(ns1, selector)
	allNSSelector.Spec.NamespaceSelector = "all()"

	// GlobalNetworkPolicies both ServiceAccountSelectors and NamespaceSelectors.
	SAandNSSelectorKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "sa-and-ns-selector"}
	SAandNSSelector := fullGNPv3(ns1, selector)
	SAandNSSelector.Spec.ServiceAccountSelector = "role == 'development'"
	SAandNSSelector.Spec.NamespaceSelector = "name == 'testing'"

	// GlobalNetworkPolicies without a Selector and with combinations of ServiceAccount and Namespace selectors.
	noSelWithSASelectorKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "no-sel-with-sa-selector"}
	noSelWithSASelector := fullGNPv3(ns1, "")
	noSelWithSASelector.Spec.ServiceAccountSelector = "role == 'development'"

	noSelWithNSSelectorKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "no-sel-with-ns-selector"}
	noSelWithNSSelector := fullGNPv3(ns1, "")
	noSelWithNSSelector.Spec.NamespaceSelector = "name == 'testing'"

	noSelWithSAandNSSelectorKey := model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "no-sel-with-ns-and-sa-selector"}
	noSelWithSAandNSSelector := fullGNPv3(ns1, "")
	noSelWithSAandNSSelector.Spec.ServiceAccountSelector = "role == 'development'"
	noSelWithSAandNSSelector.Spec.NamespaceSelector = "name == 'testing'"

	Context("test processing of a valid GlobalNetworkPolicy from V3 to V1", func() {
		up := updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(apiv3.KindGlobalNetworkPolicy)

		// Basic tests with minimal and full GlobalNetworkPolicies.
		It("should accept a GlobalNetworkPolicy with a minimal configuration", func() {
			kvps, err := up.Process(&model.KVPair{Key: minimalGNPKey, Value: minimalGNP, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())
			Expect(kvps).To(HaveLen(1))

			v1Key := model.PolicyKey{
				Name: "minimal",
				Kind: apiv3.KindGlobalNetworkPolicy,
			}
			Expect(kvps[0]).To(Equal(&model.KVPair{
				Key: v1Key,
				Value: &model.Policy{
					Tier:           "default",
					PreDNAT:        true,
					ApplyOnForward: true,
				},
				Revision: testRev,
			}))
		})

		It("should accept a GlobalNetworkPolicy with a full configuration", func() {
			kvps, err := up.Process(&model.KVPair{Key: fullGNPKey, Value: fullGNP, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `mylabel == 'selectme'`
			v1Key := model.PolicyKey{
				Name: "full",
				Kind: apiv3.KindGlobalNetworkPolicy,
			}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))

			By("should be able to delete the full network policy")
			kvps, err = up.Process(&model.KVPair{Key: fullGNPKey, Value: nil})
			Expect(err).NotTo(HaveOccurred())
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: nil}}))
		})

		It("should NOT accept a GlobalNetworkPolicy with the wrong Key type", func() {
			_, err := up.Process(&model.KVPair{
				Key:      model.GlobalBGPPeerKey{PeerIP: cnet.MustParseIP("1.2.3.4")},
				Value:    emptyGNP,
				Revision: "abcde",
			})
			Expect(err).To(HaveOccurred())
		})

		It("should NOT accept a GlobalNetworkPolicy with the wrong Value type", func() {
			kvps, err := up.Process(&model.KVPair{Key: emptyGNPKey, Value: apiv3.NewHostEndpoint(), Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			v1Key := model.PolicyKey{
				Name: "empty",
				Kind: apiv3.KindGlobalNetworkPolicy,
			}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: nil}}))
		})

		// GlobalNetworkPolicies with valid, invalid and 'all()' ServiceAccountSelectors.
		It("should accept a GlobalNetworkPolicy with a ServiceAccountSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: validSASelectorKey, Value: validSASelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `(mylabel == 'selectme') && pcsa.role == "development"`
			v1Key := model.PolicyKey{
				Name: "valid-sa-selector",
				Kind: apiv3.KindGlobalNetworkPolicy,
			}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should NOT add an invalid ServiceAccountSelector to the GNP's Selector field", func() {
			kvps, err := up.Process(&model.KVPair{Key: invalidSASelectorKey, Value: invalidSASelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `mylabel == 'selectme'`
			v1Key := model.PolicyKey{
				Name: "invalid-sa-selector",
				Kind: apiv3.KindGlobalNetworkPolicy,
			}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should accept a GlobalNetworkPolicy with 'all()' as the ServiceAccountSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: allSASelectorKey, Value: allSASelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `(mylabel == 'selectme') && has(projectcalico.org/serviceaccount)`
			v1Key := model.PolicyKey{
				Name: "all-sa-selector",
				Kind: apiv3.KindGlobalNetworkPolicy,
			}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		// GlobalNetworkPolicies with valid, invalid and 'all()' NamespaceSelectors.
		It("should accept a GlobalNetworkPolicy with a NamespaceSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: validNSSelectorKey, Value: validNSSelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `(mylabel == 'selectme') && pcns.name == "testing"`
			v1Key := model.PolicyKey{
				Name: "valid-ns-selector",
				Kind: apiv3.KindGlobalNetworkPolicy,
			}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should NOT add an invalid NamespaceSelector to the GNP's Selector field", func() {
			kvps, err := up.Process(&model.KVPair{Key: invalidNSSelectorKey, Value: invalidNSSelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `mylabel == 'selectme'`
			v1Key := model.PolicyKey{
				Name: "invalid-ns-selector",
				Kind: apiv3.KindGlobalNetworkPolicy,
			}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should accept a GlobalNetworkPolicy with 'all()' as the NamespaceSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: allNSSelectorKey, Value: allNSSelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `(mylabel == 'selectme') && has(projectcalico.org/namespace)`
			v1Key := model.PolicyKey{
				Name: "all-ns-selector",
				Kind: apiv3.KindGlobalNetworkPolicy,
			}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		// GlobalNetworkPolicies both ServiceAccountSelectors and NamespaceSelectors.
		It("should accept a GlobalNetworkPolicy with a ServiceAccountSelector and s NamespaceSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: SAandNSSelectorKey, Value: SAandNSSelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `((mylabel == 'selectme') && pcns.name == "testing") && pcsa.role == "development"`
			v1Key := model.PolicyKey{
				Name: "sa-and-ns-selector",
				Kind: apiv3.KindGlobalNetworkPolicy,
			}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		// GlobalNetworkPolicies without a Selector and with combinations of ServiceAccount and Namespace selectors.
		It("should accept a GlobalNetworkPolicy without a Selector but with a ServiceAccountSelector", func() {
			kvps, err := up.Process(&model.KVPair{
				Key: noSelWithSASelectorKey, Value: noSelWithSASelector,
				Revision: testRev,
			})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `pcsa.role == "development"`
			v1Key := model.PolicyKey{
				Name: "no-sel-with-sa-selector",
				Kind: apiv3.KindGlobalNetworkPolicy,
			}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should accept a GlobalNetworkPolicy without a Selector but with a NamespaceSelector", func() {
			kvps, err := up.Process(&model.KVPair{
				Key: noSelWithNSSelectorKey, Value: noSelWithNSSelector,
				Revision: testRev,
			})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `pcns.name == "testing"`
			v1Key := model.PolicyKey{
				Name: "no-sel-with-ns-selector",
				Kind: apiv3.KindGlobalNetworkPolicy,
			}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should accept a GlobalNetworkPolicy without a Selector but with a NamespaceSelector and ServiceAccountSelector",
			func() {
				kvps, err := up.Process(&model.KVPair{
					Key:   noSelWithSAandNSSelectorKey,
					Value: noSelWithSAandNSSelector, Revision: testRev,
				})
				Expect(err).NotTo(HaveOccurred())

				policy := fullGNPv1()
				policy.Selector = `(pcns.name == "testing") && pcsa.role == "development"`
				v1Key := model.PolicyKey{
					Name: "no-sel-with-ns-and-sa-selector",
					Kind: apiv3.KindGlobalNetworkPolicy,
				}
				Expect(kvps).To(Equal(
					[]*model.KVPair{{
						Key:      v1Key,
						Value:    &policy,
						Revision: testRev,
					}},
				))
			})
	})
})

// Define ClusterNetworkPolicies and the corresponding expected v1 KVPairs.
//
// kcnp1 is a k8s ClusterNetworkPolicy with a single Egress rule, which contains ports only,
// and no selectors.
var (
	kcnpOrder = float64(1000.0)
	ports     = []clusternetpol.ClusterNetworkPolicyPort{{
		PortNumber: &clusternetpol.Port{
			Port: 80,
		},
	}}
	kcnp1 = clusternetpol.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test.policy",
			UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
		},
		Spec: clusternetpol.ClusterNetworkPolicySpec{
			Subject: clusternetpol.ClusterNetworkPolicySubject{
				Namespaces: &metav1.LabelSelector{},
			},
			Tier:     clusternetpol.AdminTier,
			Priority: 1000,
			Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
				{
					Action: "Accept",
					To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
						{
							Namespaces: &metav1.LabelSelector{},
						},
					},
					Ports: &ports,
				},
			},
		},
	}
)

// expected1 is the expected v1 KVPair representation of kcnp1 from above.
var (
	expectedModel1 = []*model.KVPair{
		{
			Key: model.PolicyKey{
				Name: fmt.Sprintf("%vtest.policy", names.K8sCNPAdminTierNamePrefix),
				Kind: model.KindKubernetesClusterNetworkPolicy,
			},
			Value: &model.Policy{
				Tier:           names.KubeAdminTierName,
				Order:          &kcnpOrder,
				Selector:       "(projectcalico.org/orchestrator == 'k8s') && has(projectcalico.org/namespace)",
				Types:          []string{"egress"},
				ApplyOnForward: false,
				OutboundRules: []model.Rule{
					{
						Action:                       "allow",
						Protocol:                     &tcp,
						SrcSelector:                  "",
						DstSelector:                  "has(projectcalico.org/namespace)",
						OriginalDstNamespaceSelector: "all()",
						DstPorts:                     []numorstring.Port{port80},
					},
				},
			},
		},
	}
)

// kcnp2 is a k8s ClusterNetworkPolicy with a single Ingress rule which allows from all namespaces.
var kcnp2 = clusternetpol.ClusterNetworkPolicy{
	ObjectMeta: metav1.ObjectMeta{
		Name: "test.policy",
		UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
	},
	Spec: clusternetpol.ClusterNetworkPolicySpec{
		Subject: clusternetpol.ClusterNetworkPolicySubject{
			Pods: &clusternetpol.NamespacedPod{
				PodSelector: metav1.LabelSelector{},
			},
		},
		Priority: 1000,
		Tier:     clusternetpol.BaselineTier,
		Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
			{
				Action: "Accept",
				From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
					{
						Namespaces: &metav1.LabelSelector{},
					},
				},
			},
		},
	},
}

var expectedModel2 = []*model.KVPair{
	{
		Key: model.PolicyKey{
			Name: fmt.Sprintf("%vtest.policy", names.K8sCNPBaselineTierNamePrefix),
			Kind: model.KindKubernetesClusterNetworkPolicy,
		},
		Value: &model.Policy{
			Tier:           names.KubeBaselineTierName,
			Order:          &kcnpOrder,
			Selector:       "(projectcalico.org/orchestrator == 'k8s') && has(projectcalico.org/namespace)",
			Types:          []string{"ingress"},
			ApplyOnForward: false,
			InboundRules: []model.Rule{
				{
					Action:                       "allow",
					SrcSelector:                  "has(projectcalico.org/namespace)",
					DstSelector:                  "",
					OriginalSrcSelector:          "",
					OriginalSrcNamespaceSelector: "all()",
				},
			},
		},
	},
}

var _ = Describe("Test the ClusterNetworkPolicy update processor + conversion", func() {
	up := updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(model.KindKubernetesClusterNetworkPolicy)

	DescribeTable("GlobalNetworkPolicy update processor + conversion tests",
		func(cnp clusternetpol.ClusterNetworkPolicy, expected []*model.KVPair) {
			// First, convert the ClusterNetworkPolicy using the k8s conversion logic.
			c := conversion.NewConverter()
			kvp, err := c.K8sClusterNetworkPolicyToCalico(&cnp)
			Expect(err).NotTo(HaveOccurred())

			// Next, run the policy through the update processor.
			out, err := up.Process(kvp)
			Expect(err).NotTo(HaveOccurred())

			// Finally, assert the expected result.
			Expect(out).To(Equal(expected))
		},

		Entry("should handle an ClusterNetworkPolicy with no rule selectors", kcnp1, expectedModel1),
		Entry("should handle an ClusterNetworkPolicy with an empty ns selector", kcnp2, expectedModel2),
	)
})
