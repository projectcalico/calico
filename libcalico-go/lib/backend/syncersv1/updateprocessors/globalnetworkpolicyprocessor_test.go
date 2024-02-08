// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
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
		up := updateprocessors.NewGlobalNetworkPolicyUpdateProcessor()

		// Basic tests with minimal and full GlobalNetworkPolicies.
		It("should accept a GlobalNetworkPolicy with a minimal configuration", func() {
			kvps, err := up.Process(&model.KVPair{Key: minimalGNPKey, Value: minimalGNP, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())
			Expect(kvps).To(HaveLen(1))

			v1Key := model.PolicyKey{Name: "minimal"}
			Expect(kvps[0]).To(Equal(&model.KVPair{
				Key: v1Key,
				Value: &model.Policy{
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
			v1Key := model.PolicyKey{Name: "full"}
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

			v1Key := model.PolicyKey{Name: "empty"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: nil}}))
		})

		// GlobalNetworkPolicies with valid, invalid and 'all()' ServiceAccountSelectors.
		It("should accept a GlobalNetworkPolicy with a ServiceAccountSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: validSASelectorKey, Value: validSASelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `(mylabel == 'selectme') && pcsa.role == "development"`
			v1Key := model.PolicyKey{Name: "valid-sa-selector"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should NOT add an invalid ServiceAccountSelector to the GNP's Selector field", func() {
			kvps, err := up.Process(&model.KVPair{Key: invalidSASelectorKey, Value: invalidSASelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `mylabel == 'selectme'`
			v1Key := model.PolicyKey{Name: "invalid-sa-selector"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should accept a GlobalNetworkPolicy with 'all()' as the ServiceAccountSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: allSASelectorKey, Value: allSASelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `(mylabel == 'selectme') && has(projectcalico.org/serviceaccount)`
			v1Key := model.PolicyKey{Name: "all-sa-selector"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		// GlobalNetworkPolicies with valid, invalid and 'all()' NamespaceSelectors.
		It("should accept a GlobalNetworkPolicy with a NamespaceSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: validNSSelectorKey, Value: validNSSelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `(mylabel == 'selectme') && pcns.name == "testing"`
			v1Key := model.PolicyKey{Name: "valid-ns-selector"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should NOT add an invalid NamespaceSelector to the GNP's Selector field", func() {
			kvps, err := up.Process(&model.KVPair{Key: invalidNSSelectorKey, Value: invalidNSSelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `mylabel == 'selectme'`
			v1Key := model.PolicyKey{Name: "invalid-ns-selector"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should accept a GlobalNetworkPolicy with 'all()' as the NamespaceSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: allNSSelectorKey, Value: allNSSelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `(mylabel == 'selectme') && has(projectcalico.org/namespace)`
			v1Key := model.PolicyKey{Name: "all-ns-selector"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		// GlobalNetworkPolicies both ServiceAccountSelectors and NamespaceSelectors.
		It("should accept a GlobalNetworkPolicy with a ServiceAccountSelector and s NamespaceSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: SAandNSSelectorKey, Value: SAandNSSelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `((mylabel == 'selectme') && pcns.name == "testing") && pcsa.role == "development"`
			v1Key := model.PolicyKey{Name: "sa-and-ns-selector"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		// GlobalNetworkPolicies without a Selector and with combinations of ServiceAccount and Namespace selectors.
		It("should accept a GlobalNetworkPolicy without a Selector but with a ServiceAccountSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: noSelWithSASelectorKey, Value: noSelWithSASelector,
				Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `pcsa.role == "development"`
			v1Key := model.PolicyKey{Name: "no-sel-with-sa-selector"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should accept a GlobalNetworkPolicy without a Selector but with a NamespaceSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: noSelWithNSSelectorKey, Value: noSelWithNSSelector,
				Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullGNPv1()
			policy.Selector = `pcns.name == "testing"`
			v1Key := model.PolicyKey{Name: "no-sel-with-ns-selector"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should accept a GlobalNetworkPolicy without a Selector but with a NamespaceSelector and ServiceAccountSelector",
			func() {
				kvps, err := up.Process(&model.KVPair{Key: noSelWithSAandNSSelectorKey,
					Value: noSelWithSAandNSSelector, Revision: testRev})
				Expect(err).NotTo(HaveOccurred())

				policy := fullGNPv1()
				policy.Selector = `(pcns.name == "testing") && pcsa.role == "development"`
				v1Key := model.PolicyKey{Name: "no-sel-with-ns-and-sa-selector"}
				Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
			})
	})
})
