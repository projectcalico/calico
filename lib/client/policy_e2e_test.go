// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

// Test cases (Policy object e2e):
// Test 1: Pass two fully populated PolicySpecs and expect the series of operations to succeed.
// Test 2: Pass one fully populated PolicySpec and another empty PolicySpec and expect the series of operations to succeed.
// Test 3: Pass one partially populated PolicySpec and another fully populated PolicySpec and expect the series of operations to succeed.

// Series of operations each test goes through:
// Update meta1 - check for failure (because it doesn't exist).
// Create meta1 with spec1.
// Apply meta2 with spec2.
// Get meta1 and meta2, compare spec1 and spec2.
// Update meta1 with spec2.
// Get meta1 compare spec2.
// List (empty Meta) ... Get meta1 and meta2.
// List (using Meta1) ... Get meta1.
// Delete meta1.
// Get meta1 ... fail.
// Delete meta2.
// List (empty Meta) ... Get no entries (should not error).

package client_test

import (
	"errors"
	"log"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

var order1 = 99.999
var order2 = 22.222

var policySpec1 = api.PolicySpec{
	Order:        &order1,
	IngressRules: []api.Rule{testutils.InRule1, testutils.InRule2},
	EgressRules:  []api.Rule{testutils.EgressRule1, testutils.EgressRule2},
	Selector:     "thing == 'value'",
}

// When reading back, the rules should have been updated to the newer format.
var policySpec1AfterRead = api.PolicySpec{
	Order:        &order1,
	IngressRules: []api.Rule{testutils.InRule1AfterRead, testutils.InRule2AfterRead},
	EgressRules:  []api.Rule{testutils.EgressRule1AfterRead, testutils.EgressRule2AfterRead},
	Selector:     "thing == 'value'",
	Types:        []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress},
}

var policySpec2 = api.PolicySpec{
	Order:          &order2,
	IngressRules:   []api.Rule{testutils.InRule2, testutils.InRule1},
	EgressRules:    []api.Rule{testutils.EgressRule2, testutils.EgressRule1},
	Selector:       "thing2 == 'value2'",
	DoNotTrack:     true,
	ApplyOnForward: true,
}

// When reading back, the rules should have been updated to the newer format.
var policySpec2AfterRead = api.PolicySpec{
	Order:          &order2,
	IngressRules:   []api.Rule{testutils.InRule2AfterRead, testutils.InRule1AfterRead},
	EgressRules:    []api.Rule{testutils.EgressRule2AfterRead, testutils.EgressRule1AfterRead},
	Selector:       "thing2 == 'value2'",
	DoNotTrack:     true,
	ApplyOnForward: true,
	Types:          []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress},
}

var policySpec3 = api.PolicySpec{
	Order:          &order2,
	IngressRules:   []api.Rule{testutils.InRule2, testutils.InRule1},
	Selector:       "thing2 == 'value2'",
	PreDNAT:        true,
	ApplyOnForward: true,
}

// When reading back, the rules should have been updated to the newer format.
var policySpec3AfterRead = api.PolicySpec{
	Order:          &order2,
	IngressRules:   []api.Rule{testutils.InRule2AfterRead, testutils.InRule1AfterRead},
	Selector:       "thing2 == 'value2'",
	PreDNAT:        true,
	ApplyOnForward: true,
	Types:          []api.PolicyType{api.PolicyTypeIngress},
}

// When reading back, an empty policy has Types 'ingress'.
var emptyPolicyAfterRead = api.PolicySpec{
	Types: []api.PolicyType{api.PolicyTypeIngress},
}

var egressPolicy = api.PolicySpec{
	Order:       &order2,
	EgressRules: []api.Rule{testutils.InRule2, testutils.InRule1},
	Selector:    "thing2 == 'value2'",
}

// When reading back, the rules should have been updated to the newer format.
var egressPolicyAfterRead = api.PolicySpec{
	Order:       &order2,
	EgressRules: []api.Rule{testutils.InRule2AfterRead, testutils.InRule1AfterRead},
	Selector:    "thing2 == 'value2'",
	Types:       []api.PolicyType{api.PolicyTypeEgress},
}

var _ = testutils.E2eDatastoreDescribe("Policy tests", testutils.DatastoreEtcdV2, func(config api.CalicoAPIConfig) {

	DescribeTable("Policy e2e tests",
		func(meta1, meta2 api.PolicyMetadata, spec1, spec2, spec1AfterRead, spec2AfterRead api.PolicySpec) {
			c := testutils.CreateCleanClient(config)
			By("Updating the policy before it is created")
			_, outError := c.Policies().Update(&api.Policy{Metadata: meta1, Spec: spec1})

			// Should return an error.
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: Policy(name=policy-1/with.foo)").Error()))

			By("Create, Apply, Get and compare")

			// Create a policy with meta1 and spec1.
			_, outError = c.Policies().Create(&api.Policy{Metadata: meta1, Spec: spec1})
			Expect(outError).NotTo(HaveOccurred())

			// Apply a policy with meta2 and spec2.
			_, outError = c.Policies().Apply(&api.Policy{Metadata: meta2, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get policy with meta1.
			outPolicy1, outError1 := c.Policies().Get(meta1)
			log.Println("Out Policy object: ", outPolicy1)

			// Get policy with meta2.
			outPolicy2, outError2 := c.Policies().Get(meta2)
			log.Println("Out Policy object: ", outPolicy2)

			// Should match spec1 & outPolicy1 and outPolicy2 & spec2 and errors to be nil.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outError2).NotTo(HaveOccurred())
			Expect(outPolicy1.Spec).To(Equal(spec1AfterRead))
			Expect(outPolicy2.Spec).To(Equal(spec2AfterRead))

			By("Update, Get and compare")

			// Update meta1 policy with spec2.
			_, outError = c.Policies().Update(&api.Policy{Metadata: meta1, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get policy with meta1.
			outPolicy1, outError1 = c.Policies().Get(meta1)

			// Assert the Spec for policy with meta1 matches spec2 and no error.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outPolicy1.Spec).To(Equal(spec2AfterRead))

			// Assert the Metadata for policy with meta1 matches meta1.
			Expect(outPolicy1.Metadata).To(Equal(meta1))

			By("List all the policies and compare")

			// Get a list of policiess.
			policyList, outError := c.Policies().List(api.PolicyMetadata{})
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get policy list returns: ", policyList.Items)
			metas := []api.PolicyMetadata{meta1, meta2}
			expectedPolicies := []api.Policy{}
			// Go through meta list and append them to expectedPolicies.
			for _, v := range metas {
				p, outError := c.Policies().Get(v)
				Expect(outError).NotTo(HaveOccurred())
				expectedPolicies = append(expectedPolicies, *p)
			}

			// Assert the returned policyList is has the meta1 and meta2 policies.
			Expect(policyList.Items).To(Equal(expectedPolicies))

			By("List a specific policy and compare")

			// Get a policy list with meta1.
			policyList, outError = c.Policies().List(meta1)
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get policy list returns: ", policyList.Items)

			// Get a policy with meta1.
			outPolicy1, outError1 = c.Policies().Get(meta1)

			// Assert they are equal and no errors.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(policyList.Items[0].Spec).To(Equal(outPolicy1.Spec))

			By("Delete, Get and assert error")

			// Delete a policy with meta1.
			outError1 = c.Policies().Delete(meta1)
			Expect(outError1).NotTo(HaveOccurred())

			// Get a policy with meta1.
			_, outError = c.Policies().Get(meta1)

			// Expect an error since the policy was deleted.
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: Policy(name=policy-1/with.foo)").Error()))

			// Delete the second policy with meta2.
			outError1 = c.Policies().Delete(meta2)
			Expect(outError1).NotTo(HaveOccurred())

			By("Delete all the policies, Get policy list and expect empty policy list")

			// Both policies are deleted in the calls above.
			// Get the list of all the policys.
			policyList, outError = c.Policies().List(api.PolicyMetadata{})
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get policy list returns: ", policyList.Items)

			// Create an empty policy list.
			// Note: you can't use make([]api.Policy, 0) because it creates an empty underlying struct,
			// whereas new([]api.Policy) just returns a pointer without creating an empty struct.
			emptyPolicyList := new([]api.Policy)

			// Expect returned policyList to contain empty policyList.
			Expect(policyList.Items).To(Equal(*emptyPolicyList))

		},

		// Test 1: Pass two fully populated PolicySpecs and expect the series of operations to succeed.
		Entry("Two fully populated PolicySpecs",
			api.PolicyMetadata{Name: "policy-1/with.foo", Annotations: map[string]string{"key": "value"}},
			api.PolicyMetadata{Name: "policy.1"},
			policySpec1,
			policySpec2,
			policySpec1AfterRead,
			policySpec2AfterRead,
		),

		// Test 2: Pass one fully populated PolicySpec and another empty PolicySpec and expect the series of operations to succeed.
		Entry("One fully populated PolicySpec and another empty PolicySpec",
			api.PolicyMetadata{Name: "policy-1/with.foo"},
			api.PolicyMetadata{Name: "policy.1"},
			policySpec1,
			api.PolicySpec{},
			policySpec1AfterRead,
			emptyPolicyAfterRead,
		),

		// Test 3: Pass one partially populated PolicySpec and another fully populated PolicySpec and expect the series of operations to succeed.
		Entry("One partially populated PolicySpec and another fully populated PolicySpec",
			api.PolicyMetadata{Name: "policy-1/with.foo"},
			api.PolicyMetadata{Name: "policy_1/with.foo/with_bar"},
			api.PolicySpec{
				Selector: "has(myLabel-8.9/88-._9)",
			},
			policySpec2,
			api.PolicySpec{
				Selector: "has(myLabel-8.9/88-._9)",
				Types:    []api.PolicyType{api.PolicyTypeIngress},
			},
			policySpec2AfterRead,
		),

		// Test 4: Two fully populated PolicySpecs, one untracked and one pre-DNAT.
		Entry("Two fully populated PolicySpecs, one untracked and one pre-DNAT",
			api.PolicyMetadata{Name: "policy-1/with.foo", Annotations: map[string]string{"key": "value"}},
			api.PolicyMetadata{Name: "policy.1"},
			policySpec3,
			policySpec2,
			policySpec3AfterRead,
			policySpec2AfterRead,
		),

		// An egress Policy and an ingress Policy.
		Entry("An egress Policy and an ingress Policy",
			api.PolicyMetadata{Name: "policy-1/with.foo", Annotations: map[string]string{"key": "value"}},
			api.PolicyMetadata{Name: "policy.1"},
			egressPolicy,
			policySpec2,
			egressPolicyAfterRead,
			policySpec2AfterRead,
		),
	)
})
