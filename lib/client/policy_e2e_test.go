// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	Selector:     "policy1-selector",
}

var policySpec2 = api.PolicySpec{
	Order:        &order2,
	IngressRules: []api.Rule{testutils.InRule2, testutils.InRule1},
	EgressRules:  []api.Rule{testutils.EgressRule2, testutils.EgressRule1},
	Selector:     "policy2-selector",
}

var _ = Describe("Policy tests", func() {

	DescribeTable("Policy e2e tests",
		func(meta1, meta2 api.PolicyMetadata, spec1, spec2 api.PolicySpec) {

			// Erase etcd clean.
			testutils.CleanEtcd()

			// Create a new client.
			c, err := testutils.NewClient("")
			if err != nil {
				log.Println("Error creating client:", err)
			}
			By("Updating the policy before it is created")
			_, outError := c.Policies().Update(&api.Policy{Metadata: meta1, Spec: spec1})

			// Should return an error.
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: Policy(name=policy1)").Error()))

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
			Expect(outPolicy1.Spec).To(Equal(spec1))
			Expect(outPolicy2.Spec).To(Equal(spec2))

			By("Update, Get and compare")

			// Update meta1 policy with spec2.
			_, outError = c.Policies().Update(&api.Policy{Metadata: meta1, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get policy with meta1.
			outPolicy1, outError1 = c.Policies().Get(meta1)

			// Assert the Spec for policy with meta1 matches spec2 and no error.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outPolicy1.Spec).To(Equal(spec2))

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
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: Policy(name=policy1)").Error()))

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
			api.PolicyMetadata{Name: "policy1"},
			api.PolicyMetadata{Name: "policy2"},
			policySpec1,
			policySpec2,
		),

		// Test 2: Pass one fully populated PolicySpec and another empty PolicySpec and expect the series of operations to succeed.
		Entry("One fully populated PolicySpec and another empty PolicySpec",
			api.PolicyMetadata{Name: "policy1"},
			api.PolicyMetadata{Name: "policy2"},
			policySpec1,
			api.PolicySpec{},
		),

		// Test 3: Pass one partially populated PolicySpec and another fully populated PolicySpec and expect the series of operations to succeed.
		Entry("One partially populated PolicySpec and another fully populated PolicySpec",
			api.PolicyMetadata{Name: "policy1"},
			api.PolicyMetadata{Name: "policy2"},
			api.PolicySpec{
				Selector: "policy1-selector",
			},
			policySpec2,
		),
	)
})
