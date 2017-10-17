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

// Test cases (Profile object e2e):
// Test 1: Pass two fully populated ProfileSpecs and expect the series of operations to succeed.
// Test 2: Pass one fully populated ProfileSpec and another empty ProfileSpec and expect the series of operations to succeed.
// Test 3: Pass one partially populated ProfileSpec and another fully populated ProfileSpec and expect the series of operations to succeed.

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

var profileSpec1 = api.ProfileSpec{
	IngressRules: []api.Rule{testutils.InRule1, testutils.InRule2},
	EgressRules:  []api.Rule{testutils.EgressRule1, testutils.EgressRule2},
}

// When reading back, the rules should have been updated to the newer format.
var profileSpec1AfterRead = api.ProfileSpec{
	IngressRules: []api.Rule{testutils.InRule1AfterRead, testutils.InRule2AfterRead},
	EgressRules:  []api.Rule{testutils.EgressRule1AfterRead, testutils.EgressRule2AfterRead},
}
var tags1 = []string{"profile1-tag1", "profile1-tag2"}

var profileSpec2 = api.ProfileSpec{
	IngressRules: []api.Rule{testutils.InRule2, testutils.InRule1},
	EgressRules:  []api.Rule{testutils.EgressRule2, testutils.EgressRule1},
}

// When reading back, the rules should have been updated to the newer format.
var profileSpec2AfterRead = api.ProfileSpec{
	IngressRules: []api.Rule{testutils.InRule2AfterRead, testutils.InRule1AfterRead},
	EgressRules:  []api.Rule{testutils.EgressRule2AfterRead, testutils.EgressRule1AfterRead},
}
var tags2 = []string{"profile2-tag1", "profile2-tag2"}

var _ = testutils.E2eDatastoreDescribe("Profile tests", testutils.DatastoreEtcdV2, func(config api.CalicoAPIConfig) {

	DescribeTable("Profile e2e tests",
		func(meta1, meta2 api.ProfileMetadata, spec1, spec2, spec1AfterRead, spec2AfterRead api.ProfileSpec) {
			c := testutils.CreateCleanClient(config)

			By("Updating the profile before it is created")
			_, outError := c.Profiles().Update(&api.Profile{Metadata: meta1, Spec: spec1})

			// Should return an error.
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: ProfileTags(name=profile1)").Error()))

			By("Create, Apply, Get and compare")

			// Create a profile with meta1 and spec1.
			_, outError = c.Profiles().Create(&api.Profile{Metadata: meta1, Spec: spec1})
			Expect(outError).NotTo(HaveOccurred())

			// Apply a profile with meta2 and spec2.
			_, outError = c.Profiles().Apply(&api.Profile{Metadata: meta2, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get profile with meta1.
			outProfile1, outError1 := c.Profiles().Get(meta1)
			log.Println("Out Profile object: ", outProfile1)

			// Get profile with meta2.
			outProfile2, outError2 := c.Profiles().Get(meta2)
			log.Println("Out Profile object: ", outProfile2)

			// Should match spec1 & outProfile1 and outProfile2 & spec2 and errors to be nil.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outError2).NotTo(HaveOccurred())
			Expect(outProfile1.Spec).To(Equal(spec1AfterRead))
			Expect(outProfile2.Spec).To(Equal(spec2AfterRead))

			By("Update, Get and compare")

			// Update meta1 profile with spec2.
			_, outError = c.Profiles().Update(&api.Profile{Metadata: meta1, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get profile with meta1.
			outProfile1, outError1 = c.Profiles().Get(meta1)

			// Assert the Spec for profile with meta1 matches spec2 and no error.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outProfile1.Spec).To(Equal(spec2AfterRead))

			By("List all the profiles and compare")

			// Get a list of profiless.
			profileList, outError := c.Profiles().List(api.ProfileMetadata{})
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get profile list returns: ", profileList.Items)
			metas := []api.ProfileMetadata{meta1, meta2}
			expectedProfiles := []api.Profile{}
			// Go through meta list and append them to expectedProfiles.
			for _, v := range metas {
				p, outError := c.Profiles().Get(v)
				Expect(outError).NotTo(HaveOccurred())
				expectedProfiles = append(expectedProfiles, *p)
			}

			// Assert the returned profileList is has the meta1 and meta2 profiles.
			Expect(profileList.Items).To(Equal(expectedProfiles))

			By("List a specific profile and compare")

			// Get a profile list with meta1.
			profileList, outError = c.Profiles().List(meta1)
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get profile list returns: ", profileList.Items)

			// Get a profile with meta1.
			outProfile1, outError1 = c.Profiles().Get(meta1)

			// Assert they are equal and no errors.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(profileList.Items[0].Spec).To(Equal(outProfile1.Spec))

			By("Delete, Get and assert error")

			// Delete a profile with meta1.
			outError1 = c.Profiles().Delete(meta1)
			Expect(outError1).NotTo(HaveOccurred())

			// Get a profile with meta1.
			_, outError = c.Profiles().Get(meta1)

			// Expect an error since the profile was deleted.
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: ProfileTags(name=profile1)").Error()))

			// Delete the second profile with meta2.
			outError1 = c.Profiles().Delete(meta2)
			Expect(outError1).NotTo(HaveOccurred())

			By("Delete all the profiles, Get profile list and expect empty profile list")

			// Both profiles are deleted in the calls above.
			// Get the list of all the profiles.
			profileList, outError = c.Profiles().List(api.ProfileMetadata{})
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get profile list returns: ", profileList.Items)

			// Create an empty profile list.
			// Note: you can't use make([]api.Profile, 0) because it creates an empty underlying struct,
			// whereas new([]api.Profile) just returns a pointer without creating an empty struct.
			emptyProfileList := new([]api.Profile)

			// Expect returned profileList to contain empty profileList.
			Expect(profileList.Items).To(Equal(*emptyProfileList))

		},

		// Test 1: Pass two fully populated ProfileSpecs and expect the series of operations to succeed.
		Entry("Two fully populated ProfileSpecs",
			api.ProfileMetadata{
				Name: "profile1",
				Labels: map[string]string{
					"app":  "app-abc",
					"prod": "yes",
				},
				Tags: tags1,
			},
			api.ProfileMetadata{
				Name: "profile1/with_foo",
				Labels: map[string]string{
					"app":  "app-xyz",
					"prod": "no",
				},
				Tags: tags2,
			},
			profileSpec1,
			profileSpec2,
			profileSpec1AfterRead,
			profileSpec2AfterRead,
		),

		// Test 2: Pass one fully populated ProfileSpec and another empty ProfileSpec and expect the series of operations to succeed.
		Entry("One fully populated ProfileSpec and another empty ProfileSpec",
			api.ProfileMetadata{
				Name: "profile1",
				Labels: map[string]string{
					"app":  "app-abc",
					"prod": "yes",
				},
				Tags: tags2,
			},
			api.ProfileMetadata{
				Name: "profile1/with_foo",
				Labels: map[string]string{
					"app":  "app-xyz",
					"prod": "no",
				},
			},
			profileSpec1,
			api.ProfileSpec{},
			profileSpec1AfterRead,
			api.ProfileSpec{},
		),

		// Test 3: Pass one partially populated ProfileSpec and another fully populated ProfileSpec and expect the series of operations to succeed.
		Entry("One partially populated ProfileSpec and another fully populated ProfileSpec",
			api.ProfileMetadata{
				Name: "profile1",
				Labels: map[string]string{
					"app":  "app-abc",
					"prod": "yes",
				},
			},
			api.ProfileMetadata{
				Name: "profile1/with.foo",
				Labels: map[string]string{
					"app":  "app-xyz",
					"prod": "no",
				},
			},
			api.ProfileSpec{
				IngressRules: []api.Rule{testutils.InRule1},
			},
			profileSpec2,
			api.ProfileSpec{
				IngressRules: []api.Rule{testutils.InRule1AfterRead},
			},
			profileSpec2AfterRead,
		),
	)
})
