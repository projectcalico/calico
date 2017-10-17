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

// Test cases (Pool object e2e):
// Test 1: Pass two fully populated IPPoolSpecs and expect the series of operations to succeed.
// Test 2: Pass one partially populated IPPoolSpec and another fully populated IPPoolSpec and expect the series of operations to succeed.
// Test 3: Pass one fully populated IPPoolSpec and another empty IPPoolSpec and expect the series of operations to succeed.
// Test 4: Pass two fully populated IPPoolSpecs with two IPPoolMetadata (one IPv4 and another IPv6) and expect the series of operations to succeed.

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
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/api"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/ipip"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("IPPool e2e tests", testutils.DatastoreAll, func(apiConfig api.CalicoAPIConfig) {

	DescribeTable("IPPool e2e tests",
		func(meta1, meta2 api.IPPoolMetadata, spec1, spec2 api.IPPoolSpec) {
			c := testutils.CreateCleanClient(apiConfig)

			By("Updating the pool before it is created")
			_, outError := c.IPPools().Update(&api.IPPool{Metadata: meta1, Spec: spec1})

			// Should return an error.
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: IPPool(cidr=10.0.0.0/24)").Error()))

			By("Create, Apply, Get and compare")

			// Create a pool with meta1 and spec1.
			_, outError = c.IPPools().Create(&api.IPPool{Metadata: meta1, Spec: spec1})
			Expect(outError).NotTo(HaveOccurred())

			// Apply a pool with meta2 and spec2.
			_, outError = c.IPPools().Apply(&api.IPPool{Metadata: meta2, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get pool with meta1.
			outPool1, outError1 := c.IPPools().Get(meta1)
			log.Println("Out IPPool object: ", outPool1)

			// Get pool with meta2.
			outPool2, outError2 := c.IPPools().Get(meta2)
			log.Println("Out IPPool object: ", outPool2)

			// Should match spec1 & outPool1 and outPool2 & spec2 and errors to be nil.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outError2).NotTo(HaveOccurred())
			Expect(outPool1.Spec).To(Equal(spec1))
			Expect(outPool2.Spec).To(Equal(spec2))

			By("Update, Get and compare")

			// Update meta1 pool with spec2.
			_, outError = c.IPPools().Update(&api.IPPool{Metadata: meta1, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get pool with meta1.
			outPool1, outError1 = c.IPPools().Get(meta1)

			// Assert the Spec for pool with meta1 matches spec2 and no error.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outPool1.Spec).To(Equal(spec2))

			By("List all the pools and compare")

			// Get a list of pools.
			poolList, outError := c.IPPools().List(api.IPPoolMetadata{})
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get pool list returns: ", poolList.Items)
			metas := []api.IPPoolMetadata{meta1, meta2}
			expectedPools := []api.IPPool{}
			// Go through meta list and append them to expectedPools.
			for _, v := range metas {
				p, outError := c.IPPools().Get(v)
				Expect(outError).NotTo(HaveOccurred())
				expectedPools = append(expectedPools, *p)
			}

			// Assert the returned poolList is has the meta1 and meta2 pools.
			Expect(poolList.Items).To(Equal(expectedPools))

			By("List a specific pool and compare")

			// Get a pool list with meta1.
			poolList, outError = c.IPPools().List(meta1)
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get pool list returns: ", poolList.Items)

			// Get a pool with meta1.
			outPool1, outError1 = c.IPPools().Get(meta1)

			// Assert they are equal and no errors.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(len(poolList.Items)).To(Equal(1))
			Expect(poolList.Items[0].Spec).To(Equal(outPool1.Spec))

			By("Delete, Get and assert error")

			// Delete a pool with meta1.
			outError1 = c.IPPools().Delete(meta1)
			Expect(outError1).NotTo(HaveOccurred())

			// Get a pool with meta1.
			_, outError = c.IPPools().Get(meta1)

			// Expect an error since the pool was deleted.
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: IPPool(cidr=10.0.0.0/24)").Error()))

			// Delete the second pool with meta2.
			outError1 = c.IPPools().Delete(meta2)
			Expect(outError1).NotTo(HaveOccurred())

			By("Delete all the pools, Get pool list and expect empty pool list")

			// Both pools are deleted in the calls above.
			// Get the list of all the pools.
			poolList, outError = c.IPPools().List(api.IPPoolMetadata{})
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get pool list returns: ", poolList.Items)

			// Create an empty pool list.
			// Note: you can't use make([]api.IPPool, 0) because it creates an empty underlying struct,
			// whereas new([]api.IPPool) just returns a pointer without creating an empty struct.
			emptyPoolList := new([]api.IPPool)

			// Expect returned poolList to contain empty poolList.
			Expect(poolList.Items).To(Equal(*emptyPoolList))
		},

		// Test 1: Pass two fully populated IPPoolSpecs and expect the series of operations to succeed.
		Entry("Two fully populated IPPoolSpecs",
			api.IPPoolMetadata{CIDR: net.MustParseNetwork("10.0.0.0/24")},
			api.IPPoolMetadata{CIDR: net.MustParseNetwork("192.168.0.0/24")},
			api.IPPoolSpec{
				IPIP: &api.IPIPConfiguration{
					Enabled: true,
				},
				NATOutgoing: true,
				Disabled:    true,
			},
			api.IPPoolSpec{
				IPIP:        nil,
				NATOutgoing: true,
				Disabled:    false,
			}),

		// Test 2: Pass one partially populated IPPoolSpec and another fully populated IPPoolSpec and expect the series of operations to succeed.
		Entry("One partially populated IPPoolSpec and another fully populated IPPoolSpec",
			api.IPPoolMetadata{CIDR: net.MustParseNetwork("10.0.0.0/24")},
			api.IPPoolMetadata{CIDR: net.MustParseNetwork("192.168.0.0/24")},
			api.IPPoolSpec{
				IPIP: &api.IPIPConfiguration{
					Enabled: true,
				},
			},
			api.IPPoolSpec{
				IPIP:        nil,
				NATOutgoing: true,
				Disabled:    true,
			}),

		// Test 3: Pass one fully populated IPPoolSpec and another empty IPPoolSpec and expect the series of operations to succeed.
		Entry("One fully populated IPPoolSpec and another empty IPPoolSpec",
			api.IPPoolMetadata{CIDR: net.MustParseNetwork("10.0.0.0/24")},
			api.IPPoolMetadata{CIDR: net.MustParseNetwork("192.168.0.0/24")},
			api.IPPoolSpec{
				IPIP: &api.IPIPConfiguration{
					Enabled: true,
				},
				NATOutgoing: true,
				Disabled:    true,
			},
			api.IPPoolSpec{},
		),

		// Test 4: Pass two fully populated IPPoolSpecs with two IPPoolMetadata (one IPv4 and another IPv6) and expect the series of operations to succeed.
		Entry("Two fully populated IPPoolSpecs with two IPPoolMetadata (one IPv4 and another IPv6)",
			api.IPPoolMetadata{CIDR: net.MustParseNetwork("10.0.0.0/24")},
			api.IPPoolMetadata{CIDR: net.MustParseNetwork("2001::/120")},
			api.IPPoolSpec{
				NATOutgoing: true,
				Disabled:    true,
			},
			api.IPPoolSpec{
				NATOutgoing: false,
				Disabled:    false,
			},
		),

		// Test 5: Test starting with IPIP (cross subnet mode) and moving to no IPIP
		Entry("IPIP (cross subnet mode) and moving to no IPIP",
			api.IPPoolMetadata{CIDR: net.MustParseNetwork("10.0.0.0/24")},
			api.IPPoolMetadata{CIDR: net.MustParseNetwork("2001::/120")},
			api.IPPoolSpec{
				IPIP: &api.IPIPConfiguration{
					Enabled: true,
					Mode:    ipip.CrossSubnet,
				},
			},
			api.IPPoolSpec{},
		),

		// Test 6: Test starting with IPIP (cross subnet mode) and moving to IPIP disabled (keeping IPIP mode)
		Entry("IPIP (cross subnet mode) and moving to IPIP disabled (keeping IPIP mode)",
			api.IPPoolMetadata{CIDR: net.MustParseNetwork("10.0.0.0/24")},
			api.IPPoolMetadata{CIDR: net.MustParseNetwork("10.10.10.0/24")},
			api.IPPoolSpec{
				IPIP: &api.IPIPConfiguration{
					Enabled: true,
					Mode:    ipip.CrossSubnet,
				},
			},
			api.IPPoolSpec{
				IPIP: &api.IPIPConfiguration{
					Enabled: false,
					Mode:    ipip.CrossSubnet,
				},
			},
		),
	)

	Describe("Checking operations perform data validation", func() {
		c := testutils.CreateCleanClient(apiConfig)

		var err error
		valErrorType := reflect.TypeOf(cerrors.ErrorValidation{})

		// Step-1: Test data validation occurs on create.
		It("should invoke validation failure", func() {
			By("Creating a pool with small CIDR (< /26)")
			_, err = c.IPPools().Create(&api.IPPool{
				Metadata: api.IPPoolMetadata{CIDR: net.MustParseCIDR("10.10.10.0/30")},
				Spec:     api.IPPoolSpec{},
			})

			Expect(err).To(HaveOccurred())
			Expect(reflect.TypeOf(err)).To(Equal(valErrorType))
		})

		// Step-2: Test data validation occurs on apply.
		It("should invoke validation failure", func() {
			By("Applying a pool with small CIDR (< /122)")
			_, err = c.IPPools().Apply(&api.IPPool{
				Metadata: api.IPPoolMetadata{CIDR: net.MustParseCIDR("aa:bb::c8/125")},
				Spec:     api.IPPoolSpec{},
			})
			Expect(err).To(HaveOccurred())
			Expect(reflect.TypeOf(err)).To(Equal(valErrorType))
		})

		// Step-3: Test data validation occurs on update.
		It("should invoke validation failure", func() {
			By("Creating a pool with a valid CIDR")
			_, err = c.IPPools().Create(&api.IPPool{
				Metadata: api.IPPoolMetadata{CIDR: net.MustParseCIDR("aa:bb::/120")},
				Spec:     api.IPPoolSpec{},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Updating the pool using invalid settings (IPIP on IPv6 pool)")
			_, err = c.IPPools().Update(&api.IPPool{
				Metadata: api.IPPoolMetadata{CIDR: net.MustParseCIDR("aa:bb::/120")},
				Spec:     api.IPPoolSpec{IPIP: &api.IPIPConfiguration{Enabled: true}},
			})
			Expect(err).To(HaveOccurred())
			Expect(reflect.TypeOf(err)).To(Equal(valErrorType))
		})

		// Step-4: Test data validation occurs on create.
		It("should invoke validation failure", func() {
			By("Creating a pool with unstrict masked CIDR")
			_, err = c.IPPools().Create(&api.IPPool{
				Metadata: api.IPPoolMetadata{CIDR: net.MustParseCIDR("10.10.10.0/16")},
				Spec:     api.IPPoolSpec{},
			})

			Expect(err).To(HaveOccurred())
			Expect(reflect.TypeOf(err)).To(Equal(valErrorType))
		})
	})
})
