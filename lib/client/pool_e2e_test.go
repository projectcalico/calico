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

// Test cases (Pool object e2e):
// Test 1: Pass two fully populated PoolSpecs and expect the series of operations to succeed.
// Test 2: Pass one partially populated PoolSpec and another fully populated PoolSpec and expect the series of operations to succeed.
// Test 3: Pass one fully populated PoolSpec and another empty PoolSpec and expect the series of operations to succeed.
// Test 4: Pass two fully populated PoolSpecs with two PoolMetadata (one IPv4 and another IPv6) and expect the series of operations to succeed.

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

var _ = Describe("Pool tests", func() {

	DescribeTable("Pool e2e tests",
		func(meta1, meta2 api.PoolMetadata, spec1, spec2 api.PoolSpec) {

			// Erase etcd clean.
			testutils.CleanEtcd()

			// Create a new client.
			c, err := testutils.NewClient("")
			if err != nil {
				log.Println("Error creating client:", err)
			}
			By("Updating the pool before it is created")
			_, outError := c.Pools().Update(&api.Pool{Metadata: meta1, Spec: spec1})

			// Should return an error.
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: Pool(cidr=10.0.0.0/24)").Error()))

			By("Create, Apply, Get and compare")

			// Create a pool with meta1 and spec1.
			_, outError = c.Pools().Create(&api.Pool{Metadata: meta1, Spec: spec1})
			Expect(outError).NotTo(HaveOccurred())

			// Apply a pool with meta2 and spec2.
			_, outError = c.Pools().Apply(&api.Pool{Metadata: meta2, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get pool with meta1.
			outPool1, outError1 := c.Pools().Get(meta1)
			log.Println("Out Pool object: ", outPool1)

			// Get pool with meta2.
			outPool2, outError2 := c.Pools().Get(meta2)
			log.Println("Out Pool object: ", outPool2)

			// Should match spec1 & outPool1 and outPool2 & spec2 and errors to be nil.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outError2).NotTo(HaveOccurred())
			Expect(outPool1.Spec).To(Equal(spec1))
			Expect(outPool2.Spec).To(Equal(spec2))

			By("Update, Get and compare")

			// Update meta1 pool with spec2.
			_, outError = c.Pools().Update(&api.Pool{Metadata: meta1, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get pool with meta1.
			outPool1, outError1 = c.Pools().Get(meta1)

			// Assert the Spec for pool with meta1 matches spec2 and no error.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outPool1.Spec).To(Equal(spec2))

			By("List all the pools and compare")

			// Get a list of pools.
			poolList, outError := c.Pools().List(api.PoolMetadata{})
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get pool list returns: ", poolList.Items)
			metas := []api.PoolMetadata{meta1, meta2}
			expectedPools := []api.Pool{}
			// Go through meta list and append them to expectedPools.
			for _, v := range metas {
				p, outError := c.Pools().Get(v)
				Expect(outError).NotTo(HaveOccurred())
				expectedPools = append(expectedPools, *p)
			}

			// Assert the returned poolList is has the meta1 and meta2 pools.
			Expect(poolList.Items).To(Equal(expectedPools))

			By("List a specific pool and compare")

			// Get a pool list with meta1.
			poolList, outError = c.Pools().List(meta1)
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get pool list returns: ", poolList.Items)

			// Get a pool with meta1.
			outPool1, outError1 = c.Pools().Get(meta1)

			// Assert they are equal and no errors.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(poolList.Items[0].Spec).To(Equal(outPool1.Spec))

			By("Delete, Get and assert error")

			// Delete a pool with meta1.
			outError1 = c.Pools().Delete(meta1)
			Expect(outError1).NotTo(HaveOccurred())

			// Get a pool with meta1.
			_, outError = c.Pools().Get(meta1)

			// Expect an error since the pool was deleted.
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: Pool(cidr=10.0.0.0/24)").Error()))

			// Delete the second pool with meta2.
			outError1 = c.Pools().Delete(meta2)
			Expect(outError1).NotTo(HaveOccurred())

			By("Delete all the pools, Get pool list and expect empty pool list")

			// Both pools are deleted in the calls above.
			// Get the list of all the pools.
			poolList, outError = c.Pools().List(api.PoolMetadata{})
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get pool list returns: ", poolList.Items)

			// Create an empty pool list.
			// Note: you can't use make([]api.Pool, 0) because it creates an empty underlying struct,
			// whereas new([]api.Pool) just returns a pointer without creating an empty struct.
			emptyPoolList := new([]api.Pool)

			// Expect returned poolList to contain empty poolList.
			Expect(poolList.Items).To(Equal(*emptyPoolList))
		},

		// Test 1: Pass two fully populated PoolSpecs and expect the series of operations to succeed.
		Entry("Two fully populated PoolSpecs",
			api.PoolMetadata{CIDR: testutils.MustParseCIDR("10.0.0.0/24")},
			api.PoolMetadata{CIDR: testutils.MustParseCIDR("192.168.0.0/24")},
			api.PoolSpec{
				IPIP: &api.IPIPConfiguration{
					Enabled: true,
				},
				NATOutgoing: true,
				Disabled:    true,
			},
			api.PoolSpec{
				IPIP:        nil,
				NATOutgoing: true,
				Disabled:    false,
			}),

		// Test 2: Pass one partially populated PoolSpec and another fully populated PoolSpec and expect the series of operations to succeed.
		Entry("One partially populated PoolSpec and another fully populated PoolSpec",
			api.PoolMetadata{CIDR: testutils.MustParseCIDR("10.0.0.0/24")},
			api.PoolMetadata{CIDR: testutils.MustParseCIDR("192.168.0.0/24")},
			api.PoolSpec{
				IPIP: &api.IPIPConfiguration{
					Enabled: true,
				},
			},
			api.PoolSpec{
				IPIP:        nil,
				NATOutgoing: true,
				Disabled:    true,
			}),

		// Test 3: Pass one fully populated PoolSpec and another empty PoolSpec and expect the series of operations to succeed.
		Entry("One fully populated PoolSpec and another empty PoolSpec",
			api.PoolMetadata{CIDR: testutils.MustParseCIDR("10.0.0.0/24")},
			api.PoolMetadata{CIDR: testutils.MustParseCIDR("192.168.0.0/24")},
			api.PoolSpec{
				IPIP: &api.IPIPConfiguration{
					Enabled: true,
				},
				NATOutgoing: true,
				Disabled:    true,
			},
			api.PoolSpec{},
		),

		// Test 4: Pass two fully populated PoolSpecs with two PoolMetadata (one IPv4 and another IPv6) and expect the series of operations to succeed.
		Entry("Two fully populated PoolSpecs with two PoolMetadata (one IPv4 and another IPv6)",
			api.PoolMetadata{CIDR: testutils.MustParseCIDR("10.0.0.0/24")},
			api.PoolMetadata{CIDR: testutils.MustParseCIDR("fe80::00/120")},
			api.PoolSpec{
				IPIP: &api.IPIPConfiguration{
					Enabled: true,
				},
				NATOutgoing: true,
				Disabled:    true,
			},
			api.PoolSpec{
				IPIP: &api.IPIPConfiguration{
					Enabled: true,
				},
				NATOutgoing: false,
				Disabled:    false,
			}),
	)
})
