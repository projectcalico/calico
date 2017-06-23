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

// Test cases (BGPPeer object e2e):
// Test 1: Pass two fully populated BGPPeerSpecs and expect the series of operations to succeed.
// Test 2: Pass one fully populated BGPPeerSpec and another empty BGPPeerSpec and expect the series of operations to succeed.

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
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/scope"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("BGPPeer tests", testutils.DatastoreEtcdV2, func(config api.CalicoAPIConfig) {

	DescribeTable("BGPPeer e2e tests",
		func(meta1, meta2 api.BGPPeerMetadata, spec1, spec2 api.BGPPeerSpec) {
			c := testutils.CreateCleanClient(config)
			By("Updating the BGPPeer before it is created")
			_, outError := c.BGPPeers().Update(&api.BGPPeer{Metadata: meta1, Spec: spec1})

			// Should return an error.
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: BGPPeer(node=node1, ip=10.0.0.1)").Error()))

			By("Create, Apply, Get and compare")

			// Create a BGPPeer with meta1 and spec1.
			_, outError = c.BGPPeers().Create(&api.BGPPeer{Metadata: meta1, Spec: spec1})
			Expect(outError).NotTo(HaveOccurred())

			// Apply a BGPPeer with meta2 and spec2.
			_, outError = c.BGPPeers().Apply(&api.BGPPeer{Metadata: meta2, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get BGPPeer with meta1.
			outBGPPeer1, outError1 := c.BGPPeers().Get(meta1)
			log.Println("Out BGPPeer object: ", outBGPPeer1)

			// Get BGPPeer with meta2.
			outBGPPeer2, outError2 := c.BGPPeers().Get(meta2)
			log.Println("Out BGPPeer object: ", outBGPPeer2)

			// Should match spec1 & outBGPPeer1 and outBGPPeer2 & spec2 and errors to be nil.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outError2).NotTo(HaveOccurred())
			Expect(outBGPPeer1.Spec).To(Equal(spec1))
			Expect(outBGPPeer2.Spec).To(Equal(spec2))

			By("Update, Get and compare")

			// Update meta1 BGPPeer with spec2.
			_, outError = c.BGPPeers().Update(&api.BGPPeer{Metadata: meta1, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get BGPPeer with meta1.
			outBGPPeer1, outError1 = c.BGPPeers().Get(meta1)

			// Assert the Spec for BGPPeer with meta1 matches spec2 and no error.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outBGPPeer1.Spec).To(Equal(spec2))

			By("List all the BGPPeers and compare")

			// Get a list of BGPPeers.
			BGPPeerList, outError := c.BGPPeers().List(api.BGPPeerMetadata{})
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get BGPPeer list returns: ", BGPPeerList.Items)

			// Get BGPPeers for both Metadata.
			bp1, _ := c.BGPPeers().Get(meta1)
			bp2, _ := c.BGPPeers().Get(meta2)

			// Assert the returned BGPPeerList contains the meta1 and meta2 BGPPeers.
			Expect(BGPPeerList.Items).To(ContainElement(*bp1))
			Expect(BGPPeerList.Items).To(ContainElement(*bp2))

			By("List a specific BGPPeer and compare")

			// Get a BGPPeer list with meta1.
			BGPPeerList, outError = c.BGPPeers().List(meta1)
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get BGPPeer list returns: ", BGPPeerList.Items)

			// Get a BGPPeer with meta1.
			outBGPPeer1, outError1 = c.BGPPeers().Get(meta1)

			// Assert they are equal and no errors.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(BGPPeerList.Items[0].Spec).To(Equal(outBGPPeer1.Spec))

			By("Delete, Get and assert error")

			// Delete a BGPPeer with meta1.
			outError1 = c.BGPPeers().Delete(meta1)
			Expect(outError1).NotTo(HaveOccurred())

			// Get a BGPPeer with meta1.
			_, outError = c.BGPPeers().Get(meta1)

			// Expect an error since the BGPPeer was deleted.
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: BGPPeer(node=node1, ip=10.0.0.1)").Error()))

			// Delete the second BGPPeer with meta2.
			outError1 = c.BGPPeers().Delete(meta2)
			Expect(outError1).NotTo(HaveOccurred())

			By("Delete all the BGPPeers, Get BGPPeer list and expect empty BGPPeer list")

			// Both BGPPeers are deleted in the calls above.
			// Get the list of all the BGPPeers.
			BGPPeerList, outError = c.BGPPeers().List(api.BGPPeerMetadata{})
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get BGPPeer list returns: ", BGPPeerList.Items)

			// Create an empty BGPPeer list.
			// Note: you can't use make([]api.BGPPeer, 0) because it creates an empty underlying struct,
			// whereas new([]api.BGPPeer) just returns a pointer without creating an empty struct.
			emptyBGPPeerList := new([]api.BGPPeer)

			// Expect returned BGPPeerList to contain empty BGPPeerList.
			Expect(BGPPeerList.Items).To(Equal(*emptyBGPPeerList))
		},

		// Test 1: Pass two fully populated BGPPeerSpecs and expect the series of operations to succeed.
		Entry("Two fully populated BGPPeerSpecs",
			api.BGPPeerMetadata{
				Scope:  scope.Scope("node"),
				Node:   "node1",
				PeerIP: net.MustParseIP("10.0.0.1"),
			},
			api.BGPPeerMetadata{
				Scope:  scope.Scope("global"),
				PeerIP: net.MustParseIP("20.0.0.1"),
			},
			api.BGPPeerSpec{
				ASNumber: numorstring.ASNumber(6512),
			},
			api.BGPPeerSpec{
				ASNumber: numorstring.ASNumber(6511),
			}),

		// Test 2: Pass one fully populated BGPPeerSpec and another empty BGPPeerSpec and expect the series of operations to succeed.
		Entry("One fully populated BGPPeerSpec and another empty BGPPeerSpec",
			api.BGPPeerMetadata{
				Scope:  scope.Scope("node"),
				Node:   "node1",
				PeerIP: net.MustParseIP("10.0.0.1"),
			},
			api.BGPPeerMetadata{
				Scope:  scope.Scope("global"),
				PeerIP: net.MustParseIP("20.0.0.1"),
			},
			api.BGPPeerSpec{
				ASNumber: numorstring.ASNumber(6512),
			},
			api.BGPPeerSpec{}),
	)

	Describe("Checking operations perform data validation", func() {
		c := testutils.CreateCleanClient(config)
		var err error
		valErrorType := reflect.TypeOf(cerrors.ErrorValidation{})

		It("should invoke validation failure", func() {
			By("Creating a BGPPeer with invalid combination of scope and node")
			_, err = c.BGPPeers().Create(&api.BGPPeer{
				Metadata: api.BGPPeerMetadata{
					Scope:  scope.Scope("global"),
					Node:   "node1",
					PeerIP: net.MustParseIP("10.0.0.1"),
				},
				Spec: api.BGPPeerSpec{},
			})

			Expect(err).To(HaveOccurred())
			Expect(reflect.TypeOf(err)).To(Equal(valErrorType))
			Expect(err.(cerrors.ErrorValidation).ErroredFields).To(HaveLen(1))
			Expect(err.(cerrors.ErrorValidation).ErroredFields[0].Name).To(Equal("Metadata.Node"))
		})

		It("should invoke validation failure", func() {
			By("Listing BGPPeers with invalid combination of scope and node")
			_, err = c.BGPPeers().List(api.BGPPeerMetadata{
				Scope:  scope.Scope("global"),
				Node:   "node1",
				PeerIP: net.MustParseIP("10.0.0.1"),
			})

			Expect(err).To(HaveOccurred())
			Expect(reflect.TypeOf(err)).To(Equal(valErrorType))
			Expect(err.(cerrors.ErrorValidation).ErroredFields).To(HaveLen(1))
			Expect(err.(cerrors.ErrorValidation).ErroredFields[0].Name).To(Equal("Metadata.Node"))
		})

		It("should invoke validation failure", func() {
			By("Getting a BGPPeer with invalid combination of scope and node")
			_, err = c.BGPPeers().Get(api.BGPPeerMetadata{
				Scope:  scope.Scope("global"),
				Node:   "node1",
				PeerIP: net.MustParseIP("10.0.0.1"),
			})

			Expect(err).To(HaveOccurred())
			Expect(reflect.TypeOf(err)).To(Equal(valErrorType))
			Expect(err.(cerrors.ErrorValidation).ErroredFields).To(HaveLen(1))
			Expect(err.(cerrors.ErrorValidation).ErroredFields[0].Name).To(Equal("Metadata.Node"))
		})
	})
})
