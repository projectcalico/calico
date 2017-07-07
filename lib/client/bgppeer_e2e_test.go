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

package client_test

import (
	"errors"
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

// Perform CRUD operations on Global and Node-specific BGP Peer Resources.
var _ = testutils.E2eDatastoreDescribe("BGPPeer tests", testutils.DatastoreAll, func(config api.CalicoAPIConfig) {

	DescribeTable("BGPPeer e2e tests",
		func(meta1, meta2 api.BGPPeerMetadata, spec1, spec2 api.BGPPeerSpec) {
			c := testutils.CreateCleanClient(config)

			By("Updating the BGPPeer before it is created")
			_, outError := c.BGPPeers().Update(&api.BGPPeer{Metadata: meta1, Spec: spec1})
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: BGPPeer(node=127.0.0.1, ip=10.0.0.1)").Error()))

			By("Creating a new BGPPeer with meta/spec1")
			_, outError = c.BGPPeers().Create(&api.BGPPeer{Metadata: meta1, Spec: spec1})
			Expect(outError).NotTo(HaveOccurred())

			By("Applying a new BGPPeer with meta/spec1")
			_, outError = c.BGPPeers().Apply(&api.BGPPeer{Metadata: meta2, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			By("Getting BGPPeer (meta1) and comparing the output against spec1")
			outBGPPeer1, outError1 := c.BGPPeers().Get(meta1)
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outBGPPeer1.Spec).To(Equal(spec1))

			By("Getting BGPPeer (meta2) and comparing the output against spec2")
			outBGPPeer2, outError2 := c.BGPPeers().Get(meta2)
			Expect(outError2).NotTo(HaveOccurred())
			Expect(outBGPPeer2.Spec).To(Equal(spec2))

			By("Updating BGPPeer (meta1) with spec2")
			_, outError = c.BGPPeers().Update(&api.BGPPeer{Metadata: meta1, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			By("Getting BGPPeer (meta1) with spec2")
			outBGPPeer1, outError1 = c.BGPPeers().Get(meta1)
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outBGPPeer1.Spec).To(Equal(spec2))

			By("Listing all the BGPPeers")
			BGPPeerList, outError := c.BGPPeers().List(api.BGPPeerMetadata{})
			Expect(outError).NotTo(HaveOccurred())

			By("Getting both BGPPeers (meta1 and meta2) and checking they match the list entries")
			bp1, _ := c.BGPPeers().Get(meta1)
			bp2, _ := c.BGPPeers().Get(meta2)
			Expect(BGPPeerList.Items).To(ContainElement(*bp1))
			Expect(BGPPeerList.Items).To(ContainElement(*bp2))

			By("List BGPPeer (meta1) and compare")
			BGPPeerList, outError = c.BGPPeers().List(meta1)
			Expect(outError).NotTo(HaveOccurred())
			Expect(BGPPeerList.Items[0]).To(Equal(*bp1))

			By("Deleting BGPPeer (meta1)")
			outError1 = c.BGPPeers().Delete(meta1)
			Expect(outError1).NotTo(HaveOccurred())

			By("Getting BGPPeer (meta1) and checking for error")
			_, outError = c.BGPPeers().Get(meta1)
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: BGPPeer(node=127.0.0.1, ip=10.0.0.1)").Error()))

			By("Deleting BGPPeer (meta2)")
			outError1 = c.BGPPeers().Delete(meta2)
			Expect(outError1).NotTo(HaveOccurred())

			By("Listing all Peers and checking for zero entries")
			BGPPeerList, outError = c.BGPPeers().List(api.BGPPeerMetadata{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(BGPPeerList.Items).To(HaveLen(0))
		},

		// Test 1: Pass two fully populated BGPPeerSpecs and expect the series of operations to succeed.
		Entry("Two fully populated BGPPeerSpecs",
			api.BGPPeerMetadata{
				Scope:  scope.Scope("node"),
				Node:   "127.0.0.1",
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
				Node:   "127.0.0.1",
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
