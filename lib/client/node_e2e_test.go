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

// Test operations involving node resources.  These tests test a variety of
// operations to check that each operation returns the expected data.  By
// writing and reading sets of node data we can check that the data is stored
// and round trips correctly.  Note that these tests do not actually test the
// format of the data as it is stored in the underlying datastore.
//
// The tests are designed to test standard, Update, Create, Apply, Get, List,
// and Delete operations in standard operational and failure scenarios -
// creating and modifying field values and checking that the values hold in
// subsequent queries.
//
// Read the test code for full details of the test.

package client_test

import (
	"errors"
	"log"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

var _ = Describe("Node tests", func() {
	ipv4 := testutils.MustParseIP("1.2.3.4")
	ipv6 := testutils.MustParseIP("aa::bb:dd")
	asn := numorstring.ASNumber(12345)

	DescribeTable("Node e2e tests",
		func(meta1, meta2 api.NodeMetadata, spec1, spec2 api.NodeSpec) {
			// Erase etcd clean.
			testutils.CleanEtcd()

			// Create a new client.
			c, err := testutils.NewClient("")
			if err != nil {
				log.Println("Error creating client:", err)
			}

			// Updating non-existent node1 should return an error
			By("Updating the node before it is created")
			_, err = c.Nodes().Update(&api.Node{Metadata: meta1, Spec: spec1})
			Expect(err.Error()).To(Equal(errors.New("resource does not exist: Node(name=node1)").Error()))

			// Create a new node1 with meta1 and spec1.  This should not error.
			By("Creating a new node1")
			_, err = c.Nodes().Create(&api.Node{Metadata: meta1, Spec: spec1})
			Expect(err).NotTo(HaveOccurred())

			// Failing to create the same resource.
			By("Creating a the same node1 and checking for failure")
			_, err = c.Nodes().Create(&api.Node{Metadata: meta1, Spec: spec1})
			Expect(err.Error()).To(Equal(errors.New("resource already exists: Node(name=node1)").Error()))

			// Apply a new node2 with meta2 and spec2.  This should not error.
			By("Applying a new node2")
			_, err = c.Nodes().Apply(&api.Node{Metadata: meta2, Spec: spec2})
			Expect(err).NotTo(HaveOccurred())

			testutils.DumpEtcd()

			// Get node1.  This should not error, spec should match spec1.
			By("Getting node1 and comparing with spec1")
			outNode, err := c.Nodes().Get(meta1)
			Expect(err).NotTo(HaveOccurred())
			Expect(outNode.Metadata).To(Equal(meta1))
			Expect(outNode.Spec).To(Equal(spec1))

			// Get node2  This should not error, spec should match spec1.
			By("Getting node2 and comparing with spec2")
			outNode, err = c.Nodes().Get(meta2)
			Expect(err).NotTo(HaveOccurred())
			Expect(outNode.Metadata).To(Equal(meta2))
			Expect(outNode.Spec).To(Equal(spec2))

			// Update node1 with spec2.
			By("Updating node1 with spec2")
			_, err = c.Nodes().Update(&api.Node{Metadata: meta1, Spec: spec2})
			Expect(err).NotTo(HaveOccurred())

			// Apply node2 with spec1.
			By("Applying node2 with spec1")
			_, err = c.Nodes().Update(&api.Node{Metadata: meta2, Spec: spec1})
			Expect(err).NotTo(HaveOccurred())

			// Get node with meta1.
			By("Getting node1 and comparing with spec2")
			outNode, err = c.Nodes().Get(meta1)
			Expect(err).NotTo(HaveOccurred())
			Expect(outNode.Metadata).To(Equal(meta1))
			Expect(outNode.Spec).To(Equal(spec2))

			// Get a list of nodes.  This should not error.  Compare this
			// against the expected results - there are only two entries
			// so just use brute force comparison.
			By("Listing all the nodes and comparing with expected")
			nodeList, err := c.Nodes().List(api.NodeMetadata{})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(nodeList.Items)).To(Equal(2))
			Expect(nodeList.Items[0].Metadata).To(Equal(meta1))
			Expect(nodeList.Items[1].Metadata).To(Equal(meta2))
			Expect(nodeList.Items[0].Spec).To(Equal(spec2))
			Expect(nodeList.Items[1].Spec).To(Equal(spec1))

			// Get a node list with meta1.
			By("Listing a specific node and comparing with expected")
			nodeList, err = c.Nodes().List(meta1)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(nodeList.Items)).To(Equal(1))
			Expect(nodeList.Items[0].Metadata).To(Equal(meta1))
			Expect(nodeList.Items[0].Spec).To(Equal(spec2))

			// Get a node with meta1 and compare against the list results.  This
			// checks the full output of List is the same as Get.
			outNode, err = c.Nodes().Get(meta1)
			Expect(err).NotTo(HaveOccurred())
			Expect(nodeList.Items[0]).To(Equal(*outNode))

			// Deleting node1 should not error.
			By("Deleting node1")
			err = c.Nodes().Delete(meta1)
			Expect(err).NotTo(HaveOccurred())

			// Get a node with meta1.
			By("Getting node1 and checking for error")
			_, err = c.Nodes().Get(meta1)
			Expect(err.Error()).To(Equal(errors.New("resource does not exist: Node(name=node1)").Error()))

			// Delete node2 should not error.
			By("Deleting node2")
			err = c.Nodes().Delete(meta2)
			Expect(err).NotTo(HaveOccurred())

			// Both resources are deleted in the calls above, so listing the
			// resources should return no results.
			By("Listing resources and checking for empty list")
			nodeList, err = c.Nodes().List(api.NodeMetadata{})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(nodeList.Items)).To(Equal(0))
		},

		// Test 1: One IPv4 and one IPv6 nodespecs.  One with ASNumber, one without.
		Entry("Two fully populated NodeSpecs",
			api.NodeMetadata{Name: "node1"},
			api.NodeMetadata{Name: "node2"},
			api.NodeSpec{
				BGP: &api.NodeBGPSpec{
					IPv4Address: &ipv4,
				},
			},
			api.NodeSpec{
				BGP: &api.NodeBGPSpec{
					IPv6Address: &ipv6,
					ASNumber:    &asn,
				},
			}),

		// Test 2: BGP IPv4 and 6, and no BGP.
		Entry("Two fully populated NodeSpecs",
			api.NodeMetadata{Name: "node1"},
			api.NodeMetadata{Name: "node2"},
			api.NodeSpec{},
			api.NodeSpec{
				BGP: &api.NodeBGPSpec{
					IPv4Address: &ipv4,
					IPv6Address: &ipv6,
					ASNumber:    &asn,
				},
			}),
	)

	Describe("Checking global config is set only once", func() {
		testutils.CleanEtcd()
		c, _ := testutils.NewClient("")
		var guidOrig string
		var guidNew string
		var set bool
		var err error

		// Step-1: Create node 1.
		Context("Create node1", func() {
			_, err = c.Nodes().Create(&api.Node{
				Metadata: api.NodeMetadata{Name: "node1"},
				Spec:     api.NodeSpec{},
			})
			It("should create the node", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			It("should create the global GUID", func() {
				guidOrig, set, err = c.Config().GetFelixConfig("ClusterGUID", "")
				Expect(err).NotTo(HaveOccurred())
				Expect(set).To(BeTrue())
				Expect(guidOrig).NotTo(Equal(""))
			})
		})

		// Step-2: Create node 2.
		Context("Create node 2", func() {
			_, err = c.Nodes().Create(&api.Node{
				Metadata: api.NodeMetadata{Name: "node2"},
				Spec:     api.NodeSpec{},
			})
			It("should create the node", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			It("should not change the global GUID", func() {
				guidNew, set, err = c.Config().GetFelixConfig("ClusterGUID", "")
				Expect(err).NotTo(HaveOccurred())
				Expect(set).To(BeTrue())
				Expect(guidNew).NotTo(Equal(""))
				Expect(guidNew).To(Equal(guidOrig))
			})
		})
	})

})
