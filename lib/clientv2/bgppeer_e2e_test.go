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

package clientv2_test

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/backend"
	"github.com/projectcalico/libcalico-go/lib/clientv2"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

// Perform CRUD operations on Global and Node-specific BGP Peer Resources.
var _ = testutils.E2eDatastoreDescribe("BGPPeer tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	DescribeTable("BGPPeer e2e tests",
		func(name1, name2 string, spec1, spec2 apiv2.BGPPeerSpec) {
			c, err := clientv2.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Updating the BGPPeer before it is created")
			res, outError := c.BGPPeers().Update(&apiv2.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("resource does not exist: BGPPeer(" + name1 + ")"))

			By("Attempting to creating a new BGPPeer with name1/spec1 and a non-empty ResourceVersion")
			res, outError = c.BGPPeers().Create(&apiv2.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(res).To(BeNil())
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Creating a new BGPPeer with name1/spec1")
			res1, outError := c.BGPPeers().Create(&apiv2.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			assertBGPPeer(res1, name1, spec1)

			// Track the version of the original data for name1.
			rv1_1 := res1.ObjectMeta.ResourceVersion

			By("Attempting to create the same BGPPeer with name1 but with spec2")
			res1, outError = c.BGPPeers().Create(&apiv2.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: BGPPeer(" + name1 + ")"))
			// Check return value is actually the previously stored value.
			assertBGPPeer(res1, name1, spec1)
			Expect(res1.ObjectMeta.ResourceVersion).To(Equal(rv1_1))

			By("Getting BGPPeer (name1) and comparing the output against spec1")
			res, outError = c.BGPPeers().Get(name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			assertBGPPeer(res, name1, spec1)
			Expect(res.ObjectMeta.ResourceVersion).To(Equal(res1.ObjectMeta.ResourceVersion))

			By("Getting BGPPeer (name2) before it is created")
			res, outError = c.BGPPeers().Get(name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: BGPPeer(" + name2 + ")"))

			By("Listing all the BGPPeers, expecting a single result with name1/spec1")
			outList, outError := c.BGPPeers().List(options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			assertBGPPeer(&outList.Items[0], name1, spec1)

			By("Creating a new BGPPeer with name2/spec2")
			res2, outError := c.BGPPeers().Create(&apiv2.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			assertBGPPeer(res2, name2, spec2)

			By("Getting BGPPeer (name2) and comparing the output against spec2")
			res, outError = c.BGPPeers().Get(name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			assertBGPPeer(res, name2, spec2)
			Expect(res.ObjectMeta.ResourceVersion).To(Equal(res2.ObjectMeta.ResourceVersion))

			By("Listing all the BGPPeers, expecting a two results with name1/spec1 and name2/spec2")
			outList, outError = c.BGPPeers().List(options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(2))
			assertBGPPeer(&outList.Items[0], name1, spec1)
			assertBGPPeer(&outList.Items[1], name2, spec2)

			By("Updating BGPPeer name1 with spec2")
			res1.Spec = spec2
			res1, outError = c.BGPPeers().Update(res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			assertBGPPeer(res1, name1, spec2)

			// Track the version of the updated name1 data.
			rv1_2 := res1.ObjectMeta.ResourceVersion

			By("Updating BGPPeer name1 without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			res, outError = c.BGPPeers().Update(res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))
			Expect(res).To(BeNil())

			By("Updating BGPPeer name1 using the previous resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = rv1_1
			res1, outError = c.BGPPeers().Update(res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: BGPPeer(" + name1 + ")"))
			Expect(res1.ObjectMeta.ResourceVersion).To(Equal(rv1_2))

			By("Getting BGPPeer (name1) with the original resource version and comparing the output against spec1")
			res, outError = c.BGPPeers().Get(name1, options.GetOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			assertBGPPeer(res, name1, spec1)
			Expect(res.ObjectMeta.ResourceVersion).To(Equal(rv1_1))

			By("Getting BGPPeer (name1) with the updated resource version and comparing the output against spec2")
			res, outError = c.BGPPeers().Get(name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			assertBGPPeer(res, name1, spec2)
			Expect(res.ObjectMeta.ResourceVersion).To(Equal(rv1_2))

			By("Listing BGPPeers with the original resource version and checking for a single result with name1/spec1")
			outList, outError = c.BGPPeers().List(options.ListOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			assertBGPPeer(&outList.Items[0], name1, spec1)

			By("Listing BGPPeers with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError = c.BGPPeers().List(options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(2))
			assertBGPPeer(&outList.Items[0], name1, spec2)
			assertBGPPeer(&outList.Items[1], name2, spec2)

			By("Deleting BGPPeer (name1) with the old resource version")
			outError = c.BGPPeers().Delete(name1, options.DeleteOptions{ResourceVersion: rv1_1})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: BGPPeer(" + name1 + ")"))

			By("Deleting BGPPeer (name1) with the new resource version")
			outError = c.BGPPeers().Delete(name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())

			By("Updating BGPPeer name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.BGPPeers().Update(res2, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)
			_, outError = c.BGPPeers().Get(name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(2 * time.Second)
			_, outError = c.BGPPeers().Get(name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: BGPPeer(" + name2 + ")"))

			By("Creating BGPPeer name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.BGPPeers().Create(&apiv2.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)
			_, outError = c.BGPPeers().Get(name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(2 * time.Second)
			_, outError = c.BGPPeers().Get(name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: BGPPeer(" + name2 + ")"))

			By("Attempting to deleting BGPPeer (name2) again")
			outError = c.BGPPeers().Delete(name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: BGPPeer(" + name2 + ")"))

			By("Listing all BGPPeers and expecting no items")
			outList, outError = c.BGPPeers().List(options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting BGPPeer (name2) and expecting an error")
			res, outError = c.BGPPeers().Get(name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: BGPPeer(" + name2 + ")"))
		},

		// Test 1: Pass two fully populated BGPPeerSpecs and expect the series of operations to succeed.
		Entry("Two fully populated BGPPeerSpecs",
			"bgpnode-1",
			"bgpnode-2",
			apiv2.BGPPeerSpec{
				Node:     "node1",
				PeerIP:   "10.0.0.1",
				ASNumber: numorstring.ASNumber(6512),
			},
			apiv2.BGPPeerSpec{
				Node:     "node2",
				PeerIP:   "20.0.0.1",
				ASNumber: numorstring.ASNumber(6511),
			}),
	)
})

func assertBGPPeer(res *apiv2.BGPPeer, name string, spec apiv2.BGPPeerSpec) {
	Expect(res.ObjectMeta.Name).To(Equal(name))
	Expect(res.Spec).To(Equal(spec))
	Expect(res.ObjectMeta.ResourceVersion).NotTo(BeEmpty())
	Expect(res.TypeMeta.Kind).To(Equal("BGPPeer"))
	Expect(res.TypeMeta.APIVersion).To(Equal("projectcalico.org/v2"))
}
