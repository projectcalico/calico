// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package clientv3_test

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("Block affinity tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	name1 := "affinity-1"
	name2 := "affinity-2"
	spec1 := libapiv3.BlockAffinitySpec{
		State:   "confirmed",
		Node:    "node-1",
		CIDR:    "10.0.0.0/24",
		Deleted: "false",
	}
	spec2 := libapiv3.BlockAffinitySpec{
		State:   "confirmed",
		Node:    "node-2",
		CIDR:    "10.1.0.0/24",
		Deleted: "false",
	}

	var c clientv3.Interface
	var be bapi.Client

	BeforeEach(func() {
		var err error
		c, err = clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())

		be, err = backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		err = be.Clean()
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("Block affinity e2e CRUD tests",
		func(name1, name2 string, spec1, spec2 libapiv3.BlockAffinitySpec) {
			By("Updating the block affinity before it is created")
			_, outError := c.BlockAffinities().Update(ctx, &libapiv3.BlockAffinity{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: "test-fail-affinity"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: BlockAffinity(" + name1 + ") with error:"))

			By("Attempting to creating a new block affinity with name1/spec1 and a non-empty ResourceVersion")
			_, outError = c.BlockAffinities().Create(ctx, &libapiv3.BlockAffinity{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Getting a block affinity before it is created")
			_, outError = c.BlockAffinities().Get(ctx, name1, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: BlockAffinity(" + name1 + ") with error:"))

			By("Creating a new BlockAffinity with name1/spec1")
			res1, outError := c.BlockAffinities().Create(ctx, &libapiv3.BlockAffinity{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name1, spec1))

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same BlockAffinity with name1 but with spec2")
			_, outError = c.BlockAffinities().Create(ctx, &libapiv3.BlockAffinity{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: BlockAffinity(" + name1 + ")"))

			By("Getting BlockAffinity (name1) and comparing the output against spec1")
			res, outError := c.BlockAffinities().Get(ctx, name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name1, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))
			fmt.Printf("Getting res %v", res)

			By("Getting BlockAffinity (name2) before it is created")
			_, outError = c.BlockAffinities().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: BlockAffinity(" + name2 + ") with error:"))

			By("Listing all the BlockAffinities, expecting a single result with name1/spec1")
			outList, outError := c.BlockAffinities().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name1, spec1),
			))

			By("Creating a new BlockAffinity with name2/spec2")
			res2, outError := c.BlockAffinities().Create(ctx, &libapiv3.BlockAffinity{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name2, spec2))

			By("Getting BlockAffinity (name2) and comparing the output against spec2")
			res, outError = c.BlockAffinities().Get(ctx, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name2, spec2))
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the BlockAffinities, expecting two results with name1/spec1 and name2/spec2")
			outList, outError = c.BlockAffinities().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name1, spec1),
				testutils.Resource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name2, spec2),
			))

			By("Updating BlockAffinity name1 with spec2")
			res1.Spec = spec2
			res1, outError = c.BlockAffinities().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name1, spec2))

			By("Attempting to update the BlockAffinity without a Creation Timestamp")
			res, outError = c.BlockAffinities().Update(ctx, &libapiv3.BlockAffinity{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", UID: "test-fail-affinity"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the BlockAffinity without a UID")
			res, outError = c.BlockAffinities().Update(ctx, &libapiv3.BlockAffinity{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name1 data.
			rv1_2 := res1.ResourceVersion

			By("Updating BlockAffinity name1 without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.BlockAffinities().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating BlockAffinity name1 using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			_, outError = c.BlockAffinities().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: BlockAffinity(" + name1 + ")"))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Getting BlockAffinity (name1) with the original resource version and comparing the output against spec1")
				res, outError = c.BlockAffinities().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(res).To(MatchResource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name1, spec1))
				Expect(res.ResourceVersion).To(Equal(rv1_1))
			}

			By("Getting BlockAffinity (name1) with the updated resource version and comparing the output against spec2")
			res, outError = c.BlockAffinities().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name1, spec2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Listing BlockAffinities with the original resource version and checking for a single result with name1/spec1")
				outList, outError = c.BlockAffinities().List(ctx, options.ListOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(outList.Items).To(ConsistOf(
					testutils.Resource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name1, spec1),
				))
			}

			By("Listing BlockAffinity with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError = c.BlockAffinities().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name1, spec2),
				testutils.Resource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name2, spec2),
			))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Deleting BlockAffinity (name1) with the old resource version")
				_, outError = c.BlockAffinities().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_1})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal("update conflict: BlockAffinity(" + name1 + ")"))
			}

			By("Updating BlockAffinity (name1) to have the Deleted flag set to \"true\"")
			res1.ResourceVersion = rv1_2
			res1.Spec.Deleted = "true"
			spec2.Deleted = "true"
			res1, outError = c.BlockAffinities().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name1, spec2))

			By("Listing BlockAffinities and noticing that BlockAffinity (name1) is no longer available")
			outList, outError = c.BlockAffinities().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name2, spec2),
			))

			By("Deleting BlockAffinity (name1) with the new resource version")
			dres, outError := c.BlockAffinities().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(testutils.MatchResource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name1, spec2))

			By("Listing BlockAffinities again and noticing it is unchanged now that BlockAffinity (name1) is deleted")
			outList, outError = c.BlockAffinities().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name2, spec2),
			))

			By("Deleting BlockAffinity (name2) with the new resource version")
			dres, outError = c.BlockAffinities().Delete(ctx, name2, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(testutils.MatchResource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name2, spec2))

			By("Listing BlockAffinities and expecting error")
			_, outError = c.BlockAffinities().List(ctx, options.ListOptions{})
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				Expect(outError.Error()).To(ContainSubstring("operation List is not supported"))
			} else {
				Expect(outError).NotTo(HaveOccurred())
			}
		},

		Entry("BlockAffinitySpecs 1,2", name1, name2, spec1, spec2),
	)
})
