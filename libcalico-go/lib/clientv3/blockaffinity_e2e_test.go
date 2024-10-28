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

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
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
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: uid},
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
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", UID: uid},
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

			By("Attempt to update BlockAffinity (name1) to have the Deleted flag set to \"true\"")
			res1.ResourceVersion = rv1_2
			res1.ObjectMeta.ResourceVersion = rv1_2
			spec2.Deleted = "true"
			res1.Spec = spec2
			_, outError = c.BlockAffinities().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Spec.Deleted = '{confirmed node-2 10.1.0.0/24 true}' (spec.Deleted cannot be set to \"true\")"))

			By("Deleting BlockAffinity (name1)")
			spec2.Deleted = "false"
			_, outError = c.BlockAffinities().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: res1.ResourceVersion})
			Expect(outError).NotTo(HaveOccurred())

			By("Listing BlockAffinities again and noticing BlockAffinity (name1) is deleted")
			outList, outError = c.BlockAffinities().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindBlockAffinity, testutils.ExpectNoNamespace, name2, spec2),
			))

			By("Deleting BlockAffinity (name2)")
			_, outError = c.BlockAffinities().Delete(ctx, name2, options.DeleteOptions{ResourceVersion: res2.ResourceVersion})
			Expect(outError).NotTo(HaveOccurred())

			By("Listing BlockAffinities and expecting no resources")
			outList, outError = c.BlockAffinities().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting BlockAffinity (name1) and expecting an error")
			_, outError = c.BlockAffinities().Get(ctx, name1, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: BlockAffinity(" + name1 + ") with error:"))

			By("Getting BlockAffinity (name2) and expecting an error")
			_, outError = c.BlockAffinities().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: BlockAffinity(" + name2 + ") with error:"))
		},

		Entry("BlockAffinitySpecs 1,2", name1, name2, spec1, spec2),
	)

	Describe("Block affinity watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing block affinities with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError := c.BlockAffinities().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a BlockAffinity name1/spec1 and storing the response")
			outRes1, err := c.BlockAffinities().Create(
				ctx,
				&libapiv3.BlockAffinity{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			rev1 := outRes1.ResourceVersion
			modifiedOutRes1 := outRes1.DeepCopy()
			modifiedOutRes1.Spec.Deleted = fmt.Sprintf("%t", true)

			By("Configuring a BlockAffinity name2/spec2 and storing the response")
			outRes2, err := c.BlockAffinities().Create(
				ctx,
				&libapiv3.BlockAffinity{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
				},
				options.SetOptions{},
			)
			modifiedOutRes2 := outRes2.DeepCopy()
			modifiedOutRes2.Spec.Deleted = fmt.Sprintf("%t", true)

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.BlockAffinities().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.BlockAffinities().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())

			// Kubernetes does not have version control on delete so need an extra update is called per delete.
			if config.Spec.DatastoreType == apiconfig.EtcdV3 {
				By("Checking for two events, create res2 and delete res1")
				testWatcher1.ExpectEvents(libapiv3.KindBlockAffinity, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes2,
					},
					{
						Type:     watch.Deleted,
						Previous: outRes1,
					},
				})
				testWatcher1.Stop()
			} else {
				By("Checking for three events, create res2 and delete re1")
				testWatcher1.ExpectEvents(libapiv3.KindBlockAffinity, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes2,
					},
					{
						Type:     watch.Modified,
						Previous: outRes1,
						Object:   modifiedOutRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: modifiedOutRes1,
					},
				})
				testWatcher1.Stop()
			}

			By("Starting a watcher from rev0 - this should get all events")
			w, err = c.BlockAffinities().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.BlockAffinities().Update(
				ctx,
				&libapiv3.BlockAffinity{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			modifiedOutRes3 := outRes3.DeepCopy()
			modifiedOutRes3.Spec.Deleted = fmt.Sprintf("%t", true)
			if config.Spec.DatastoreType == apiconfig.EtcdV3 {
				// Etcd has version control so it does not update the block affinity before deletion.
				testWatcher2.ExpectEvents(libapiv3.KindBlockAffinity, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes1,
					},
					{
						Type:   watch.Added,
						Object: outRes2,
					},
					{
						Type:     watch.Deleted,
						Previous: outRes1,
					},
					{
						Type:     watch.Modified,
						Previous: outRes2,
						Object:   outRes3,
					},
				})
			} else {
				testWatcher2.ExpectEvents(libapiv3.KindBlockAffinity, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes1,
					},
					{
						Type:   watch.Added,
						Object: outRes2,
					},
					{
						Type:     watch.Modified,
						Previous: outRes1,
						Object:   modifiedOutRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: modifiedOutRes1,
					},
					{
						Type:     watch.Modified,
						Previous: outRes2,
						Object:   outRes3,
					},
				})
			}
			testWatcher2.Stop()

			// Only etcdv3 supports watching a specific instance of a resource.
			if config.Spec.DatastoreType == apiconfig.EtcdV3 {
				By("Starting a watcher from rev0 watching name1 - this should get all events for name1")
				w, err = c.BlockAffinities().Watch(ctx, options.ListOptions{Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(libapiv3.KindBlockAffinity, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: outRes1,
					},
				})
				testWatcher2_1.Stop()
			}

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.BlockAffinities().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(libapiv3.KindBlockAffinity, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})
			testWatcher3.Stop()

			By("Configuring BlockAffinity name1/spec1 again and storing the response")
			outRes1, err = c.BlockAffinities().Create(
				ctx,
				&libapiv3.BlockAffinity{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.BlockAffinities().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEventsAnyOrder(libapiv3.KindBlockAffinity, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})

			By("Cleaning the datastore and expecting deletion events for each configured resource (tests prefix deletes results in individual events for each key)")
			be.Clean()
			if config.Spec.DatastoreType == apiconfig.EtcdV3 {
				// Etcd has version control so it does not modify the block affinity before deletion.
				testWatcher4.ExpectEvents(libapiv3.KindBlockAffinity, []watch.Event{
					{
						Type:     watch.Deleted,
						Previous: outRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: outRes3,
					},
				})
			} else {
				// Clean calls the backend API client's Delete method which does not work for the Kubernetes datastore.
				// Call Delete manually for Kubernetes datastore tests.
				_, err = c.BlockAffinities().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: outRes1.ResourceVersion})
				Expect(err).NotTo(HaveOccurred())
				_, err = c.BlockAffinities().Delete(ctx, name2, options.DeleteOptions{ResourceVersion: outRes3.ResourceVersion})
				Expect(err).NotTo(HaveOccurred())
				testWatcher4.ExpectEvents(libapiv3.KindBlockAffinity, []watch.Event{
					{
						Type:     watch.Modified,
						Previous: outRes1,
						Object:   modifiedOutRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: modifiedOutRes1,
					},
					{
						Type:     watch.Modified,
						Previous: outRes3,
						Object:   modifiedOutRes3,
					},
					{
						Type:     watch.Deleted,
						Previous: modifiedOutRes3,
					},
				})
			}
			testWatcher4.Stop()
		})
	})
})
