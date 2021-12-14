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

package clientv3_test

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("ClusterInformation tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	name := "default"
	readyTrue := true
	spec1 := apiv3.ClusterInformationSpec{
		ClusterGUID:    "test-cluster-guid1",
		ClusterType:    "test-cluster-type1",
		CalicoVersion:  "test-version1",
		DatastoreReady: &readyTrue,
	}
	spec2 := apiv3.ClusterInformationSpec{
		ClusterGUID:   "test-cluster-guid2",
		ClusterType:   "test-cluster-type2",
		CalicoVersion: "test-version2",
	}

	var c clientv3.Interface
	var be bapi.Client

	BeforeEach(func() {
		var err error
		c, err = clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())

		be, err = backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()
	})

	Describe("after running EnsureInitialized", func() {
		var kddTypePart string

		BeforeEach(func() {
			err := c.EnsureInitialized(ctx, "v0.0.0", "test")
			Expect(err).NotTo(HaveOccurred())
			if config.Spec.DatastoreType == "kubernetes" {
				kddTypePart = ",kdd"
			} else {
				kddTypePart = ""
			}
		})

		It("should create the ClusterInformation", func() {
			res, err := c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Spec.ClusterGUID).To(MatchRegexp("^[a-f0-9]{32}$"))
			Expect(res).To(MatchResource(
				apiv3.KindClusterInformation, testutils.ExpectNoNamespace,
				name,
				apiv3.ClusterInformationSpec{
					ClusterGUID:    res.Spec.ClusterGUID,
					ClusterType:    "test" + kddTypePart,
					CalicoVersion:  "v0.0.0",
					DatastoreReady: &readyTrue,
				}))
		})

		It("should be idempotent", func() {
			res, err := c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			guid := res.Spec.ClusterGUID

			err = c.EnsureInitialized(ctx, "v0.0.0", "test")
			Expect(err).NotTo(HaveOccurred())

			res, err = c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(
				apiv3.KindClusterInformation, testutils.ExpectNoNamespace,
				name,
				apiv3.ClusterInformationSpec{
					ClusterGUID:    guid,
					ClusterType:    "test" + kddTypePart,
					CalicoVersion:  "v0.0.0",
					DatastoreReady: &readyTrue,
				}))
		})

		It("should merge cluster types", func() {
			res, err := c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			guid := res.Spec.ClusterGUID

			err = c.EnsureInitialized(ctx, "v0.0.0", "test2")
			Expect(err).NotTo(HaveOccurred())

			res, err = c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			spec := apiv3.ClusterInformationSpec{
				ClusterGUID:    guid,
				ClusterType:    "test" + kddTypePart + ",test2",
				CalicoVersion:  "v0.0.0",
				DatastoreReady: &readyTrue,
			}
			Expect(res).To(MatchResource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace,
				name, spec))

			By("ignoring idempotent update 'test'")
			err = c.EnsureInitialized(ctx, "v0.0.0", "test")
			Expect(err).NotTo(HaveOccurred())
			res, err = c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace,
				name, spec))

			By("ignoring idempotent update 'test2'")
			err = c.EnsureInitialized(ctx, "v0.0.0", "test2")
			Expect(err).NotTo(HaveOccurred())
			res, err = c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace,
				name, spec))

			By("ignoring idempotent update ''")
			err = c.EnsureInitialized(ctx, "", "")
			Expect(err).NotTo(HaveOccurred())
			res, err = c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace,
				name, spec))
		})

		It("should overwrite version", func() {
			res, err := c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			guid := res.Spec.ClusterGUID

			err = c.EnsureInitialized(ctx, "v0.0.1", "test")
			Expect(err).NotTo(HaveOccurred())

			res, err = c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			spec := apiv3.ClusterInformationSpec{
				ClusterGUID:    guid,
				ClusterType:    "test" + kddTypePart,
				CalicoVersion:  "v0.0.1",
				DatastoreReady: &readyTrue,
			}
			Expect(res).To(MatchResource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace,
				name, spec))
		})

		Describe("after disabling ready flag", func() {
			BeforeEach(func() {
				res, err := c.ClusterInformation().Get(ctx, name, options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				readyFalse := false
				res.Spec.DatastoreReady = &readyFalse
				_, err = c.ClusterInformation().Update(ctx, res, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should not set it back to true", func() {
				err := c.EnsureInitialized(ctx, "v0.0.0", "test")
				Expect(err).NotTo(HaveOccurred())
				res, err := c.ClusterInformation().Get(ctx, name, options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(*res.Spec.DatastoreReady).To(BeFalse())
			})
		})

		Describe("after nilling-out ready flag", func() {
			BeforeEach(func() {
				res, err := c.ClusterInformation().Get(ctx, name, options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				res.Spec.DatastoreReady = nil
				_, err = c.ClusterInformation().Update(ctx, res, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should set it back to true", func() {
				err := c.EnsureInitialized(ctx, "v0.0.0", "test")
				Expect(err).NotTo(HaveOccurred())
				res, err := c.ClusterInformation().Get(ctx, name, options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(*res.Spec.DatastoreReady).To(BeTrue())
			})
		})
	})

	DescribeTable("ClusterInformation e2e CRUD tests",
		func(name string, spec1, spec2 apiv3.ClusterInformationSpec) {
			By("Updating the ClusterInformation before it is created")
			_, outError := c.ClusterInformation().Update(ctx, &apiv3.ClusterInformation{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: "test-fail-clusterinfo"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: ClusterInformation(" + name + ") with error:"))

			By("Attempting to creating a new ClusterInformation with name/spec1 and a non-empty ResourceVersion")
			_, outError = c.ClusterInformation().Create(ctx, &apiv3.ClusterInformation{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Getting ClusterInformation (name) before it is created")
			_, outError = c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: ClusterInformation(" + name + ") with error:"))

			By("Attempting to create a new ClusterInformation with a non-default name and spec1")
			_, outError = c.ClusterInformation().Create(ctx, &apiv3.ClusterInformation{
				ObjectMeta: metav1.ObjectMeta{Name: "not-default"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("Cannot create a Cluster Information resource with a name other than \"default\""))

			By("Creating a new ClusterInformation with name/spec1")
			res1, outError := c.ClusterInformation().Create(ctx, &apiv3.ClusterInformation{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace, name, spec1))

			// Track the version of the original data for name.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same ClusterInformation with name but with spec2")
			_, outError = c.ClusterInformation().Create(ctx, &apiv3.ClusterInformation{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: ClusterInformation(" + name + ")"))

			By("Getting ClusterInformation (name) and comparing the output against spec1")
			res, outError := c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace, name, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Listing all the ClusterInformation, expecting a single result with name/spec1")
			outList, outError := c.ClusterInformation().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace, name, spec1),
			))

			By("Updating ClusterInformation name with spec2")
			res1.Spec = spec2
			res1, outError = c.ClusterInformation().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace, name, spec2))

			By("Attempting to update the ClusterInformation without a Creation Timestamp")
			res, outError = c.ClusterInformation().Update(ctx, &apiv3.ClusterInformation{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", UID: "test-fail-clusterinfo"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the ClusterInformation without a UID")
			res, outError = c.ClusterInformation().Update(ctx, &apiv3.ClusterInformation{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name data.
			rv1_2 := res1.ResourceVersion

			By("Updating ClusterInformation name without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.ClusterInformation().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating ClusterInformation name using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			_, outError = c.ClusterInformation().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: ClusterInformation(" + name + ")"))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Getting ClusterInformation (name) with the original resource version and comparing the output against spec1")
				res, outError = c.ClusterInformation().Get(ctx, name, options.GetOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(res).To(MatchResource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace, name, spec1))
				Expect(res.ResourceVersion).To(Equal(rv1_1))
			}

			By("Getting ClusterInformation (name) with the updated resource version and comparing the output against spec2")
			res, outError = c.ClusterInformation().Get(ctx, name, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace, name, spec2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Listing ClusterInformation with the original resource version and checking for a single result with name/spec1")
				outList, outError = c.ClusterInformation().List(ctx, options.ListOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(outList.Items).To(ConsistOf(
					testutils.Resource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace, name, spec1),
				))
			}

			By("Listing ClusterInformation with the latest resource version and checking for one result with name/spec2")
			outList, outError = c.ClusterInformation().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace, name, spec2),
			))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Deleting ClusterInformation (name) with the old resource version")
				_, outError = c.ClusterInformation().Delete(ctx, name, options.DeleteOptions{ResourceVersion: rv1_1})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal("update conflict: ClusterInformation(" + name + ")"))
			}

			By("Deleting ClusterInformation (name) with the new resource version")
			dres, outError := c.ClusterInformation().Delete(ctx, name, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(apiv3.KindClusterInformation, testutils.ExpectNoNamespace, name, spec2))

			By("Listing all ClusterInformation and expecting no items")
			outList, outError = c.ClusterInformation().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

		},

		// Test 1: Pass two fully populated ClusterInformationSpecs and expect the series of operations to succeed.
		Entry("Two fully populated ClusterInformationSpecs", name, spec1, spec2),
	)

	Describe("ClusterInformation watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			By("Listing ClusterInformation with the latest resource version and checking for one result with name/spec2")
			outList, outError := c.ClusterInformation().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a ClusterInformation name/spec1 and storing the response")
			outRes1, err := c.ClusterInformation().Create(
				ctx,
				&apiv3.ClusterInformation{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			rev1 := outRes1.ResourceVersion

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.ClusterInformation().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.ClusterInformation().Delete(ctx, name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for event: delete res1")
			testWatcher1.ExpectEvents(apiv3.KindClusterInformation, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
			})
			testWatcher1.Stop()

			By("Configuring a ClusterInformation name2/spec2 and storing the response")
			outRes2, err := c.ClusterInformation().Create(
				ctx,
				&apiv3.ClusterInformation{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec:       spec2,
				},
				options.SetOptions{},
			)

			By("Starting a watcher from rev0 - this should get all events")
			w, err = c.ClusterInformation().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.ClusterInformation().Update(
				ctx,
				&apiv3.ClusterInformation{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindClusterInformation, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Modified,
					Previous: outRes2,
					Object:   outRes3,
				},
			})
			testWatcher2.Stop()

			// Only etcdv3 supports watching a specific instance of a resource.
			if config.Spec.DatastoreType == apiconfig.EtcdV3 {
				By("Starting a watcher from rev0 watching name - this should get all events for name")
				w, err = c.ClusterInformation().Watch(ctx, options.ListOptions{Name: name, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(apiv3.KindClusterInformation, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: outRes1,
					},
					{
						Type:   watch.Added,
						Object: outRes2,
					},
					{
						Type:     watch.Modified,
						Previous: outRes2,
						Object:   outRes3,
					},
				})
				testWatcher2_1.Stop()
			}

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.ClusterInformation().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEventsAnyOrder(apiv3.KindClusterInformation, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})

			By("Cleaning the datastore and expecting deletion events for each configured resource (tests prefix deletes results in individual events for each key)")
			be.Clean()
			testWatcher3.ExpectEvents(apiv3.KindClusterInformation, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes3,
				},
			})
			testWatcher3.Stop()
		})
	})
})
