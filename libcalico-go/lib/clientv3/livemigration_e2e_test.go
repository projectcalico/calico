// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("LiveMigration tests", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	namespace1 := "namespace-1"
	namespace2 := "namespace-2"
	name1 := "livemigration-1"
	name2 := "livemigration-2"
	spec1 := libapiv3.LiveMigrationSpec{
		DestinationWorkloadEndpoint: types.NamespacedName{
			Namespace: "ns-dest-1",
			Name:      "wep-dest-1",
		},
		SourceWorkloadEndpoint: types.NamespacedName{
			Namespace: "ns-src-1",
			Name:      "wep-src-1",
		},
	}
	spec2 := libapiv3.LiveMigrationSpec{
		DestinationWorkloadEndpoint: types.NamespacedName{
			Namespace: "ns-dest-2",
			Name:      "wep-dest-2",
		},
		SourceWorkloadEndpoint: types.NamespacedName{
			Namespace: "ns-src-2",
			Name:      "wep-src-2",
		},
	}

	DescribeTable("LiveMigration e2e CRUD tests",
		func(namespace1, namespace2, name1, name2 string, spec1, spec2 libapiv3.LiveMigrationSpec) {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Updating the LiveMigration before it is created")
			_, outError := c.LiveMigrations().Update(ctx, &libapiv3.LiveMigration{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: uid},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: LiveMigration(" + namespace1 + "/" + name1 + ") with error:"))

			By("Attempting to get a LiveMigration before it is created")
			_, outError = c.LiveMigrations().Get(ctx, namespace1, name1, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: LiveMigration(" + namespace1 + "/" + name1 + ") with error:"))

			By("Attempting to create a new LiveMigration with a non-empty ResourceVersion")
			_, outError = c.LiveMigrations().Create(ctx, &libapiv3.LiveMigration{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Creating a new LiveMigration with namespace1/name1/spec1")
			res1, outError := c.LiveMigrations().Create(ctx, &libapiv3.LiveMigration{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(libapiv3.KindLiveMigration, namespace1, name1, spec1))

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same LiveMigration with name1 but with spec2")
			_, outError = c.LiveMigrations().Create(ctx, &libapiv3.LiveMigration{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource already exists: LiveMigration(" + namespace1 + "/" + name1 + ") with error:"))

			By("Getting LiveMigration (name1) and comparing the output against spec1")
			res, outError := c.LiveMigrations().Get(ctx, namespace1, name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindLiveMigration, namespace1, name1, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Getting LiveMigration (name2) before it is created")
			_, outError = c.LiveMigrations().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: LiveMigration(" + namespace2 + "/" + name2 + ") with error:"))

			By("Listing all the LiveMigrations in namespace1, expecting a single result with name1/spec1")
			outList, outError := c.LiveMigrations().List(ctx, options.ListOptions{Namespace: namespace1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindLiveMigration, namespace1, name1, spec1),
			))

			By("Creating a new LiveMigration with namespace2/name2/spec2")
			res2, outError := c.LiveMigrations().Create(ctx, &libapiv3.LiveMigration{
				ObjectMeta: metav1.ObjectMeta{Name: name2, Namespace: namespace2},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(libapiv3.KindLiveMigration, namespace2, name2, spec2))

			By("Getting LiveMigration (name2) and comparing the output against spec2")
			res, outError = c.LiveMigrations().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindLiveMigration, namespace2, name2, spec2))
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the LiveMigrations using an empty namespace (all-namespaces), expecting two results")
			outList, outError = c.LiveMigrations().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindLiveMigration, namespace1, name1, spec1),
				testutils.Resource(libapiv3.KindLiveMigration, namespace2, name2, spec2),
			))

			By("Listing all the LiveMigrations in namespace2, expecting a single result with name2/spec2")
			outList, outError = c.LiveMigrations().List(ctx, options.ListOptions{Namespace: namespace2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindLiveMigration, namespace2, name2, spec2),
			))

			By("Updating LiveMigration name1 with spec2")
			res1.Spec = spec2
			res1Out, outError := c.LiveMigrations().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			res1 = res1Out
			Expect(res1).To(MatchResource(libapiv3.KindLiveMigration, namespace1, name1, spec2))

			// Track the version of the updated name1 data.
			rv1_2 := res1.ResourceVersion

			By("Updating LiveMigration name1 using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			_, outError = c.LiveMigrations().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: LiveMigration(" + namespace1 + "/" + name1 + ")"))

			By("Getting LiveMigration (name1) with the original resource version and comparing the output against spec1")
			res, outError = c.LiveMigrations().Get(ctx, namespace1, name1, options.GetOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindLiveMigration, namespace1, name1, spec1))
			Expect(res.ResourceVersion).To(Equal(rv1_1))

			By("Getting LiveMigration (name1) with the updated resource version and comparing the output against spec2")
			res, outError = c.LiveMigrations().Get(ctx, namespace1, name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindLiveMigration, namespace1, name1, spec2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			By("Deleting LiveMigration (name1) with the old resource version")
			_, outError = c.LiveMigrations().Delete(ctx, namespace1, name1, options.DeleteOptions{ResourceVersion: rv1_1})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: LiveMigration(" + namespace1 + "/" + name1 + ")"))

			By("Deleting LiveMigration (name1) with the new resource version")
			dres, outError := c.LiveMigrations().Delete(ctx, namespace1, name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(libapiv3.KindLiveMigration, namespace1, name1, spec2))

			By("Deleting LiveMigration (name2)")
			dres, outError = c.LiveMigrations().Delete(ctx, namespace2, name2, options.DeleteOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(libapiv3.KindLiveMigration, namespace2, name2, spec2))

			By("Attempting to delete LiveMigration (name2) again")
			_, outError = c.LiveMigrations().Delete(ctx, namespace2, name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: LiveMigration(" + namespace2 + "/" + name2 + ") with error:"))

			By("Listing all LiveMigrations and expecting no items")
			outList, outError = c.LiveMigrations().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting LiveMigration (name2) and expecting an error")
			_, outError = c.LiveMigrations().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: LiveMigration(" + namespace2 + "/" + name2 + ") with error:"))
		},

		Entry("Two fully populated LiveMigrationSpecs",
			namespace1, namespace2,
			name1, name2,
			spec1, spec2,
		),
	)

	Describe("LiveMigration watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing LiveMigrations with the latest resource version and checking for no results")
			outList, outError := c.LiveMigrations().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a LiveMigration namespace1/name1/spec1 and storing the response")
			outRes1, err := c.LiveMigrations().Create(
				ctx,
				&libapiv3.LiveMigration{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			rev1 := outRes1.ResourceVersion
			Expect(err).NotTo(HaveOccurred())

			By("Configuring a LiveMigration namespace2/name2/spec2 and storing the response")
			outRes2, err := c.LiveMigrations().Create(
				ctx,
				&libapiv3.LiveMigration{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace2, Name: name2},
					Spec:       spec2,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.LiveMigrations().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.LiveMigrations().Delete(ctx, namespace1, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete res1")
			testWatcher1.ExpectEvents(libapiv3.KindLiveMigration, []watch.Event{
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

			By("Starting a watcher from rev0 - this should get all events")
			w, err = c.LiveMigrations().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.LiveMigrations().Update(
				ctx,
				&libapiv3.LiveMigration{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(libapiv3.KindLiveMigration, []watch.Event{
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
			testWatcher2.Stop()

			By("Starting a watcher from rev0 watching name1 - this should get all events for name1")
			w, err = c.LiveMigrations().Watch(ctx, options.ListOptions{Namespace: namespace1, Name: name1, ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2_1.Stop()
			testWatcher2_1.ExpectEvents(libapiv3.KindLiveMigration, []watch.Event{
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

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.LiveMigrations().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(libapiv3.KindLiveMigration, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})
			testWatcher3.Stop()

			By("Starting a watcher at rev0 in namespace1 - expect the events for LiveMigration in namespace1")
			w, err = c.LiveMigrations().Watch(ctx, options.ListOptions{Namespace: namespace1, ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEvents(libapiv3.KindLiveMigration, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
			})
			testWatcher4.Stop()
		})
	})
})
