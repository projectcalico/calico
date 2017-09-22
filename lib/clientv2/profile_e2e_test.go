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

	"context"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/backend"
	"github.com/projectcalico/libcalico-go/lib/clientv2"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/testutils"
	"github.com/projectcalico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("Profile tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	name1 := "profile-1"
	name2 := "profile-2"
	spec1 := apiv2.ProfileSpec{
		LabelsToApply: map[string]string {
			"aa": "bb",
		},
	}
	spec2 := apiv2.ProfileSpec{
		LabelsToApply: map[string]string {
			"bb": "cc",
		},
	}

	DescribeTable("Profile e2e CRUD tests",
		func(name1, name2 string, spec1, spec2 apiv2.ProfileSpec) {
			c, err := clientv2.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Updating the Profile before it is created")
			res, outError := c.Profiles().Update(context.Background(), &apiv2.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("resource does not exist: Profile(" + name1 + ")"))

			By("Attempting to creating a new Profile with name1/spec1 and a non-empty ResourceVersion")
			res, outError = c.Profiles().Create(context.Background(), &apiv2.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(res).To(BeNil())
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Creating a new Profile with name1/spec1")
			res1, outError := c.Profiles().Create(context.Background(), &apiv2.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			testutils.ExpectResource(res1, apiv2.KindProfile, clientv2.NoNamespace, name1, spec1)

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same Profile with name1 but with spec2")
			res1, outError = c.Profiles().Create(context.Background(), &apiv2.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: Profile(" + name1 + ")"))
			// Check return value is actually the previously stored value.
			testutils.ExpectResource(res1, apiv2.KindProfile, clientv2.NoNamespace, name1, spec1)
			Expect(res1.ResourceVersion).To(Equal(rv1_1))

			By("Getting Profile (name1) and comparing the output against spec1")
			res, outError = c.Profiles().Get(context.Background(), name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			testutils.ExpectResource(res, apiv2.KindProfile, clientv2.NoNamespace, name1, spec1)
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Getting Profile (name2) before it is created")
			res, outError = c.Profiles().Get(context.Background(), name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: Profile(" + name2 + ")"))

			By("Listing all the Profiles, expecting a single result with name1/spec1")
			outList, outError := c.Profiles().List(context.Background(), options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			testutils.ExpectResource(&outList.Items[0], apiv2.KindProfile, clientv2.NoNamespace, name1, spec1)

			By("Creating a new Profile with name2/spec2")
			res2, outError := c.Profiles().Create(context.Background(), &apiv2.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			testutils.ExpectResource(res2, apiv2.KindProfile, clientv2.NoNamespace, name2, spec2)

			By("Getting Profile (name2) and comparing the output against spec2")
			res, outError = c.Profiles().Get(context.Background(), name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			testutils.ExpectResource(res2, apiv2.KindProfile, clientv2.NoNamespace, name2, spec2)
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the Profiles, expecting a two results with name1/spec1 and name2/spec2")
			outList, outError = c.Profiles().List(context.Background(), options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(2))
			testutils.ExpectResource(&outList.Items[0], apiv2.KindProfile, clientv2.NoNamespace, name1, spec1)
			testutils.ExpectResource(&outList.Items[1], apiv2.KindProfile, clientv2.NoNamespace, name2, spec2)

			By("Updating Profile name1 with spec2")
			res1.Spec = spec2
			res1, outError = c.Profiles().Update(context.Background(), res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			testutils.ExpectResource(res1, apiv2.KindProfile, clientv2.NoNamespace, name1, spec2)

			// Track the version of the updated name1 data.
			rv1_2 := res1.ResourceVersion

			By("Updating Profile name1 without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			res, outError = c.Profiles().Update(context.Background(), res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))
			Expect(res).To(BeNil())

			By("Updating Profile name1 using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			res1, outError = c.Profiles().Update(context.Background(), res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: Profile(" + name1 + ")"))
			Expect(res1.ResourceVersion).To(Equal(rv1_2))

			By("Getting Profile (name1) with the original resource version and comparing the output against spec1")
			res, outError = c.Profiles().Get(context.Background(), name1, options.GetOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			testutils.ExpectResource(res, apiv2.KindProfile, clientv2.NoNamespace, name1, spec1)
			Expect(res.ResourceVersion).To(Equal(rv1_1))

			By("Getting Profile (name1) with the updated resource version and comparing the output against spec2")
			res, outError = c.Profiles().Get(context.Background(), name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			testutils.ExpectResource(res, apiv2.KindProfile, clientv2.NoNamespace, name1, spec2)
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			By("Listing Profiles with the original resource version and checking for a single result with name1/spec1")
			outList, outError = c.Profiles().List(context.Background(), options.ListOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			testutils.ExpectResource(&outList.Items[0], apiv2.KindProfile, clientv2.NoNamespace, name1, spec1)

			By("Listing Profiles with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError = c.Profiles().List(context.Background(), options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(2))
			testutils.ExpectResource(&outList.Items[0], apiv2.KindProfile, clientv2.NoNamespace, name1, spec2)
			testutils.ExpectResource(&outList.Items[1], apiv2.KindProfile, clientv2.NoNamespace, name2, spec2)

			By("Deleting Profile (name1) with the old resource version")
			outError = c.Profiles().Delete(context.Background(), name1, options.DeleteOptions{ResourceVersion: rv1_1})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: Profile(" + name1 + ")"))

			By("Deleting Profile (name1) with the new resource version")
			outError = c.Profiles().Delete(context.Background(), name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())

			By("Updating Profile name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.Profiles().Update(context.Background(), res2, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)
			_, outError = c.Profiles().Get(context.Background(), name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(2 * time.Second)
			_, outError = c.Profiles().Get(context.Background(), name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: Profile(" + name2 + ")"))

			By("Creating Profile name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.Profiles().Create(context.Background(), &apiv2.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)
			_, outError = c.Profiles().Get(context.Background(), name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(2 * time.Second)
			_, outError = c.Profiles().Get(context.Background(), name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: Profile(" + name2 + ")"))

			By("Attempting to deleting Profile (name2) again")
			outError = c.Profiles().Delete(context.Background(), name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: Profile(" + name2 + ")"))

			By("Listing all Profiles and expecting no items")
			outList, outError = c.Profiles().List(context.Background(), options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting Profile (name2) and expecting an error")
			res, outError = c.Profiles().Get(context.Background(), name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: Profile(" + name2 + ")"))
		},

		// Test 1: Pass two fully populated ProfileSpecs and expect the series of operations to succeed.
		Entry("Two fully populated ProfileSpecs", name1, name2, spec1, spec2),
	)

	Describe("Profile watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv2.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing Profiles with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError := c.Profiles().List(context.Background(), options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a Profile name1/spec1 and storing the response")
			outRes1, err := c.Profiles().Create(
				context.Background(),
				&apiv2.Profile{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			rev1 := outRes1.ResourceVersion

			By("Configuring a Profile name2/spec2 and storing the response")
			outRes2, err := c.Profiles().Create(
				context.Background(),
				&apiv2.Profile{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
				},
				options.SetOptions{},
			)

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.Profiles().Watch(context.Background(), options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.TestResourceWatch(w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			err = c.Profiles().Delete(context.Background(), name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(apiv2.KindProfile, []watch.Event{
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
			w, err = c.Profiles().Watch(context.Background(), options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.TestResourceWatch(w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.Profiles().Update(
				context.Background(),
				&apiv2.Profile{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv2.KindProfile, []watch.Event{
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

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.Profiles().Watch(context.Background(), options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.TestResourceWatch(w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(apiv2.KindProfile, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})
			testWatcher3.Stop()

			By("Configuring Profile name1/spec1 again and storing the response")
			outRes1, err = c.Profiles().Create(
				context.Background(),
				&apiv2.Profile{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.Profiles().Watch(context.Background(), options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.TestResourceWatch(w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEvents(apiv2.KindProfile, []watch.Event{
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
			testWatcher4.ExpectEvents(apiv2.KindProfile, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes3,
				},
			})
			testWatcher4.Stop()
		})
	})
})
