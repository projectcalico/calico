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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"context"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("Profile tests", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	name1 := "profile-1"
	name2 := "profile-2"
	spec1 := apiv3.ProfileSpec{
		LabelsToApply: map[string]string{
			"aa": "bb",
		},
	}
	spec2 := apiv3.ProfileSpec{
		LabelsToApply: map[string]string{
			"bb": "cc",
		},
	}
	defaultAllowSpec := apiv3.ProfileSpec{
		Ingress: []v3.Rule{{Action: apiv3.Allow}},
		Egress:  []v3.Rule{{Action: apiv3.Allow}},
	}
	defaultAllowName := "projectcalico-default-allow"

	DescribeTable("Profile e2e CRUD tests",
		func(name1, name2 string, spec1, spec2 apiv3.ProfileSpec) {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing all the Profiles, expecting a single result with the default-allow profile")
			outList, outError := c.Profiles().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindProfile, testutils.ExpectNoNamespace, defaultAllowName, defaultAllowSpec),
			))

			By("Updating the Profile before it is created")
			_, outError = c.Profiles().Update(ctx, &apiv3.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: "test-fail-profile"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: Profile(" + name1 + ") with error:"))

			By("Attempting to creating a new Profile with name1/spec1 and a non-empty ResourceVersion")
			_, outError = c.Profiles().Create(ctx, &apiv3.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Creating a new Profile with name1/spec1")
			res1, outError := c.Profiles().Create(ctx, &apiv3.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindProfile, testutils.ExpectNoNamespace, name1, spec1))

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same Profile with name1 but with spec2")
			_, outError = c.Profiles().Create(ctx, &apiv3.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: Profile(" + name1 + ")"))

			By("Getting Profile (name1) and comparing the output against spec1")
			res, outError := c.Profiles().Get(ctx, name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindProfile, testutils.ExpectNoNamespace, name1, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Getting Profile (name2) before it is created")
			_, outError = c.Profiles().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: Profile(" + name2 + ") with error:"))

			By("Listing all the Profiles, expecting 2 results, including name1/spec1")
			outList, outError = c.Profiles().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindProfile, testutils.ExpectNoNamespace, defaultAllowName, defaultAllowSpec),
				testutils.Resource(apiv3.KindProfile, testutils.ExpectNoNamespace, name1, spec1),
			))

			By("Creating a new Profile with name2/spec2")
			res2, outError := c.Profiles().Create(ctx, &apiv3.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(apiv3.KindProfile, testutils.ExpectNoNamespace, name2, spec2))

			By("Getting Profile (name2) and comparing the output against spec2")
			res, outError = c.Profiles().Get(ctx, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(apiv3.KindProfile, testutils.ExpectNoNamespace, name2, spec2))
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the Profiles, expecting 3 results, including name1/spec1 and name2/spec2")
			outList, outError = c.Profiles().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindProfile, testutils.ExpectNoNamespace, defaultAllowName, defaultAllowSpec),
				testutils.Resource(apiv3.KindProfile, testutils.ExpectNoNamespace, name1, spec1),
				testutils.Resource(apiv3.KindProfile, testutils.ExpectNoNamespace, name2, spec2),
			))

			By("Updating Profile name1 with spec2")
			res1.Spec = spec2
			res1, outError = c.Profiles().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindProfile, testutils.ExpectNoNamespace, name1, spec2))

			By("Attempting to update the Profile without a Creation Timestamp")
			res, outError = c.Profiles().Update(ctx, &apiv3.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", UID: "test-fail-profile"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the Profile without a UID")
			res, outError = c.Profiles().Update(ctx, &apiv3.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name1 data.
			rv1_2 := res1.ResourceVersion

			By("Updating Profile name1 without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.Profiles().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating Profile name1 using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			_, outError = c.Profiles().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: Profile(" + name1 + ")"))

			By("Getting Profile (name1) with the original resource version and comparing the output against spec1")
			res, outError = c.Profiles().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindProfile, testutils.ExpectNoNamespace, name1, spec1))
			Expect(res.ResourceVersion).To(Equal(rv1_1))

			By("Getting Profile (name1) with the updated resource version and comparing the output against spec2")
			res, outError = c.Profiles().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindProfile, testutils.ExpectNoNamespace, name1, spec2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			By("Listing Profiles with the original resource version and checking for 2 results, including name1/spec1")
			outList, outError = c.Profiles().List(ctx, options.ListOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())

			// We're specifying an rv that is outside of the default-allow profile's
			// pseudo rv.
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindProfile, testutils.ExpectNoNamespace, defaultAllowName, defaultAllowSpec),
				testutils.Resource(apiv3.KindProfile, testutils.ExpectNoNamespace, name1, spec1),
			))

			By("Listing Profiles with the latest resource version and checking for 3 results including name1/spec2 and name2/spec2")
			outList, outError = c.Profiles().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindProfile, testutils.ExpectNoNamespace, defaultAllowName, defaultAllowSpec),
				testutils.Resource(apiv3.KindProfile, testutils.ExpectNoNamespace, name1, spec2),
				testutils.Resource(apiv3.KindProfile, testutils.ExpectNoNamespace, name2, spec2),
			))

			By("Deleting Profile (name1) with the old resource version")
			_, outError = c.Profiles().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_1})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: Profile(" + name1 + ")"))

			By("Deleting Profile (name1) with the new resource version")
			dres, outError := c.Profiles().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(apiv3.KindProfile, testutils.ExpectNoNamespace, name1, spec2))

			By("Updating Profile name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.Profiles().Update(ctx, res2, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)
			_, outError = c.Profiles().Get(ctx, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(2 * time.Second)
			_, outError = c.Profiles().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: Profile(" + name2 + ") with error:"))

			By("Creating Profile name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.Profiles().Create(ctx, &apiv3.Profile{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)
			_, outError = c.Profiles().Get(ctx, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(2 * time.Second)
			_, outError = c.Profiles().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: Profile(" + name2 + ") with error:"))

			By("Attempting to deleting Profile (name2) again")
			_, outError = c.Profiles().Delete(ctx, name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: Profile(" + name2 + ") with error:"))

			By("Listing all Profiles and expecting 1 item")
			outList, outError = c.Profiles().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))

			By("Getting Profile (name2) and expecting an error")
			_, outError = c.Profiles().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: Profile(" + name2 + ") with error:"))

			By("Creating Profile (projectcalico-default-allow) and expecting an error")
			res = apiv3.NewProfile()
			res.Name = defaultAllowName
			res.Spec = defaultAllowSpec
			_, outError = c.Profiles().Create(ctx, res, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource already exists: projectcalico-default-allow"))

			By("Getting Profile (projectcalico-default-allow) with any rv should return the resource")
			rvs := []string{"", "0", "1", "2"}
			for _, rv := range rvs {
				res, outError = c.Profiles().Get(ctx, defaultAllowName, options.GetOptions{ResourceVersion: rv})
				Expect(outError).NotTo(HaveOccurred())

				Expect(res.Name).To(Equal(defaultAllowName))
				Expect(res.Namespace).To(BeEmpty())
				Expect(res.Spec.Ingress).Should(ConsistOf(defaultAllowSpec.Ingress))
				Expect(res.Spec.Egress).Should(ConsistOf(defaultAllowSpec.Egress))
			}

			By("Listing all Profiles with any rv should return the default-allow profile")
			rvs = []string{"", "0", "1", "2"}
			for _, rv := range rvs {
				outList, outError = c.Profiles().List(ctx, options.ListOptions{ResourceVersion: rv})
				Expect(outError).NotTo(HaveOccurred())

				Expect(outList.Items).To(ConsistOf(
					testutils.Resource(apiv3.KindProfile, testutils.ExpectNoNamespace, defaultAllowName, defaultAllowSpec),
				))
			}

			By("Updating Profile (projectcalico-default-allow) and expecting an error")
			// Fill in some fields to pass validation.
			res.ResourceVersion = "fakerv"
			res.CreationTimestamp = metav1.Now()
			res.UID = "uid"

			_, outError = c.Profiles().Update(ctx, res, options.SetOptions{})
			Expect(outError).To(HaveOccurred())

			Expect(outError.Error()).To(ContainSubstring("The profile \"projectcalico-default-allow\" is a default provided by Calico and cannot be updated"))

			By("Deleting Profile (projectcalico-default-allow) and expecting an error")
			_, outError = c.Profiles().Delete(ctx, defaultAllowName, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("The profile \"projectcalico-default-allow\" is a default provided by Calico and cannot be deleted"))
		},

		// Test 1: Pass two fully populated ProfileSpecs and expect the series of operations to succeed.
		Entry("Two fully populated ProfileSpecs", name1, name2, spec1, spec2),
	)

	Describe("Profile watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing Profiles with the latest resource version and checking for no results")
			outList, outError := c.Profiles().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			Expect(outList.Items[0].ResourceVersion).To(Equal("0"))
			Expect(outList.Items[0].Spec.Ingress).To(ConsistOf(defaultAllowSpec.Ingress))
			Expect(outList.Items[0].Spec.Egress).To(ConsistOf(defaultAllowSpec.Egress))
			rev0 := outList.ResourceVersion

			By("Starting a watcher with no revision")
			w, err := c.Profiles().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)

			By("Configuring a Profile name1/spec1 and storing the response")
			outRes1, err := c.Profiles().Create(
				ctx,
				&apiv3.Profile{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			rev1 := outRes1.ResourceVersion

			By("Configuring a Profile name2/spec2 and storing the response")
			outRes2, err := c.Profiles().Create(
				ctx,
				&apiv3.Profile{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
				},
				options.SetOptions{},
			)

			By("Starting a watcher with no revision")
			w, err = c.Profiles().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher = testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)

			By("Checking for 2 ADDED events for the 2 profiles above but not the default-allow profile")
			testWatcher.ExpectEvents(apiv3.KindProfile, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes2,
				},
			})
			testWatcher.Stop()

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err = c.Profiles().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.Profiles().Delete(ctx, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(apiv3.KindProfile, []watch.Event{
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
			w, err = c.Profiles().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.Profiles().Update(
				ctx,
				&apiv3.Profile{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindProfile, []watch.Event{
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

			// Only etcdv3 supports watching a specific instance of a resource.
			if config.Spec.DatastoreType == apiconfig.EtcdV3 {
				By("Starting a watcher from rev0 watching name1 - this should get all events for name1")
				w, err = c.Profiles().Watch(ctx, options.ListOptions{Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()

				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1.ExpectEvents(apiv3.KindProfile, []watch.Event{
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
			w, err = c.Profiles().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()

			Expect(err).NotTo(HaveOccurred())

			testWatcher3.ExpectEvents(apiv3.KindProfile, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})
			testWatcher3.Stop()

			By("Configuring Profile name1/spec1 again and storing the response")
			outRes1, err = c.Profiles().Create(
				ctx,
				&apiv3.Profile{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.Profiles().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEvents(apiv3.KindProfile, []watch.Event{
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
			testWatcher4.ExpectEvents(apiv3.KindProfile, []watch.Event{
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
