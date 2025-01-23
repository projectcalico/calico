// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("StagedGlobalNetworkPolicy tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	order1 := 99.999
	order2 := 22.222
	tier := "tier-a"
	tierOrder := float64(10)
	name1 := "globalnetworkp-1"
	name2 := "globalnetworkp-2"

	spec1 := apiv3.StagedGlobalNetworkPolicySpec{
		StagedAction: v3.StagedActionSet,
		Order:        &order1,
		Ingress:      []apiv3.Rule{testutils.InRule1, testutils.InRule2},
		Egress:       []apiv3.Rule{testutils.EgressRule1, testutils.EgressRule2},
		Selector:     "thing == 'value'",
	}

	spec2 := apiv3.StagedGlobalNetworkPolicySpec{
		StagedAction:   v3.StagedActionSet,
		Order:          &order2,
		Ingress:        []apiv3.Rule{testutils.InRule2, testutils.InRule1},
		Egress:         []apiv3.Rule{testutils.EgressRule2, testutils.EgressRule1},
		Selector:       "thing2 == 'value2'",
		DoNotTrack:     true,
		ApplyOnForward: true,
	}

	// Specs with only ingress or egress rules, without Types set.
	ingressSpec1 := spec1
	ingressSpec1.Egress = nil
	egressSpec2 := spec2
	egressSpec2.Ingress = nil
	// Specs with ingress and egress rules, with Types set to just ingress or egress.
	ingressTypesSpec1 := spec1
	ingressTypesSpec1.Types = ingress
	egressTypesSpec2 := spec2
	egressTypesSpec2.Types = egress

	var c clientv3.Interface
	var be bapi.Client

	BeforeEach(func() {
		var err error
		c, err = clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())

		be, err = backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		err = c.EnsureInitialized(ctx, "", "", "")
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("StagedGlobalNetworkPolicy e2e CRUD tests",
		func(tier, name1, name2 string, spec1, spec2 apiv3.StagedGlobalNetworkPolicySpec, types1, types2 []apiv3.PolicyType) {
			spec1.Tier = tier
			spec2.Tier = tier

			if tier != "" && tier != "default" {
				// Create the tier if required before running other tiered policy tests.
				denyAction := apiv3.Deny
				tierSpec := apiv3.TierSpec{Order: &tierOrder, DefaultAction: &denyAction}
				By("Creating the tier")
				tierRes, resErr := c.Tiers().Create(ctx, &apiv3.Tier{
					ObjectMeta: metav1.ObjectMeta{Name: tier},
					Spec:       tierSpec,
				}, options.SetOptions{})
				Expect(resErr).NotTo(HaveOccurred())
				Expect(tierRes).To(MatchResource(apiv3.KindTier, testutils.ExpectNoNamespace, tier, tierSpec))
			}

			By("Updating the StagedGlobalNetworkPolicy before it is created")
			_, outError := c.StagedGlobalNetworkPolicies().Update(ctx, &apiv3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: uid},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: StagedGlobalNetworkPolicy(" + tieredGNPName(name1, tier) + ") with error:"))

			By("Attempting to creating a new StagedGlobalNetworkPolicy with name1/spec1 and a non-empty ResourceVersion")
			polToCreate := &apiv3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
				Spec:       spec1,
			}
			polToCreateCopy := polToCreate.DeepCopy()
			_, outError = c.StagedGlobalNetworkPolicies().Create(ctx, polToCreate, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))
			Expect(polToCreate).To(Equal(polToCreateCopy), "Create() unexpectedly modified input policy")

			By("Creating a new StagedGlobalNetworkPolicy with name1/spec1")
			spec1.Types = types1
			polToCreate = &apiv3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
			}
			polToCreateCopy = polToCreate.DeepCopy()
			res1, outError := c.StagedGlobalNetworkPolicies().Create(ctx, polToCreate, options.SetOptions{})
			Expect(polToCreate).To(Equal(polToCreateCopy), "Create() unexpectedly modified input policy")
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name1, tier), spec1))

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same StagedGlobalNetworkPolicy with name1 but with spec2")
			_, outError = c.StagedGlobalNetworkPolicies().Create(ctx, &apiv3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: StagedGlobalNetworkPolicy(" + tieredGNPName(name1, tier) + ")"))

			By("Getting StagedGlobalNetworkPolicy (name1) and comparing the output against spec1")
			res, outError := c.StagedGlobalNetworkPolicies().Get(ctx, name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name1, tier), spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Getting StagedGlobalNetworkPolicy (name2) before it is created")
			_, outError = c.StagedGlobalNetworkPolicies().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: StagedGlobalNetworkPolicy(" + tieredGNPName(name2, tier) + ") with error:"))

			By("Listing all the StagedGlobalNetworkPolicies, expecting a single result with name1/spec1")
			outList, outError := c.StagedGlobalNetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name1, tier), spec1),
			))

			By("Creating a new StagedGlobalNetworkPolicy with name2/spec2")
			spec2.Types = types2
			res2, outError := c.StagedGlobalNetworkPolicies().Create(ctx, &apiv3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name2, tier), spec2))

			By("Getting StagedGlobalNetworkPolicy (name2) and comparing the output against spec2")
			res, outError = c.StagedGlobalNetworkPolicies().Get(ctx, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name2, tier), spec2))
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the StagedGlobalNetworkPolicies, expecting a two results with name1/spec1 and name2/spec2")
			outList, outError = c.StagedGlobalNetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name1, tier), spec1),
				testutils.Resource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name2, tier), spec2),
			))

			By("Updating StagedGlobalNetworkPolicy name1 with spec2")
			res1.Spec = spec2
			res1Copy := res1.DeepCopy()
			res1out, outError := c.StagedGlobalNetworkPolicies().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(Equal(res1Copy), "Update() unexpectedly modified input")
			Expect(res1).To(MatchResource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name1, tier), spec2))
			res1 = res1out

			By("Attempting to update the StagedGlobalNetworkPolicy without a Creation Timestamp")
			res, outError = c.StagedGlobalNetworkPolicies().Update(ctx, &apiv3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", UID: uid},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the StagedGlobalNetworkPolicy without a UID")
			res, outError = c.StagedGlobalNetworkPolicies().Update(ctx, &apiv3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name1 data.
			rv1_2 := res1.ResourceVersion

			By("Updating StagedGlobalNetworkPolicy name1 without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.StagedGlobalNetworkPolicies().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating StagedGlobalNetworkPolicy name1 using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			_, outError = c.StagedGlobalNetworkPolicies().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: StagedGlobalNetworkPolicy(" + tieredGNPName(name1, tier) + ")"))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Getting StagedGlobalNetworkPolicy (name1) with the original resource version and comparing the output against spec1")
				res, outError = c.StagedGlobalNetworkPolicies().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(res).To(MatchResource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name1, tier), spec1))
				Expect(res.ResourceVersion).To(Equal(rv1_1))
			}

			By("Getting StagedGlobalNetworkPolicy (name1) with the updated resource version and comparing the output against spec2")
			res, outError = c.StagedGlobalNetworkPolicies().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name1, tier), spec2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Listing StagedGlobalNetworkPolicies with the original resource version and checking for a single result with name1/spec1")
				outList, outError = c.StagedGlobalNetworkPolicies().List(ctx, options.ListOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(outList.Items).To(ConsistOf(
					testutils.Resource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name1, tier), spec1),
				))
			}

			By("Listing StagedGlobalNetworkPolicies with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError = c.StagedGlobalNetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name1, tier), spec2),
				testutils.Resource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name2, tier), spec2),
			))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Deleting StagedGlobalNetworkPolicy (name1) with the old resource version")
				_, outError = c.StagedGlobalNetworkPolicies().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_1})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal("update conflict: StagedGlobalNetworkPolicy(" + tieredGNPName(name1, tier) + ")"))
			}

			By("Deleting StagedGlobalNetworkPolicy (name1) with the new resource version")
			dres, outError := c.StagedGlobalNetworkPolicies().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name1, tier), spec2))
			time.Sleep(1 * time.Second)

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Updating StagedGlobalNetworkPolicy name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.StagedGlobalNetworkPolicies().Update(ctx, res2, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
				_, outError = c.StagedGlobalNetworkPolicies().Get(ctx, name2, options.GetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(2 * time.Second)
				_, outError = c.StagedGlobalNetworkPolicies().Get(ctx, name2, options.GetOptions{})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(ContainSubstring("resource does not exist: StagedGlobalNetworkPolicy(" + tieredGNPName(name2, tier) + ") with error:"))

				By("Creating StagedGlobalNetworkPolicy name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.StagedGlobalNetworkPolicies().Create(ctx, &apiv3.StagedGlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
				}, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
				_, outError = c.StagedGlobalNetworkPolicies().Get(ctx, name2, options.GetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(2 * time.Second)
				_, outError = c.StagedGlobalNetworkPolicies().Get(ctx, name2, options.GetOptions{})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(ContainSubstring("resource does not exist: StagedGlobalNetworkPolicy(" + tieredGNPName(name2, tier) + ") with error:"))
			}

			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				By("Deleting StagedGlobalNetworkPolicy (name2) for KDD that does not support TTL")
				dres, outError = c.StagedGlobalNetworkPolicies().Delete(ctx, name2, options.DeleteOptions{})
				Expect(outError).NotTo(HaveOccurred())
				Expect(dres).To(MatchResource(apiv3.KindStagedGlobalNetworkPolicy, testutils.ExpectNoNamespace, tieredGNPName(name2, tier), spec2))
				time.Sleep(1 * time.Second)
			}

			By("Attempting to delete StagedGlobalNetworkPolicy (name2) again")
			_, outError = c.StagedGlobalNetworkPolicies().Delete(ctx, name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: StagedGlobalNetworkPolicy(" + tieredGNPName(name2, tier) + ") with error:"))

			By("Listing all StagedGlobalNetworkPolicies and expecting no items")
			outList, outError = c.StagedGlobalNetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting StagedGlobalNetworkPolicy (name2) and expecting an error")
			_, outError = c.StagedGlobalNetworkPolicies().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: StagedGlobalNetworkPolicy(" + tieredGNPName(name2, tier) + ") with error:"))
		},

		// Pass two fully populated StagedGlobalNetworkPolicySpecs in a tier, and expect the series of operations to succeed.
		Entry("Two fully populated StagedGlobalNetworkPolicySpecs", tier, tier+"."+name1, tier+"."+name2, spec1, spec2, ingressEgress, ingressEgress),
		// Pass two fully populated StagedGlobalNetworkPolicySpecs in default tier and expect the series of operations to succeed.
		Entry("Two fully populated StagedGlobalNetworkPolicySpecs", "default", name1, name2, spec1, spec2, ingressEgress, ingressEgress),
		// Check defaulting for policies with ingress rules and egress rules only.
		Entry("Ingress-only and egress-only policies", "default", name1, name2, ingressSpec1, egressSpec2, ingress, egress),
		// Check non-defaulting for policies with explicit Types value.
		Entry("Policies with explicit ingress and egress Types", "default", name1, name2, ingressTypesSpec1, egressTypesSpec2, ingress, egress),
	)

	Describe("StagedGlobalNetworkPolicy watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			By("Listing StagedGlobalNetworkPolicies with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError := c.StagedGlobalNetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a StagedGlobalNetworkPolicy name1/spec1 and storing the response")
			outRes1, err := c.StagedGlobalNetworkPolicies().Create(
				ctx,
				&apiv3.StagedGlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			rev1 := outRes1.ResourceVersion

			By("Configuring a StagedGlobalNetworkPolicy name2/spec2 and storing the response")
			outRes2, err := c.StagedGlobalNetworkPolicies().Create(
				ctx,
				&apiv3.StagedGlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
				},
				options.SetOptions{},
			)

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.StagedGlobalNetworkPolicies().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.StagedGlobalNetworkPolicies().Delete(ctx, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(apiv3.KindStagedGlobalNetworkPolicy, []watch.Event{
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
			w, err = c.StagedGlobalNetworkPolicies().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.StagedGlobalNetworkPolicies().Update(
				ctx,
				&apiv3.StagedGlobalNetworkPolicy{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindStagedGlobalNetworkPolicy, []watch.Event{
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
				w, err = c.StagedGlobalNetworkPolicies().Watch(ctx, options.ListOptions{Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(apiv3.KindStagedGlobalNetworkPolicy, []watch.Event{
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
			w, err = c.StagedGlobalNetworkPolicies().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(apiv3.KindStagedGlobalNetworkPolicy, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})
			testWatcher3.Stop()

			By("Configuring StagedGlobalNetworkPolicy name1/spec1 again and storing the response")
			outRes1, err = c.StagedGlobalNetworkPolicies().Create(
				ctx,
				&apiv3.StagedGlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.StagedGlobalNetworkPolicies().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEventsAnyOrder(apiv3.KindStagedGlobalNetworkPolicy, []watch.Event{
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
			testWatcher4.ExpectEvents(apiv3.KindStagedGlobalNetworkPolicy, []watch.Event{
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
