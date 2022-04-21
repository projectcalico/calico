// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"

	"context"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("NetworkPolicy tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	order1 := 99.999
	order2 := 22.222
	namespace1 := "namespace-1"
	namespace2 := "namespace-2"
	name1 := "networkp-1"
	name2 := "networkp-2"
	spec1 := apiv3.NetworkPolicySpec{
		Order:    &order1,
		Ingress:  []apiv3.Rule{testutils.InRule1, testutils.InRule2},
		Egress:   []apiv3.Rule{testutils.EgressRule1, testutils.EgressRule2},
		Selector: "thing == 'value'",
	}
	spec2 := apiv3.NetworkPolicySpec{
		Order:    &order2,
		Ingress:  []apiv3.Rule{testutils.InRule2, testutils.InRule1},
		Egress:   []apiv3.Rule{testutils.EgressRule2, testutils.EgressRule1},
		Selector: "thing2 == 'value2'",
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

	DescribeTable("NetworkPolicy e2e CRUD tests",
		func(namespace1, namespace2, name1, name2 string, spec1, spec2 apiv3.NetworkPolicySpec, types1, types2 []apiv3.PolicyType) {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Updating the NetworkPolicy before it is created")
			rv := "1234"
			_, outError := c.NetworkPolicies().Update(ctx, &apiv3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1, ResourceVersion: rv, CreationTimestamp: metav1.Now(), UID: "test-fail-networkpolicy"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: NetworkPolicy(" + namespace1 + "/default." + name1 + ") with error:"))

			By("Attempting to creating a new NetworkPolicy with name1/spec1 and a non-empty ResourceVersion")
			_, outError = c.NetworkPolicies().Create(ctx, &apiv3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: rv},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '" + rv + "' (field must not be set for a Create request)"))

			By("Creating a new NetworkPolicy with namespace1/name1/spec1")
			res1, outError := c.NetworkPolicies().Create(ctx, &apiv3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			spec1.Types = types1
			Expect(res1).To(MatchResource(apiv3.KindNetworkPolicy, namespace1, name1, spec1))

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same NetworkPolicy with name1 but with spec2")
			_, outError = c.NetworkPolicies().Create(ctx, &apiv3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: NetworkPolicy(" + namespace1 + "/default." + name1 + ")"))

			By("Getting NetworkPolicy (name1) and comparing the output against spec1")
			res, outError := c.NetworkPolicies().Get(ctx, namespace1, name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindNetworkPolicy, namespace1, name1, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Getting NetworkPolicy (name2) before it is created")
			_, outError = c.NetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: NetworkPolicy(" + namespace2 + "/default." + name2 + ") with error:"))

			By("Listing all the NetworkPolicies in namespace1, expecting a single result with name1/spec1")
			outList, outError := c.NetworkPolicies().List(ctx, options.ListOptions{Namespace: namespace1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindNetworkPolicy, namespace1, name1, spec1),
			))

			By("Creating a new NetworkPolicy with name2/spec2")
			res2, outError := c.NetworkPolicies().Create(ctx, &apiv3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace2, Name: name2},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			spec2.Types = types2
			Expect(res2).To(MatchResource(apiv3.KindNetworkPolicy, namespace2, name2, spec2))

			By("Getting NetworkPolicy (name2) and comparing the output against spec2")
			res, outError = c.NetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindNetworkPolicy, namespace2, name2, spec2))
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the NetworkPolicies using an empty namespace (all-namespaces), expecting a two results with name1/spec1 and name2/spec2")
			outList, outError = c.NetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindNetworkPolicy, namespace1, name1, spec1),
				testutils.Resource(apiv3.KindNetworkPolicy, namespace2, name2, spec2),
			))

			By("Listing all the NetworkPolicies in namespace2, expecting a one results with name2/spec2")
			outList, outError = c.NetworkPolicies().List(ctx, options.ListOptions{Namespace: namespace2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindNetworkPolicy, namespace2, name2, spec2),
			))

			By("Updating NetworkPolicy name1 with spec2")
			res1.Spec = spec2
			res1, outError = c.NetworkPolicies().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindNetworkPolicy, namespace1, name1, spec2))

			By("Attempting to update the NetworkPolicy without a Creation Timestamp")
			res, outError = c.NetworkPolicies().Update(ctx, &apiv3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1, ResourceVersion: rv, UID: "test-fail-networkpolicy"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the NetworkPolicy without a UID")
			res, outError = c.NetworkPolicies().Update(ctx, &apiv3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1, ResourceVersion: rv, CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name1 data.
			rv1_2 := res1.ResourceVersion

			By("Updating NetworkPolicy name1 without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.NetworkPolicies().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating NetworkPolicy name1 using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			_, outError = c.NetworkPolicies().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: NetworkPolicy(" + namespace1 + "/default." + name1 + ")"))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Getting NetworkPolicy (name1) with the original resource version and comparing the output against spec1")
				res, outError = c.NetworkPolicies().Get(ctx, namespace1, name1, options.GetOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(res).To(MatchResource(apiv3.KindNetworkPolicy, namespace1, name1, spec1))
				Expect(res.ResourceVersion).To(Equal(rv1_1))
			}

			By("Getting NetworkPolicy (name1) with the updated resource version and comparing the output against spec2")
			res, outError = c.NetworkPolicies().Get(ctx, namespace1, name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindNetworkPolicy, namespace1, name1, spec2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Listing NetworkPolicies with the original resource version and checking for a single result with name1/spec1")
				outList, outError = c.NetworkPolicies().List(ctx, options.ListOptions{Namespace: namespace1, ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(outList.Items).To(ConsistOf(
					testutils.Resource(apiv3.KindNetworkPolicy, namespace1, name1, spec1),
				))
			}

			By("Listing NetworkPolicies (all namespaces) with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError = c.NetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindNetworkPolicy, namespace1, name1, spec2),
				testutils.Resource(apiv3.KindNetworkPolicy, namespace2, name2, spec2),
			))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Deleting NetworkPolicy (name1) with the old resource version")
				_, outError = c.NetworkPolicies().Delete(ctx, namespace1, name1, options.DeleteOptions{ResourceVersion: rv1_1})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal("update conflict: NetworkPolicy(" + namespace1 + "/default." + name1 + ")"))
			}

			By("Deleting NetworkPolicy (name1) with the new resource version")
			dres, outError := c.NetworkPolicies().Delete(ctx, namespace1, name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(apiv3.KindNetworkPolicy, namespace1, name1, spec2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Updating NetworkPolicy name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.NetworkPolicies().Update(ctx, res2, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
				_, outError = c.NetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(2 * time.Second)
				_, outError = c.NetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(ContainSubstring("resource does not exist: NetworkPolicy(" + namespace2 + "/default." + name2 + ") with error:"))

				By("Creating NetworkPolicy name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.NetworkPolicies().Create(ctx, &apiv3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace2, Name: name2},
					Spec:       spec2,
				}, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
				_, outError = c.NetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(2 * time.Second)
				_, outError = c.NetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(ContainSubstring("resource does not exist: NetworkPolicy(" + namespace2 + "/default." + name2 + ") with error:"))
			}

			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				By("Attempting to deleting NetworkPolicy (name2) again")
				dres, outError = c.NetworkPolicies().Delete(ctx, namespace2, name2, options.DeleteOptions{})
				Expect(outError).NotTo(HaveOccurred())
				Expect(dres).To(MatchResource(apiv3.KindNetworkPolicy, namespace2, name2, spec2))
			}

			By("Attempting to delete NetworkPolicy (name2) again")
			_, outError = c.NetworkPolicies().Delete(ctx, namespace2, name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: NetworkPolicy(" + namespace2 + "/default." + name2 + ") with error:"))

			By("Listing all NetworkPolicies and expecting no items")
			outList, outError = c.NetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting NetworkPolicy (name2) and expecting an error")
			_, outError = c.NetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: NetworkPolicy(" + namespace2 + "/default." + name2 + ") with error:"))
		},

		// Pass two fully populated PolicySpecs and expect the series of operations to succeed.
		Entry("Two fully populated PolicySpecs",
			namespace1, namespace2,
			name1, name2,
			spec1, spec2,
			ingressEgress, ingressEgress,
		),
		// Check defaulting for policies with ingress rules and egress rules only.
		Entry("Ingress-only and egress-only policies",
			namespace1, namespace2,
			name1, name2,
			ingressSpec1, egressSpec2,
			ingress, egress,
		),
		// Check non-defaulting for policies with explicit Types value.
		Entry("Policies with explicit ingress and egress Types",
			namespace1, namespace2,
			name1, name2,
			ingressTypesSpec1, egressTypesSpec2,
			ingress, egress,
		),
	)

	Describe("NetworkPolicy watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing NetworkPolicies with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError := c.NetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a NetworkPolicy namespace1/name1/spec1 and storing the response")
			outRes1, err := c.NetworkPolicies().Create(
				ctx,
				&apiv3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			rev1 := outRes1.ResourceVersion

			By("Configuring a NetworkPolicy namespace2/name2/spec2 and storing the response")
			outRes2, err := c.NetworkPolicies().Create(
				ctx,
				&apiv3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace2, Name: name2},
					Spec:       spec2,
				},
				options.SetOptions{},
			)

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.NetworkPolicies().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.NetworkPolicies().Delete(ctx, namespace1, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(apiv3.KindNetworkPolicy, []watch.Event{
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
			w, err = c.NetworkPolicies().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.NetworkPolicies().Update(
				ctx,
				&apiv3.NetworkPolicy{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindNetworkPolicy, []watch.Event{
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
				By("Starting a watcher from rev0 watching namespace1/name1 - this should get all events for name1")
				w, err = c.NetworkPolicies().Watch(ctx, options.ListOptions{Namespace: namespace1, Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(apiv3.KindNetworkPolicy, []watch.Event{
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

				By("Starting a watcher from rev0 watching name1 - this should get all events for name1")
				w, err = c.NetworkPolicies().Watch(ctx, options.ListOptions{Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_2.Stop()
				testWatcher2_2.ExpectEvents(apiv3.KindNetworkPolicy, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: outRes1,
					},
				})
				testWatcher2_2.Stop()
			}

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.NetworkPolicies().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(apiv3.KindNetworkPolicy, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})
			testWatcher3.Stop()

			By("Starting a watcher at rev0 in namespace1 - expect the events for policy in namespace1")
			w, err = c.NetworkPolicies().Watch(ctx, options.ListOptions{Namespace: namespace1, ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEvents(apiv3.KindNetworkPolicy, []watch.Event{
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

	// These tests check that the names we use on the API properly round-trip.  In particular,
	// k8s and OpenStack policies have special prefixes, which should be preserved.  Other
	// names get stored with a prefix, for consistency but the API returns them without the
	// prefix.
	nameNormalizationTests := []TableEntry{
		// OpenStack names should round-trip, including their prefix.
		Entry("OpenStack policy", "ossg.default.group1", "ossg.default.group1"),
		// As should normal names.
		Entry("OpenStack policy", "foo-bar", "default.foo-bar"),
	}
	if config.Spec.DatastoreType != "kubernetes" {
		// Only test writing a knp-prefixed policy if we're not backed by KDD.  In KDD,
		// the knp-prefixed policies are derived from k8s data so it doesn't make sense
		// to write them through our API.
		knpName := "knp.default.a-name"
		nameNormalizationTests = append(nameNormalizationTests,
			Entry("KDD policy", knpName, knpName),
		)
	}
	DescribeTable("name round-tripping tests",
		func(name, backendName string) {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Attempting to creating a new NetworkPolicy with name: " + name)
			inNp := &apiv3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name},
				Spec:       ingressTypesSpec1,
			}
			np, outError := c.NetworkPolicies().Create(ctx, inNp, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(inNp.GetName()).To(Equal(name), "Create() shouldn't touch input data")
			Expect(np.GetName()).To(Equal(name), "Create() should return the data as we'd read it")

			By("Reading back the raw data with its normalized name: " + backendName)
			// Make sure that, where the name and the storage name differ, we do the write with
			// the storage name.  Then the assertions below verify that all the CRUD methods
			// do the right conversion too.
			kv, err := be.Get(ctx, model.ResourceKey{
				Kind:      apiv3.KindNetworkPolicy,
				Namespace: namespace1,
				Name:      backendName,
			}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(kv.Value.(*apiv3.NetworkPolicy).Spec).To(Equal(ingressTypesSpec1))

			By("Getting the right policy by name")
			np, err = c.NetworkPolicies().Get(ctx, namespace1, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(np.GetName()).To(Equal(name))
			Expect(np.Spec).To(Equal(ingressTypesSpec1))

			By("Updating the policy")
			np.Spec = egressTypesSpec2
			np, err = c.NetworkPolicies().Update(ctx, np, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Getting the right policy")
			np, err = c.NetworkPolicies().Get(ctx, namespace1, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(np.GetName()).To(Equal(name))
			Expect(np.Spec).To(Equal(egressTypesSpec2))

			By("Listing the policy with correct name (no query options)")
			nps, err := c.NetworkPolicies().List(ctx, options.ListOptions{Namespace: namespace1})
			Expect(err).NotTo(HaveOccurred())
			var names []string
			for _, np := range nps.Items {
				names = append(names, np.GetName())
			}
			Expect(names).To(ContainElement(name))
			if name != name {
				Expect(names).NotTo(ContainElement(name))
			}

			By("Listing the policy with correct name (list by name)")
			nps, err = c.NetworkPolicies().List(ctx,
				options.ListOptions{Namespace: namespace1, Name: name})
			Expect(err).NotTo(HaveOccurred())
			names = nil
			for _, np := range nps.Items {
				names = append(names, np.GetName())
			}
			Expect(names).To(ConsistOf(name))

			By("Deleting the policy via the name")
			np, err = c.NetworkPolicies().Delete(ctx, namespace1, name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			if np != nil {
				Expect(np.GetName()).To(Equal(name))
			}
		},
		nameNormalizationTests...,
	)
})
