// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

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
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var (
	k8sIngressEgress = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}
	k8sIngress       = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	k8sEgress        = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
)

var _ = testutils.E2eDatastoreDescribe("StagedKubernetesNetworkPolicy tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	namespace1 := "namespace-1"
	namespace2 := "namespace-2"
	name1 := "networkp-1"
	name2 := "networkp-2"

	port80 := intstr.FromInt(80)
	port443 := intstr.FromInt(443)

	ingress1 := networkingv1.NetworkPolicyIngressRule{
		Ports: []networkingv1.NetworkPolicyPort{
			{Port: &port80},
		},
		From: []networkingv1.NetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"k":  "v",
						"k2": "v2",
					},
				},
			},
		},
	}

	ingress2 := networkingv1.NetworkPolicyIngressRule{
		Ports: []networkingv1.NetworkPolicyPort{
			{Port: &port443},
		},
		From: []networkingv1.NetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"k2": "v2",
						"k":  "v",
					},
				},
			},
		},
	}

	egress1 := networkingv1.NetworkPolicyEgressRule{
		Ports: []networkingv1.NetworkPolicyPort{
			{Port: &port80},
		},
		To: []networkingv1.NetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"k":  "v",
						"k2": "v2",
					},
				},
			},
		},
	}

	egress2 := networkingv1.NetworkPolicyEgressRule{
		Ports: []networkingv1.NetworkPolicyPort{
			{Port: &port443},
		},
		To: []networkingv1.NetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"k2": "v2",
						"k":  "v",
					},
				},
			},
		},
	}

	spec1 := apiv3.StagedKubernetesNetworkPolicySpec{
		StagedAction: v3.StagedActionSet,
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"label":  "value",
				"label2": "value2",
			},
		},
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			ingress1, ingress2,
		},
		Egress: []networkingv1.NetworkPolicyEgressRule{
			egress1, egress2,
		},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
	}

	spec2 := apiv3.StagedKubernetesNetworkPolicySpec{
		StagedAction: v3.StagedActionSet,
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"label":  "value",
				"label2": "value2",
			},
		},
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			ingress2, ingress1,
		},
		Egress: []networkingv1.NetworkPolicyEgressRule{
			egress2, egress1,
		},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
	}

	// Specs with only ingress or egress rules, without Types set.
	ingressSpec1 := spec1
	ingressSpec1.Egress = nil
	egressSpec2 := spec2
	egressSpec2.Ingress = nil
	// Specs with ingress and egress rules, with Types set to just ingress or egress.
	ingressTypesSpec1 := spec1
	ingressTypesSpec1.PolicyTypes = k8sIngress
	egressTypesSpec2 := spec2
	egressTypesSpec2.PolicyTypes = k8sEgress

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

	DescribeTable("StagedKubernetesNetworkPolicy e2e CRUD tests",
		func(tier, namespace1, namespace2, name1, name2 string, spec1, spec2 apiv3.StagedKubernetesNetworkPolicySpec, types1, types2 []networkingv1.PolicyType) {
			By("Updating the StagedKubernetesNetworkPolicy before it is created")
			rv := "1234"

			_, outError := c.StagedKubernetesNetworkPolicies().Update(ctx, &apiv3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1, ResourceVersion: rv, CreationTimestamp: metav1.Now(), UID: uid},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: StagedKubernetesNetworkPolicy(" + namespace1 + "/" + name1 + ") with error:"))

			By("Attempting to creating a new StagedKubernetesNetworkPolicy with name1/spec1 and a non-empty ResourceVersion")
			_, outError = c.StagedKubernetesNetworkPolicies().Create(ctx, &apiv3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: rv},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '" + rv + "' (field must not be set for a Create request)"))

			By("Creating a new StagedKubernetesNetworkPolicy with namespace1/name1/spec1")
			spec1.PolicyTypes = types1
			res1, outError := c.StagedKubernetesNetworkPolicies().Create(ctx, &apiv3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindStagedKubernetesNetworkPolicy, namespace1, name1, spec1))

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same StagedKubernetesNetworkPolicy with name1 but with spec2")
			_, outError = c.StagedKubernetesNetworkPolicies().Create(ctx, &apiv3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: StagedKubernetesNetworkPolicy(" + namespace1 + "/" + name1 + ")"))

			By("Getting StagedKubernetesNetworkPolicy (name1) and comparing the output against spec1")
			res, outError := c.StagedKubernetesNetworkPolicies().Get(ctx, namespace1, name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindStagedKubernetesNetworkPolicy, namespace1, name1, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Getting StagedKubernetesNetworkPolicy (name2) before it is created")
			_, outError = c.StagedKubernetesNetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: StagedKubernetesNetworkPolicy(" + namespace2 + "/" + name2 + ") with error:"))

			By("Listing all the NetworkPolicies in namespace1, expecting a single result with name1/spec1")
			outList, outError := c.StagedKubernetesNetworkPolicies().List(ctx, options.ListOptions{Namespace: namespace1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindStagedKubernetesNetworkPolicy, namespace1, name1, spec1),
			))

			By("Creating a new StagedKubernetesNetworkPolicy with name2/spec2")
			spec2.PolicyTypes = types2
			res2, outError := c.StagedKubernetesNetworkPolicies().Create(ctx, &apiv3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace2, Name: name2},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(apiv3.KindStagedKubernetesNetworkPolicy, namespace2, name2, spec2))

			By("Getting StagedKubernetesNetworkPolicy (name2) and comparing the output against spec2")
			res, outError = c.StagedKubernetesNetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindStagedKubernetesNetworkPolicy, namespace2, name2, spec2))
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the NetworkPolicies using an empty namespace (all-namespaces), expecting a two results with name1/spec1 and name2/spec2")
			outList, outError = c.StagedKubernetesNetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindStagedKubernetesNetworkPolicy, namespace1, name1, spec1),
				testutils.Resource(apiv3.KindStagedKubernetesNetworkPolicy, namespace2, name2, spec2),
			))

			By("Listing all the NetworkPolicies in namespace2, expecting a one results with name2/spec2")
			outList, outError = c.StagedKubernetesNetworkPolicies().List(ctx, options.ListOptions{Namespace: namespace2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindStagedKubernetesNetworkPolicy, namespace2, name2, spec2),
			))

			By("Updating StagedKubernetesNetworkPolicy name1 with spec2")
			res1.Spec = spec2
			res1, outError = c.StagedKubernetesNetworkPolicies().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindStagedKubernetesNetworkPolicy, namespace1, name1, spec2))

			By("Attempting to update the StagedKubernetesNetworkPolicy without a Creation Timestamp")
			res, outError = c.StagedKubernetesNetworkPolicies().Update(ctx, &apiv3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1, ResourceVersion: rv, UID: uid},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the StagedKubernetesNetworkPolicy without a UID")
			res, outError = c.StagedKubernetesNetworkPolicies().Update(ctx, &apiv3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1, ResourceVersion: rv, CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name1 data.
			rv1_2 := res1.ResourceVersion

			By("Updating StagedKubernetesNetworkPolicy name1 without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.StagedKubernetesNetworkPolicies().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating StagedKubernetesNetworkPolicy name1 using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			_, outError = c.StagedKubernetesNetworkPolicies().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: StagedKubernetesNetworkPolicy(" + namespace1 + "/" + name1 + ")"))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Getting StagedKubernetesNetworkPolicy (name1) with the original resource version and comparing the output against spec1")
				res, outError = c.StagedKubernetesNetworkPolicies().Get(ctx, namespace1, name1, options.GetOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(res).To(MatchResource(apiv3.KindStagedKubernetesNetworkPolicy, namespace1, name1, spec1))
				Expect(res.ResourceVersion).To(Equal(rv1_1))
			}

			By("Getting StagedKubernetesNetworkPolicy (name1) with the updated resource version and comparing the output against spec2")
			res, outError = c.StagedKubernetesNetworkPolicies().Get(ctx, namespace1, name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindStagedKubernetesNetworkPolicy, namespace1, name1, spec2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Listing NetworkPolicies with the original resource version and checking for a single result with name1/spec1")
				outList, outError = c.StagedKubernetesNetworkPolicies().List(ctx, options.ListOptions{Namespace: namespace1, ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(outList.Items).To(ConsistOf(
					testutils.Resource(apiv3.KindStagedKubernetesNetworkPolicy, namespace1, name1, spec1),
				))
			}

			By("Listing NetworkPolicies (all namespaces) with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError = c.StagedKubernetesNetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindStagedKubernetesNetworkPolicy, namespace1, name1, spec2),
				testutils.Resource(apiv3.KindStagedKubernetesNetworkPolicy, namespace2, name2, spec2),
			))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Deleting StagedKubernetesNetworkPolicy (name1) with the old resource version")
				_, outError = c.StagedKubernetesNetworkPolicies().Delete(ctx, namespace1, name1, options.DeleteOptions{ResourceVersion: rv1_1})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal("update conflict: StagedKubernetesNetworkPolicy(" + namespace1 + "/" + name1 + ")"))
			}

			By("Deleting StagedKubernetesNetworkPolicy (name1) with the new resource version")
			dres, outError := c.StagedKubernetesNetworkPolicies().Delete(ctx, namespace1, name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(apiv3.KindStagedKubernetesNetworkPolicy, namespace1, name1, spec2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Updating StagedKubernetesNetworkPolicy name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.StagedKubernetesNetworkPolicies().Update(ctx, res2, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
				_, outError = c.StagedKubernetesNetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(2 * time.Second)
				_, outError = c.StagedKubernetesNetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(ContainSubstring("resource does not exist: StagedKubernetesNetworkPolicy(" + namespace2 + "/" + name2 + ") with error:"))

				By("Creating StagedKubernetesNetworkPolicy name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.StagedKubernetesNetworkPolicies().Create(ctx, &apiv3.StagedKubernetesNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace2, Name: name2},
					Spec:       spec2,
				}, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
				_, outError = c.StagedKubernetesNetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(2 * time.Second)
				_, outError = c.StagedKubernetesNetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(ContainSubstring("resource does not exist: StagedKubernetesNetworkPolicy(" + namespace2 + "/" + name2 + ") with error:"))
			}

			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				By("Attempting to deleting StagedKubernetesNetworkPolicy (name2) again")
				dres, outError = c.StagedKubernetesNetworkPolicies().Delete(ctx, namespace2, name2, options.DeleteOptions{})
				Expect(outError).NotTo(HaveOccurred())
				Expect(dres).To(MatchResource(apiv3.KindStagedKubernetesNetworkPolicy, namespace2, name2, spec2))
			}

			By("Attempting to delete StagedKubernetesNetworkPolicy (name2) again")
			_, outError = c.StagedKubernetesNetworkPolicies().Delete(ctx, namespace2, name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: StagedKubernetesNetworkPolicy(" + namespace2 + "/" + name2 + ") with error:"))

			By("Listing all NetworkPolicies and expecting no items")
			outList, outError = c.StagedKubernetesNetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting StagedKubernetesNetworkPolicy (name2) and expecting an error")
			_, outError = c.StagedKubernetesNetworkPolicies().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: StagedKubernetesNetworkPolicy(" + namespace2 + "/" + name2 + ") with error:"))
		},

		// Pass two fully populated PolicySpecs and expect the series of operations to succeed.
		Entry("Two fully populated PolicySpecs in the default tier",
			"default",
			namespace1, namespace2,
			name1, name2,
			spec1, spec2,
			k8sIngressEgress, k8sIngressEgress,
		),
		// Check defaulting for policies with ingress rules and egress rules only.
		Entry("Ingress-only and egress-only policies",
			"default",
			namespace1, namespace2,
			name1, name2,
			ingressSpec1, egressSpec2,
			k8sIngress, k8sEgress,
		),
		// Check non-defaulting for policies with explicit Types value.
		Entry("Policies with explicit ingress and egress Types",
			"default",
			namespace1, namespace2,
			name1, name2,
			ingressTypesSpec1, egressTypesSpec2,
			k8sIngress, k8sEgress,
		),
	)

	Describe("StagedKubernetesNetworkPolicy watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			By("Listing NetworkPolicies with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError := c.StagedKubernetesNetworkPolicies().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a StagedKubernetesNetworkPolicy namespace1/name1/spec1 and storing the response")
			outRes1, err := c.StagedKubernetesNetworkPolicies().Create(
				ctx,
				&apiv3.StagedKubernetesNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			rev1 := outRes1.ResourceVersion

			By("Configuring a StagedKubernetesNetworkPolicy namespace2/name2/spec2 and storing the response")
			outRes2, err := c.StagedKubernetesNetworkPolicies().Create(
				ctx,
				&apiv3.StagedKubernetesNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace2, Name: name2},
					Spec:       spec2,
				},
				options.SetOptions{},
			)

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.StagedKubernetesNetworkPolicies().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.StagedKubernetesNetworkPolicies().Delete(ctx, namespace1, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(apiv3.KindStagedKubernetesNetworkPolicy, []watch.Event{
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
			w, err = c.StagedKubernetesNetworkPolicies().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			// Revert back to client input
			By("Modifying res2")
			outRes3, err := c.StagedKubernetesNetworkPolicies().Update(
				ctx,
				&apiv3.StagedKubernetesNetworkPolicy{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindStagedKubernetesNetworkPolicy, []watch.Event{
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
				w, err = c.StagedKubernetesNetworkPolicies().Watch(ctx, options.ListOptions{Namespace: namespace1, Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(apiv3.KindStagedKubernetesNetworkPolicy, []watch.Event{
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
				w, err = c.StagedKubernetesNetworkPolicies().Watch(ctx, options.ListOptions{Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_2.Stop()
				testWatcher2_2.ExpectEvents(apiv3.KindStagedKubernetesNetworkPolicy, []watch.Event{
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
			w, err = c.StagedKubernetesNetworkPolicies().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(apiv3.KindStagedKubernetesNetworkPolicy, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})
			testWatcher3.Stop()

			By("Starting a watcher at rev0 in namespace1 - expect the events for policy in namespace1")
			w, err = c.StagedKubernetesNetworkPolicies().Watch(ctx, options.ListOptions{Namespace: namespace1, ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEvents(apiv3.KindStagedKubernetesNetworkPolicy, []watch.Event{
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
		Entry("OpenStack policy", "ossg.default.group1", "ossg.default.group1", "default"),
		// As should normal names.
		Entry("OpenStack policy", "default.foo-bar", "default.foo-bar", "default"),
	}
	if config.Spec.DatastoreType != "kubernetes" {
		// Only test writing a knp-prefixed policy if we're not backed by KDD.  In KDD,
		// the knp-prefixed policies are derived from k8s data so it doesn't make sense
		// to write them through our API.
		knpName := "knp.default.a-name"
		nameNormalizationTests = append(nameNormalizationTests,
			Entry("KDD policy", knpName, knpName, "default"),
		)
	}
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
	DescribeTable("name round-tripping tests",
		func(name, backendName, tierName string) {
			tieredIngressTypesSpec1 := ingressTypesSpec1
			tieredEgressTypesSpec2 := egressTypesSpec2

			By("Attempting to creating a new StagedKubernetesNetworkPolicy with name: " + name)
			inNp := &apiv3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name},
				Spec:       tieredIngressTypesSpec1,
			}
			np, outError := c.StagedKubernetesNetworkPolicies().Create(ctx, inNp, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(inNp.GetName()).To(Equal(name), "Create() shouldn't touch input data")
			Expect(np.GetName()).To(Equal(name), "Create() should return the data as we'd read it")

			By("Reading back the raw data with its normalized name: " + backendName)
			// Make sure that, where the name and the storage name differ, we do the write with
			// the storage name.  Then the assertions below verify that all the CRUD methods
			// do the right conversion too.
			kv, err := be.Get(ctx, model.ResourceKey{
				Kind:      apiv3.KindStagedKubernetesNetworkPolicy,
				Namespace: namespace1,
				Name:      backendName,
			}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(kv.Value.(*apiv3.StagedKubernetesNetworkPolicy).Spec).To(Equal(tieredIngressTypesSpec1))

			By("Getting the right policy by name")
			np, err = c.StagedKubernetesNetworkPolicies().Get(ctx, namespace1, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(np.GetName()).To(Equal(name))
			Expect(np.Spec).To(Equal(tieredIngressTypesSpec1))

			By("Updating the policy")
			np.Spec = tieredEgressTypesSpec2
			np, err = c.StagedKubernetesNetworkPolicies().Update(ctx, np, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Getting the right policy")
			np, err = c.StagedKubernetesNetworkPolicies().Get(ctx, namespace1, name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(np.GetName()).To(Equal(name))
			Expect(np.Spec).To(Equal(tieredEgressTypesSpec2))

			By("Listing the policy with correct name (no query options)")
			nps, err := c.StagedKubernetesNetworkPolicies().List(ctx, options.ListOptions{Namespace: namespace1})
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
			nps, err = c.StagedKubernetesNetworkPolicies().List(ctx,
				options.ListOptions{Namespace: namespace1, Name: name})
			Expect(err).NotTo(HaveOccurred())
			names = nil
			for _, np := range nps.Items {
				names = append(names, np.GetName())
			}
			Expect(names).To(ConsistOf(name))

			By("Deleting the policy via the name")
			np, err = c.StagedKubernetesNetworkPolicies().Delete(ctx, namespace1, name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			if np != nil {
				Expect(np.GetName()).To(Equal(name))
			}
		},
		nameNormalizationTests...,
	)
})
