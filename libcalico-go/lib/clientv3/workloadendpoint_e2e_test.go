// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"context"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// These tests are not run on KDD since the WEP resource is not a creatable resource.
var _ = testutils.E2eDatastoreDescribe("WorkloadEndpoint tests", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	namespace1 := "namespace-1"
	namespace2 := "namespace-2"
	name1 := "node--1-k8s-abcdef-eth0"
	name2 := "node--2-cni-a232323a-eth0"
	spec1_1 := libapiv3.WorkloadEndpointSpec{
		Node:          "node-1",
		Orchestrator:  "k8s",
		Pod:           "abcdef",
		ContainerID:   "a12345a",
		Endpoint:      "eth0",
		InterfaceName: "cali09123",
		Ports: []libapiv3.WorkloadEndpointPort{
			{
				Port:     1234,
				Name:     "foobar",
				Protocol: numorstring.ProtocolFromString("TCP"),
			},
			{
				Port:     5432,
				Name:     "bop",
				Protocol: numorstring.ProtocolFromString("TCP"),
			},
		},
	}
	spec1_2 := libapiv3.WorkloadEndpointSpec{
		Node:          "node-1",
		Orchestrator:  "k8s",
		Pod:           "abcdef",
		ContainerID:   "a12345a",
		Endpoint:      "eth0",
		InterfaceName: "foobar",
		Ports: []libapiv3.WorkloadEndpointPort{
			{
				Port:     5678,
				Name:     "bazzbiff",
				Protocol: numorstring.ProtocolFromString("UDP"),
			},
		},
	}
	spec2_1 := libapiv3.WorkloadEndpointSpec{
		Node:          "node-2",
		Orchestrator:  "cni",
		Endpoint:      "eth0",
		ContainerID:   "a232323a",
		InterfaceName: "cali09122",
	}
	spec2_2 := libapiv3.WorkloadEndpointSpec{
		Node:          "node-2",
		Orchestrator:  "cni",
		Endpoint:      "eth0",
		ContainerID:   "a232323a",
		InterfaceName: "caliabcde",
	}

	DescribeTable("WorkloadEndpoint e2e CRUD tests",
		func(namespace1, namespace2, name1, name2 string, spec1_1, spec1_2, spec2_1 libapiv3.WorkloadEndpointSpec) {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Updating the WorkloadEndpoint before it is created")
			_, outError := c.WorkloadEndpoints().Update(ctx, &libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: "test-fail-workload-endpoint"},
				Spec:       spec1_1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: WorkloadEndpoint(" + namespace1 + "/" + name1 + ") with error:"))

			By("Attempting to get a WorkloadEndpoint before it is created")
			_, outError = c.WorkloadEndpoints().Get(ctx, namespace1, name1, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: WorkloadEndpoint(" + namespace1 + "/" + name1 + ") with error:"))

			By("Attempting to create a new WorkloadEndpoint with name1/spec1_1 and a non-empty ResourceVersion")
			_, outError = c.WorkloadEndpoints().Create(ctx, &libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1, ResourceVersion: "12345", CreationTimestamp: metav1.Now(), UID: "test-fail-workload-endpoint"},
				Spec:       spec1_1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Creating a new WorkloadEndpoint with namespace1/name1/spec1_1 - name gets assigned automatically")
			wepToCreate := &libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1},
				Spec:       spec1_1,
			}
			wepToCreateCopy := wepToCreate.DeepCopy()
			res1, outError := c.WorkloadEndpoints().Create(ctx, wepToCreate, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(wepToCreate).To(Equal(wepToCreateCopy), "Create() unexpectedly modified input")
			Expect(res1).To(MatchResource(libapiv3.KindWorkloadEndpoint, namespace1, name1, spec1_1))
			Expect(res1.Labels[apiv3.LabelOrchestrator]).To(Equal(res1.Spec.Orchestrator))
			Expect(res1.Labels[apiv3.LabelNamespace]).To(Equal(res1.Namespace))

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same WorkloadEndpoint with name1 but with spec1_2")
			_, outError = c.WorkloadEndpoints().Create(ctx, &libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1},
				Spec:       spec1_2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: WorkloadEndpoint(" + namespace1 + "/" + name1 + ")"))

			By("Getting WorkloadEndpoint (name1) and comparing the output against spec1_1")
			res, outError := c.WorkloadEndpoints().Get(ctx, namespace1, name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindWorkloadEndpoint, namespace1, name1, spec1_1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))
			Expect(res.Labels[apiv3.LabelOrchestrator]).To(Equal(res.Spec.Orchestrator))
			Expect(res.Labels[apiv3.LabelNamespace]).To(Equal(res.Namespace))

			By("Getting WorkloadEndpoint (name2) before it is created")
			_, outError = c.WorkloadEndpoints().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: WorkloadEndpoint(" + namespace2 + "/" + name2 + ") with error:"))

			By("Listing all the WorkloadEndpoints in namespace1, expecting a single result with name1/spec1_1")
			outList, outError := c.WorkloadEndpoints().List(ctx, options.ListOptions{Namespace: namespace1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindWorkloadEndpoint, namespace1, name1, spec1_1),
			))
			Expect(outList.Items[0].Labels[apiv3.LabelOrchestrator]).To(Equal(outList.Items[0].Spec.Orchestrator))
			Expect(outList.Items[0].Labels[apiv3.LabelNamespace]).To(Equal(outList.Items[0].Namespace))

			By("Creating a new WorkloadEndpoint with name2/spec2_1")
			res2, outError := c.WorkloadEndpoints().Create(ctx, &libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{Name: name2, Namespace: namespace2},
				Spec:       spec2_1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(libapiv3.KindWorkloadEndpoint, namespace2, name2, spec2_1))

			By("Getting WorkloadEndpoint (name2) and comparing the output against spec1_2")
			res, outError = c.WorkloadEndpoints().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindWorkloadEndpoint, namespace2, name2, spec2_1))
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the WorkloadEndpoints using an empty namespace (all-namespaces), expecting a two results with name1/spec1_1 and name2/spec1_2")
			outList, outError = c.WorkloadEndpoints().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindWorkloadEndpoint, namespace1, name1, spec1_1),
				testutils.Resource(libapiv3.KindWorkloadEndpoint, namespace2, name2, spec2_1),
			))

			By("Listing all the WorkloadEndpoints in namespace2, expecting a one results with name2/spec2_1")
			outList, outError = c.WorkloadEndpoints().List(ctx, options.ListOptions{Namespace: namespace2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindWorkloadEndpoint, namespace2, name2, spec2_1),
			))

			By("Updating WorkloadEndpoint name1 with spec1_2")
			res1.Spec = spec1_2
			res1Copy := res1.DeepCopy()
			res1Out, outError := c.WorkloadEndpoints().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(Equal(res1Copy), "Update() unexpectedly modified input")
			res1 = res1Out
			Expect(res1).To(MatchResource(libapiv3.KindWorkloadEndpoint, namespace1, name1, spec1_2))
			Expect(res1.Labels[apiv3.LabelOrchestrator]).To(Equal(res1.Spec.Orchestrator))
			Expect(res1.Labels[apiv3.LabelNamespace]).To(Equal(res1.Namespace))

			By("Attempting to update the WorkloadEndpoint without a Creation Timestamp")
			res, outError = c.WorkloadEndpoints().Update(ctx, &libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1, ResourceVersion: "1234", UID: "test-fail-workload-endpoint"},
				Spec:       spec1_1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the WorkloadEndpoint without a UID")
			res, outError = c.WorkloadEndpoints().Update(ctx, &libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1_1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name1 data.
			rv1_2 := res1.ResourceVersion

			By("Updating BGPPeer name1 without specifying a resource version")
			res1.Spec = spec1_1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.WorkloadEndpoints().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating WorkloadEndpoint name1 using the previous resource version")
			res1.Spec = spec1_1
			res1.ResourceVersion = rv1_1
			_, outError = c.WorkloadEndpoints().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: WorkloadEndpoint(" + namespace1 + "/" + name1 + ")"))

			By("Getting WorkloadEndpoint (name1) with the original resource version and comparing the output against spec1_1")
			res, outError = c.WorkloadEndpoints().Get(ctx, namespace1, name1, options.GetOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindWorkloadEndpoint, namespace1, name1, spec1_1))
			Expect(res.ResourceVersion).To(Equal(rv1_1))

			By("Getting WorkloadEndpoint (name1) with the updated resource version and comparing the output against spec1_2")
			res, outError = c.WorkloadEndpoints().Get(ctx, namespace1, name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindWorkloadEndpoint, namespace1, name1, spec1_2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			By("Listing WorkloadEndpoints with the original resource version and checking for a single result with name1/spec1_1")
			outList, outError = c.WorkloadEndpoints().List(ctx, options.ListOptions{Namespace: namespace1, ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindWorkloadEndpoint, namespace1, name1, spec1_1),
			))

			By("Listing WorkloadEndpoints (all namespaces) with the latest resource version and checking for two results with name1/spec1_2 and name2/spec1_2")
			outList, outError = c.WorkloadEndpoints().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindWorkloadEndpoint, namespace1, name1, spec1_2),
				testutils.Resource(libapiv3.KindWorkloadEndpoint, namespace2, name2, spec2_1),
			))

			By("Deleting WorkloadEndpoint (name1) with the old resource version")
			_, outError = c.WorkloadEndpoints().Delete(ctx, namespace1, name1, options.DeleteOptions{ResourceVersion: rv1_1})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: WorkloadEndpoint(" + namespace1 + "/" + name1 + ")"))

			By("Deleting WorkloadEndpoint (name1) with the new resource version")
			dres, outError := c.WorkloadEndpoints().Delete(ctx, namespace1, name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(libapiv3.KindWorkloadEndpoint, namespace1, name1, spec1_2))
			Expect(dres.Labels[apiv3.LabelOrchestrator]).To(Equal(dres.Spec.Orchestrator))
			Expect(dres.Labels[apiv3.LabelNamespace]).To(Equal(dres.Namespace))

			By("Updating WorkloadEndpoint name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.WorkloadEndpoints().Update(ctx, res2, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)
			_, outError = c.WorkloadEndpoints().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(2 * time.Second)
			_, outError = c.WorkloadEndpoints().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: WorkloadEndpoint(" + namespace2 + "/" + name2 + ") with error:"))

			By("Creating WorkloadEndpoint name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.WorkloadEndpoints().Create(ctx, &libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace2, Name: name2},
				Spec:       spec2_1,
			}, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)
			_, outError = c.WorkloadEndpoints().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(2 * time.Second)
			_, outError = c.WorkloadEndpoints().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: WorkloadEndpoint(" + namespace2 + "/" + name2 + ") with error:"))

			By("Attempting to deleting WorkloadEndpoint (name2) again")
			_, outError = c.WorkloadEndpoints().Delete(ctx, namespace2, name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: WorkloadEndpoint(" + namespace2 + "/" + name2 + ") with error:"))

			By("Listing all WorkloadEndpoints and expecting no items")
			outList, outError = c.WorkloadEndpoints().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting WorkloadEndpoint (name2) and expecting an error")
			_, outError = c.WorkloadEndpoints().Get(ctx, namespace2, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: WorkloadEndpoint(" + namespace2 + "/" + name2 + ") with error:"))
		},

		// Test 1: Pass two fully populated WorkloadEndpointSpecs and expect the series of operations to succeed.
		Entry("Two fully populated WorkloadEndpointSpecs",
			namespace1, namespace2,
			name1, name2,
			spec1_1, spec1_2, spec2_1,
		),
	)

	Describe("WorkloadEndpoint watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing WorkloadEndpoints with the latest resource version and checking for two results with name1/spec1_2 and name2/spec1_2")
			outList, outError := c.WorkloadEndpoints().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a WorkloadEndpoint namespace1/name1/spec1_1 and storing the response")
			outRes1, err := c.WorkloadEndpoints().Create(
				ctx,
				&libapiv3.WorkloadEndpoint{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace1, Name: name1},
					Spec:       spec1_1,
				},
				options.SetOptions{},
			)
			rev1 := outRes1.ResourceVersion
			Expect(err).NotTo(HaveOccurred())

			By("Configuring a WorkloadEndpoint namespace2/name2/spec2_1 and storing the response")
			outRes2, err := c.WorkloadEndpoints().Create(
				ctx,
				&libapiv3.WorkloadEndpoint{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace2, Name: name2},
					Spec:       spec2_1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.WorkloadEndpoints().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.WorkloadEndpoints().Delete(ctx, namespace1, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(libapiv3.KindWorkloadEndpoint, []watch.Event{
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
			w, err = c.WorkloadEndpoints().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.WorkloadEndpoints().Update(
				ctx,
				&libapiv3.WorkloadEndpoint{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec2_2,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(libapiv3.KindWorkloadEndpoint, []watch.Event{
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
				w, err = c.WorkloadEndpoints().Watch(ctx, options.ListOptions{Namespace: namespace1, Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(libapiv3.KindWorkloadEndpoint, []watch.Event{
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
			w, err = c.WorkloadEndpoints().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(libapiv3.KindWorkloadEndpoint, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})
			testWatcher3.Stop()

			By("Starting a watcher at rev0 in namespace1 - expect the events for policy in namespace1")
			w, err = c.WorkloadEndpoints().Watch(ctx, options.ListOptions{Namespace: namespace1, ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEvents(libapiv3.KindWorkloadEndpoint, []watch.Event{
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

	Describe("WorkloadEndpoint prefix list", func() {
		It("should handle prefix lists of workload endpoints", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Creating two WorkloadEndpoint with same namespace, node, orchestrator and overlapping Pod")
			outRes1, err := c.WorkloadEndpoints().Create(
				ctx,
				&libapiv3.WorkloadEndpoint{
					ObjectMeta: metav1.ObjectMeta{Namespace: "namespace1", Name: "node--1-k8s-pod-eth0"},
					Spec: libapiv3.WorkloadEndpointSpec{
						Node:          "node-1",
						Orchestrator:  "k8s",
						Pod:           "pod",
						Endpoint:      "eth0",
						InterfaceName: "cali1234",
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			outRes2, err := c.WorkloadEndpoints().Create(
				ctx,
				&libapiv3.WorkloadEndpoint{
					ObjectMeta: metav1.ObjectMeta{Namespace: "namespace1", Name: "node--1-k8s-pod--1-eth0"},
					Spec: libapiv3.WorkloadEndpointSpec{
						Node:          "node-1",
						Orchestrator:  "k8s",
						Pod:           "pod-1",
						Endpoint:      "eth0",
						InterfaceName: "cali1234",
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Creating a workload in a different namespace, but with a largely overlapping name")
			outRes3, err := c.WorkloadEndpoints().Create(
				ctx,
				&libapiv3.WorkloadEndpoint{
					ObjectMeta: metav1.ObjectMeta{Namespace: "namespace2", Name: "node--1-k8s-pod--2-eth0"},
					Spec: libapiv3.WorkloadEndpointSpec{
						Node:          "node-1",
						Orchestrator:  "k8s",
						Pod:           "pod-2",
						Endpoint:      "eth0",
						InterfaceName: "cali1235",
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Doing an exact get on one of the workload endpoints")
			outList, err := c.WorkloadEndpoints().List(ctx, options.ListOptions{Namespace: "namespace1", Name: "node--1-k8s-pod-eth0"})
			Expect(err).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindWorkloadEndpoint, "namespace1", "node--1-k8s-pod-eth0", outRes1.Spec),
			))

			By("Doing a short prefix get to retrieve both workload endpoints in namespace1")
			outList, err = c.WorkloadEndpoints().List(ctx, options.ListOptions{Namespace: "namespace1", Name: "node--1-k8s-pod-", Prefix: true})
			Expect(err).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindWorkloadEndpoint, "namespace1", "node--1-k8s-pod--1-eth0", outRes2.Spec),
				testutils.Resource(libapiv3.KindWorkloadEndpoint, "namespace1", "node--1-k8s-pod-eth0", outRes1.Spec),
			))

			By("Doing a longer prefix get to retrieve one workload endpoints in namespace1")
			outList, err = c.WorkloadEndpoints().List(ctx, options.ListOptions{Namespace: "namespace1", Name: "node--1-k8s-pod--1", Prefix: true})
			Expect(err).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindWorkloadEndpoint, "namespace1", "node--1-k8s-pod--1-eth0", outRes2.Spec),
			))

			By("Doing a short prefix get with wildcarded namespace to retrieve all workload endpoints")
			outList, err = c.WorkloadEndpoints().List(ctx, options.ListOptions{Name: "node--1-k8s-pod-", Prefix: true})
			Expect(err).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindWorkloadEndpoint, "namespace1", "node--1-k8s-pod--1-eth0", outRes2.Spec),
				testutils.Resource(libapiv3.KindWorkloadEndpoint, "namespace1", "node--1-k8s-pod-eth0", outRes1.Spec),
				testutils.Resource(libapiv3.KindWorkloadEndpoint, "namespace2", "node--1-k8s-pod--2-eth0", outRes3.Spec),
			))

			By("Doing a long prefix get with wildcarded names to retrieve the workload endpoint in namespace2")
			outList, err = c.WorkloadEndpoints().List(ctx, options.ListOptions{Name: "node--1-k8s-pod--2", Prefix: true})
			Expect(err).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindWorkloadEndpoint, "namespace2", "node--1-k8s-pod--2-eth0", outRes3.Spec),
			))

			By("Deleting all endpoints")
			_, err = c.WorkloadEndpoints().Delete(ctx, outRes1.Namespace, outRes1.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = c.WorkloadEndpoints().Delete(ctx, outRes2.Namespace, outRes2.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = c.WorkloadEndpoints().Delete(ctx, outRes3.Namespace, outRes3.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("WorkloadEndpoint names based on primary identifiers in Spec", func() {
		It("should handle prefix lists of workload endpoints", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Creating a workload endpoint with missing ContainerID for CNI")
			_, err = c.WorkloadEndpoints().Create(
				ctx,
				&libapiv3.WorkloadEndpoint{
					ObjectMeta: metav1.ObjectMeta{Namespace: "namespace1", Name: "node--1-cni-container-eth0"},
					Spec: libapiv3.WorkloadEndpointSpec{
						Node:          "node-1",
						Orchestrator:  "cni",
						Pod:           "pod",
						Endpoint:      "eth0",
						InterfaceName: "cali1234",
					},
				},
				options.SetOptions{},
			)
			Expect(err).To(HaveOccurred())

			By("Creating a workload endpoint with missing Workload for arbitrary orchestrator")
			_, err = c.WorkloadEndpoints().Create(
				ctx,
				&libapiv3.WorkloadEndpoint{
					ObjectMeta: metav1.ObjectMeta{Namespace: "namespace1", Name: "node--1-cni-container-eth0"},
					Spec: libapiv3.WorkloadEndpointSpec{
						Node:          "node-1",
						Orchestrator:  "other",
						Pod:           "pod",
						Endpoint:      "eth0",
						ContainerID:   "12345",
						InterfaceName: "cali1234",
					},
				},
				options.SetOptions{},
			)
			Expect(err).To(HaveOccurred())

			By("Creating a workload endpoint with correct name and indices for k8s")
			wep, err := c.WorkloadEndpoints().Create(
				ctx,
				&libapiv3.WorkloadEndpoint{
					ObjectMeta: metav1.ObjectMeta{Namespace: "namespace1", Name: "node--1-k8s-pod-eth0"},
					Spec: libapiv3.WorkloadEndpointSpec{
						Node:          "node-1",
						Orchestrator:  "k8s",
						Pod:           "pod",
						Endpoint:      "eth0",
						ContainerID:   "12345",
						InterfaceName: "cali1234",
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Modifying the k8s WEP to have a different container ID")
			wep.Spec.ContainerID = "abcdef"
			wep, err = c.WorkloadEndpoints().Update(ctx, wep, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Modifying the k8s WEP to have a different pod")
			wep.Spec.Pod = "abcdef"
			_, err = c.WorkloadEndpoints().Update(ctx, wep, options.SetOptions{})
			Expect(err).To(HaveOccurred())
		})
	})
})
