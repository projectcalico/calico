// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo/v2"
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

var _ = testutils.E2eDatastoreDescribe("KubeControllersConfiguration tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	name := "default"
	port := 9094
	spec1 := apiv3.KubeControllersConfigurationSpec{
		HealthChecks:          apiv3.Enabled,
		PrometheusMetricsPort: &port,
		Controllers: apiv3.ControllersConfig{
			Node: &apiv3.NodeControllerConfig{
				ReconcilerPeriod: &metav1.Duration{Duration: time.Second * 330},
				SyncLabels:       apiv3.Enabled,
				HostEndpoint:     nil,
			},
			Policy:           nil,
			WorkloadEndpoint: nil,
			ServiceAccount:   nil,
			Namespace:        nil,
		},
	}
	spec2 := apiv3.KubeControllersConfigurationSpec{
		HealthChecks:          apiv3.Disabled,
		PrometheusMetricsPort: &port,
		Controllers: apiv3.ControllersConfig{
			Node: &apiv3.NodeControllerConfig{
				ReconcilerPeriod: &metav1.Duration{Duration: time.Second * 330},
				SyncLabels:       apiv3.Enabled,
				HostEndpoint: &apiv3.AutoHostEndpointConfig{
					AutoCreate: apiv3.Enabled,
				},
			},
			Policy:           &apiv3.PolicyControllerConfig{ReconcilerPeriod: &metav1.Duration{Duration: time.Minute * 3}},
			WorkloadEndpoint: &apiv3.WorkloadEndpointControllerConfig{ReconcilerPeriod: &metav1.Duration{Duration: time.Minute * 4}},
			ServiceAccount:   &apiv3.ServiceAccountControllerConfig{ReconcilerPeriod: &metav1.Duration{Duration: time.Minute * 5}},
			Namespace:        &apiv3.NamespaceControllerConfig{ReconcilerPeriod: &metav1.Duration{Duration: time.Minute * 6}},
		},
	}
	status1 := apiv3.KubeControllersConfigurationStatus{
		RunningConfig: apiv3.KubeControllersConfigurationSpec{
			LogSeverityScreen: "Debug",
			HealthChecks:      apiv3.Enabled,
			Controllers: apiv3.ControllersConfig{
				Node: &apiv3.NodeControllerConfig{
					ReconcilerPeriod: &metav1.Duration{Duration: time.Second * 330},
					SyncLabels:       apiv3.Enabled,
					HostEndpoint:     nil,
				},
				Policy:           nil,
				WorkloadEndpoint: nil,
				ServiceAccount:   nil,
				Namespace:        nil,
			},
		},
		EnvironmentVars: map[string]string{
			"LOG_LEVEL":     "Debug",
			"HEALTHENABLED": "true",
		},
	}
	status2 := apiv3.KubeControllersConfigurationStatus{
		RunningConfig: apiv3.KubeControllersConfigurationSpec{
			HealthChecks: apiv3.Disabled,
			Controllers: apiv3.ControllersConfig{
				Node: &apiv3.NodeControllerConfig{
					ReconcilerPeriod: &metav1.Duration{Duration: time.Second * 330},
					SyncLabels:       apiv3.Enabled,
					HostEndpoint: &apiv3.AutoHostEndpointConfig{
						AutoCreate: apiv3.Enabled,
					},
				},
				Policy:           &apiv3.PolicyControllerConfig{ReconcilerPeriod: &metav1.Duration{Duration: time.Minute * 3}},
				WorkloadEndpoint: &apiv3.WorkloadEndpointControllerConfig{ReconcilerPeriod: &metav1.Duration{Duration: time.Minute * 4}},
				ServiceAccount:   &apiv3.ServiceAccountControllerConfig{ReconcilerPeriod: &metav1.Duration{Duration: time.Minute * 5}},
				Namespace:        &apiv3.NamespaceControllerConfig{ReconcilerPeriod: &metav1.Duration{Duration: time.Minute * 6}},
			},
		},
		EnvironmentVars: map[string]string{
			"LOG_LEVEL":     "Info",
			"HEALTHENABLED": "false",
		},
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

	DescribeTable("KubeControllersConfiguration e2e CRUD tests",
		func(name string, spec1, spec2 apiv3.KubeControllersConfigurationSpec, status1, status2 apiv3.KubeControllersConfigurationStatus) {
			By("Updating the KubeControllersConfiguration before it is created")
			_, outError := c.KubeControllersConfiguration().Update(ctx, &apiv3.KubeControllersConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: "test-fail-kubecontrollersconfig"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: KubeControllersConfiguration(" + name + ") with error:"))

			By("Attempting to creating a new KubeControllersConfiguration with spec1 and a non-empty ResourceVersion")
			_, outError = c.KubeControllersConfiguration().Create(ctx, &apiv3.KubeControllersConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Getting KubeControllersConfiguration before it is created")
			_, outError = c.KubeControllersConfiguration().Get(ctx, name, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: KubeControllersConfiguration(" + name + ") with error:"))

			By("Attempting to create a new KubeControllersConfiguration with a non-default name and spec1")
			_, outError = c.KubeControllersConfiguration().Create(ctx, &apiv3.KubeControllersConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "not-default"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("Cannot create a Kube Controllers Configuration resource with a name other than \"default\""))

			By("Creating a new KubeControllersConfiguration with spec1")
			res1, outError := c.KubeControllersConfiguration().Create(ctx, &apiv3.KubeControllersConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec1))

			// Track the version of the original data for name.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same KubeControllersConfiguration but with spec2")
			_, outError = c.KubeControllersConfiguration().Create(ctx, &apiv3.KubeControllersConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: KubeControllersConfiguration(" + name + ")"))

			By("Getting KubeControllersConfiguration and comparing the output against spec1")
			res, outError := c.KubeControllersConfiguration().Get(ctx, name, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Listing all the KubeControllersConfiguration, expecting a single result with spec1")
			outList, outError := c.KubeControllersConfiguration().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec1),
			))

			By("Updating KubeControllersConfiguration with spec2")
			res1.Spec = spec2
			res1, outError = c.KubeControllersConfiguration().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec2))

			By("Attempting to update the KubeControllersConfiguration without a Creation Timestamp")
			res, outError = c.KubeControllersConfiguration().Update(ctx, &apiv3.KubeControllersConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", UID: "test-fail-kubecontrollersconfig"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the KubeControllersConfiguration without a UID")
			res, outError = c.KubeControllersConfiguration().Update(ctx, &apiv3.KubeControllersConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name data.
			rv1_2 := res1.ResourceVersion

			By("Updating KubeControllersConfiguration without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.KubeControllersConfiguration().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating KubeControllersConfiguration using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			_, outError = c.KubeControllersConfiguration().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: KubeControllersConfiguration(" + name + ")"))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Getting KubeControllersConfiguration with the original resource version and comparing the output against spec1")
				res, outError = c.KubeControllersConfiguration().Get(ctx, name, options.GetOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(res).To(MatchResource(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec1))
				Expect(res.ResourceVersion).To(Equal(rv1_1))
			}

			By("Getting KubeControllersConfiguration with the updated resource version and comparing the output against spec2")
			res, outError = c.KubeControllersConfiguration().Get(ctx, name, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Listing KubeControllersConfiguration with the original resource version and checking for a single result with spec1")
				outList, outError = c.KubeControllersConfiguration().List(ctx, options.ListOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(outList.Items).To(ConsistOf(
					testutils.Resource(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec1),
				))
			}

			By("Listing KubeControllersConfiguration with the latest resource version and checking for one result with spec2")
			outList, outError = c.KubeControllersConfiguration().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec2),
			))

			By("Setting status1 on resource")
			res.Status = status1
			res, outError = c.KubeControllersConfiguration().Update(ctx, res, options.SetOptions{})
			Expect(outError).ToNot(HaveOccurred())
			Expect(res).To(MatchResourceWithStatus(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec2, status1))

			By("Getting resource and verifying status1 is present")
			res, outError = c.KubeControllersConfiguration().Get(ctx, name, options.GetOptions{})
			Expect(outError).ToNot(HaveOccurred())
			Expect(res).To(MatchResourceWithStatus(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec2, status1))

			By("Setting status2 on resource")
			res.Status = status2
			res, outError = c.KubeControllersConfiguration().Update(ctx, res, options.SetOptions{})
			Expect(outError).ToNot(HaveOccurred())
			Expect(res).To(MatchResourceWithStatus(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec2, status2))
			rv1_3 := res.ResourceVersion

			By("Getting resource and verifying status2 is present")
			res, outError = c.KubeControllersConfiguration().Get(ctx, name, options.GetOptions{})
			Expect(outError).ToNot(HaveOccurred())
			Expect(res).To(MatchResourceWithStatus(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec2, status2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Deleting KubeControllersConfiguration with the old resource version")
				_, outError = c.KubeControllersConfiguration().Delete(ctx, name, options.DeleteOptions{ResourceVersion: rv1_1})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal("update conflict: KubeControllersConfiguration(" + name + ")"))
			}

			By("Deleting KubeControllersConfiguration with the new resource version")
			dres, outError := c.KubeControllersConfiguration().Delete(ctx, name, options.DeleteOptions{ResourceVersion: rv1_3})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResourceWithStatus(apiv3.KindKubeControllersConfiguration, testutils.ExpectNoNamespace, name, spec2, status2))

			By("Listing all KubeControllersConfiguration and expecting no items")
			outList, outError = c.KubeControllersConfiguration().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

		},

		// Test 1: Pass two fully populated KubeControllersConfigurationSpecs and expect the series of operations to succeed.
		Entry("Two fully populated KubeControllersConfigurationSpecs", name, spec1, spec2, status1, status2),
	)

	Describe("KubeControllersConfiguration watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			By("Listing KubeControllersConfiguration with the latest resource version and checking for one result with spec2")
			outList, outError := c.KubeControllersConfiguration().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a KubeControllersConfiguration spec1 and storing the response")
			outRes1, err := c.KubeControllersConfiguration().Create(
				ctx,
				&apiv3.KubeControllersConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			rev1 := outRes1.ResourceVersion

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.KubeControllersConfiguration().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.KubeControllersConfiguration().Delete(ctx, name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for event: delete res1")
			testWatcher1.ExpectEvents(apiv3.KindKubeControllersConfiguration, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
			})
			testWatcher1.Stop()

			By("Configuring a KubeControllersConfiguration spec2 and storing the response")
			outRes2, err := c.KubeControllersConfiguration().Create(
				ctx,
				&apiv3.KubeControllersConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec:       spec2,
				},
				options.SetOptions{},
			)

			By("Starting a watcher from rev0 - this should get all events")
			w, err = c.KubeControllersConfiguration().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.KubeControllersConfiguration().Update(
				ctx,
				&apiv3.KubeControllersConfiguration{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindKubeControllersConfiguration, []watch.Event{
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
				By("Starting a watcher from rev0 watching by name - this should get all events")
				w, err = c.KubeControllersConfiguration().Watch(ctx, options.ListOptions{Name: name, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(apiv3.KindKubeControllersConfiguration, []watch.Event{
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
			w, err = c.KubeControllersConfiguration().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEventsAnyOrder(apiv3.KindKubeControllersConfiguration, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})

			By("Cleaning the datastore and expecting deletion events for each configured resource (tests prefix deletes results in individual events for each key)")
			err = be.Clean()
			Expect(err).NotTo(HaveOccurred())
			testWatcher3.ExpectEvents(apiv3.KindKubeControllersConfiguration, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes3,
				},
			})
			testWatcher3.Stop()
		})
	})
})
