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
	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"context"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("BGPConfiguration tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	nameDefault := "default"
	name1 := "bgpconfig-1"
	name2 := "bgpconfig-2"
	ptrTrue := true
	ptrFalse := false
	nodeASNumber1 := numorstring.ASNumber(6512)
	nodeASNumber2 := numorstring.ASNumber(6511)
	nodeASNumber3 := numorstring.ASNumber(6510)
	ipCidr1 := "104.244.42.129/32"
	ipCidr2 := "172.217.3.0/24"
	clusterCIDR := "10.155.0.0/16"
	restartTime := metav1.Duration{Duration: 200 * time.Second}
	specDefault1 := apiv3.BGPConfigurationSpec{
		LogSeverityScreen:      "Info",
		NodeToNodeMeshEnabled:  &ptrTrue,
		ASNumber:               &nodeASNumber1,
		ServiceLoadBalancerIPs: []apiv3.ServiceLoadBalancerIPBlock{{CIDR: ipCidr1}},
		ServiceExternalIPs: []apiv3.ServiceExternalIPBlock{
			{CIDR: ipCidr1},
			{CIDR: ipCidr2},
		},
		ServiceClusterIPs: []apiv3.ServiceClusterIPBlock{
			{CIDR: clusterCIDR},
		},
		NodeMeshPassword: &apiv3.BGPPassword{
			SecretKeyRef: &k8sv1.SecretKeySelector{
				LocalObjectReference: k8sv1.LocalObjectReference{
					Name: "test-secret",
				},
				Key: "bgp-password",
			},
		},
		NodeMeshMaxRestartTime: &restartTime,
	}
	specDefault2 := apiv3.BGPConfigurationSpec{
		LogSeverityScreen:     "Warning",
		NodeToNodeMeshEnabled: &ptrFalse,
		ASNumber:              &nodeASNumber2,
		ServiceExternalIPs: []apiv3.ServiceExternalIPBlock{
			{CIDR: ipCidr1},
		},
	}
	specDefault3 := apiv3.BGPConfigurationSpec{
		LogSeverityScreen:     "Info",
		NodeToNodeMeshEnabled: &ptrTrue,
		ASNumber:              &nodeASNumber3,
		ServiceExternalIPs: []apiv3.ServiceExternalIPBlock{
			{CIDR: ipCidr1},
			{CIDR: ipCidr2},
		},
		NodeMeshPassword: &apiv3.BGPPassword{
			SecretKeyRef: &k8sv1.SecretKeySelector{
				LocalObjectReference: k8sv1.LocalObjectReference{
					Name: "test-secret",
				},
				Key: "bgp-password",
			},
		},
	}
	specDefault4 := apiv3.BGPConfigurationSpec{
		LogSeverityScreen:     "Info",
		NodeToNodeMeshEnabled: &ptrTrue,
		ASNumber:              &nodeASNumber3,
		ServiceExternalIPs: []apiv3.ServiceExternalIPBlock{
			{CIDR: ipCidr1},
			{CIDR: ipCidr2},
		},
		NodeMeshMaxRestartTime: &restartTime,
	}
	specInfo := apiv3.BGPConfigurationSpec{
		LogSeverityScreen: "Info",
	}
	specDebug := apiv3.BGPConfigurationSpec{
		LogSeverityScreen: "Debug",
	}

	DescribeTable("BGPConfiguration e2e CRUD tests",
		func(name1, name2 string, specInfo, specDebug apiv3.BGPConfigurationSpec) {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Updating the BGPConfiguration before it is created")
			_, outError := c.BGPConfigurations().Update(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: nameDefault, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: "test-fail-workload-bgpconfig"},
				Spec:       specDefault1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: BGPConfiguration(" + nameDefault + ") with error:"))

			By("Attempting to creating a new BGPConfiguration with name1/specInfo and a non-empty ResourceVersion")
			_, outError = c.BGPConfigurations().Create(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
				Spec:       specInfo,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Creating a new BGPConfiguration with name1/specInfo")
			res1, outError := c.BGPConfigurations().Create(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       specInfo,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name1, specInfo))

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same BGPConfiguration with name1 but with specDebug")
			_, outError = c.BGPConfigurations().Create(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       specDebug,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: BGPConfiguration(" + name1 + ")"))

			By("Getting BGPConfiguration (name1) and comparing the output against specInfo")
			res, outError := c.BGPConfigurations().Get(ctx, name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name1, specInfo))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Getting BGPConfiguration (name2) before it is created")
			_, outError = c.BGPConfigurations().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: BGPConfiguration(" + name2 + ") with error:"))

			By("Listing all the BGPConfigurations, expecting a single result with name1/specInfo")
			outList, outError := c.BGPConfigurations().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name1, specInfo),
			))

			By("Creating a new BGPConfiguration with name2/specDebug")
			res2, outError := c.BGPConfigurations().Create(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       specDebug,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name2, specDebug))

			By("Getting BGPConfiguration (name2) and comparing the output against specDebug")
			res, outError = c.BGPConfigurations().Get(ctx, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name2, specDebug))
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the BGPConfigurations, expecting a two results with name1/specInfo and name2/specDebug")
			outList, outError = c.BGPConfigurations().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name1, specInfo),
				testutils.Resource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name2, specDebug),
			))

			By("Updating BGPConfiguration name1 with specDebug")
			res1.Spec = specDebug
			res1, outError = c.BGPConfigurations().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name1, specDebug))

			By("Attempting to update the BGPConfiguration without a Creation Timestamp")
			res, outError = c.BGPConfigurations().Update(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", UID: "test-fail-bgpconfig"},
				Spec:       specInfo,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the BGPConfiguration without a UID")
			res, outError = c.BGPConfigurations().Update(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       specInfo,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name1 data.
			rv1_2 := res1.ResourceVersion

			By("Updating BGPConfiguration name1 without specifying a resource version")
			res1.Spec = specInfo
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.BGPConfigurations().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating BGPConfiguration name1 using the previous resource version")
			res1.Spec = specInfo
			res1.ResourceVersion = rv1_1
			_, outError = c.BGPConfigurations().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: BGPConfiguration(" + name1 + ")"))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Getting BGPConfiguration (name1) with the original resource version and comparing the output against specInfo")
				res, outError = c.BGPConfigurations().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(res).To(MatchResource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name1, specInfo))
				Expect(res.ResourceVersion).To(Equal(rv1_1))
			}

			By("Getting BGPConfiguration (name1) with the updated resource version and comparing the output against specDebug")
			res, outError = c.BGPConfigurations().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name1, specDebug))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Listing BGPConfigurations with the original resource version and checking for a single result with name1/specInfo")
				outList, outError = c.BGPConfigurations().List(ctx, options.ListOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(outList.Items).To(ConsistOf(
					testutils.Resource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name1, specInfo),
				))
			}

			By("Listing BGPConfigurations with the latest resource version and checking for two results with name1/specDebug and name2/specDebug")
			outList, outError = c.BGPConfigurations().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name1, specDebug),
				testutils.Resource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name2, specDebug),
			))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Deleting BGPConfiguration (name1) with the old resource version")
				_, outError = c.BGPConfigurations().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_1})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal("update conflict: BGPConfiguration(" + name1 + ")"))
			}

			By("Deleting BGPConfiguration (name1) with the new resource version")
			dres, outError := c.BGPConfigurations().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name1, specDebug))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Updating BGPConfiguration name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.BGPConfigurations().Update(ctx, res2, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
				_, outError = c.BGPConfigurations().Get(ctx, name2, options.GetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(2 * time.Second)
				_, outError = c.BGPConfigurations().Get(ctx, name2, options.GetOptions{})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(ContainSubstring("resource does not exist: BGPConfiguration(" + name2 + ") with error:"))

				By("Creating BGPConfiguration name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.BGPConfigurations().Create(ctx, &apiv3.BGPConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       specDebug,
				}, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
				_, outError = c.BGPConfigurations().Get(ctx, name2, options.GetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(2 * time.Second)
				_, outError = c.BGPConfigurations().Get(ctx, name2, options.GetOptions{})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(ContainSubstring("resource does not exist: BGPConfiguration(" + name2 + ") with error:"))
			}

			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				// Delete name2 manually since we are skipping TTL tests until it is supported by the k8s backend.
				By("Attempting to deleting BGPConfiguration (name2)")
				dres, outError = c.BGPConfigurations().Delete(ctx, name2, options.DeleteOptions{})
				Expect(outError).NotTo(HaveOccurred())
				Expect(dres).To(MatchResource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, name2, specDebug))
			}

			By("Attempting to deleting BGPConfiguration (name2) again")
			_, outError = c.BGPConfigurations().Delete(ctx, name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: BGPConfiguration(" + name2 + ") with error:"))

			By("Listing all BGPConfigurations and expecting no items")
			outList, outError = c.BGPConfigurations().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting BGPConfiguration (name2) and expecting an error")
			_, outError = c.BGPConfigurations().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: BGPConfiguration(" + name2 + ") with error:"))

			By("Creating a default BGPConfiguration with node to node mesh enabled and a default AS number")
			resDefault, outError := c.BGPConfigurations().Create(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: nameDefault},
				Spec:       specDefault1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(resDefault).To(MatchResource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, nameDefault, specDefault1))

			By("Updating the default BGPConfiguration with node to node mesh disabled and a different default AS number")
			resDefault.Spec = specDefault2
			resDefault, outError = c.BGPConfigurations().Update(ctx, resDefault, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(resDefault).To(MatchResource(apiv3.KindBGPConfiguration, testutils.ExpectNoNamespace, nameDefault, specDefault2))

			By("Attempting to create a non-default BGPConfiguration with node to node mesh enabled and a default AS number")
			_, outError = c.BGPConfigurations().Create(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "not-default"},
				Spec:       specDefault1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())

			By("Attempting to update BGPConfiguration name1 with node to node mesh enabled and a default AS number")
			_, outError = c.BGPConfigurations().Update(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       specDefault1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())

			By("Attempting to create a non-default BGP Configuration with node to node mesh enabled and a node mesh password")
			_, outError = c.BGPConfigurations().Create(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "not-default"},
				Spec:       specDefault3,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())

			By("Attempting to update BGPConfiguration name1 with node to node mesh enabled and a node mesh password")
			_, outError = c.BGPConfigurations().Update(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       specDefault3,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())

			By("Attempting to create a non-default BGP Configuration with node to node mesh enabled and a node mesh max restart time")
			_, outError = c.BGPConfigurations().Create(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "not-default"},
				Spec:       specDefault4,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())

			By("Attempting to update BGPConfiguration name1 with node to node mesh enabled and a node mesh max restart time")
			_, outError = c.BGPConfigurations().Update(ctx, &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       specDefault4,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
		},

		// Test 1: Pass two fully populated BGPConfigurationSpecs and expect the series of operations to succeed.
		Entry("Two fully populated BGPConfigurationSpecs", name1, name2, specInfo, specDebug),
	)

	Describe("BGPConfiguration watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing BGPConfigurations with the latest resource version and checking for two results with name1/specDebug and name2/specDebug")
			outList, outError := c.BGPConfigurations().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a BGPConfiguration name1/specInfo and storing the response")
			outRes1, err := c.BGPConfigurations().Create(
				ctx,
				&apiv3.BGPConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       specInfo,
				},
				options.SetOptions{},
			)
			rev1 := outRes1.ResourceVersion

			By("Configuring a BGPConfiguration name2/specDebug and storing the response")
			outRes2, err := c.BGPConfigurations().Create(
				ctx,
				&apiv3.BGPConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       specDebug,
				},
				options.SetOptions{},
			)

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.BGPConfigurations().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.BGPConfigurations().Delete(ctx, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(apiv3.KindBGPConfiguration, []watch.Event{
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
			w, err = c.BGPConfigurations().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.BGPConfigurations().Update(
				ctx,
				&apiv3.BGPConfiguration{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       specInfo,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindBGPConfiguration, []watch.Event{
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
				w, err = c.BGPConfigurations().Watch(ctx, options.ListOptions{Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(apiv3.KindBGPConfiguration, []watch.Event{
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
			w, err = c.BGPConfigurations().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(apiv3.KindBGPConfiguration, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})
			testWatcher3.Stop()

			By("Configuring BGPConfiguration name1/specInfo again and storing the response")
			outRes1, err = c.BGPConfigurations().Create(
				ctx,
				&apiv3.BGPConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       specInfo,
				},
				options.SetOptions{},
			)

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.BGPConfigurations().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEventsAnyOrder(apiv3.KindBGPConfiguration, []watch.Event{
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
			testWatcher4.ExpectEvents(apiv3.KindBGPConfiguration, []watch.Event{
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
