// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("IPPool tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	name1 := "ippool-1"
	name2 := "ippool-2"
	name3 := "ippool-3"
	spec1 := apiv3.IPPoolSpec{
		CIDR:         "1.2.3.0/24",
		IPIPMode:     apiv3.IPIPModeAlways,
		VXLANMode:    apiv3.VXLANModeNever,
		BlockSize:    26,
		NodeSelector: "all()",
		AllowedUses:  []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload, apiv3.IPPoolAllowedUseTunnel},
	}
	spec1_2 := apiv3.IPPoolSpec{
		CIDR:             "1.2.3.0/24",
		NATOutgoing:      true,
		IPIPMode:         apiv3.IPIPModeNever,
		VXLANMode:        apiv3.VXLANModeAlways,
		BlockSize:        26,
		NodeSelector:     `foo == "bar"`,
		AllowedUses:      []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload, apiv3.IPPoolAllowedUseTunnel},
		DisableBGPExport: true,
	}
	spec2 := apiv3.IPPoolSpec{
		CIDR:             "2001::/120",
		NATOutgoing:      true,
		IPIPMode:         apiv3.IPIPModeNever,
		VXLANMode:        apiv3.VXLANModeNever,
		BlockSize:        122,
		NodeSelector:     "all()",
		AllowedUses:      []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload, apiv3.IPPoolAllowedUseTunnel},
		DisableBGPExport: true,
	}
	spec2_1 := apiv3.IPPoolSpec{
		CIDR:             "2001::/120",
		IPIPMode:         apiv3.IPIPModeNever,
		VXLANMode:        apiv3.VXLANModeNever,
		BlockSize:        122,
		NodeSelector:     "all()",
		AllowedUses:      []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload, apiv3.IPPoolAllowedUseTunnel},
		DisableBGPExport: false,
	}
	spec3 := apiv3.IPPoolSpec{
		CIDR:         "1.2.3.0/24",
		IPIPMode:     "",
		VXLANMode:    "",
		BlockSize:    26,
		NodeSelector: "all()",
		AllowedUses:  []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload, apiv3.IPPoolAllowedUseTunnel},
	}
	spec3_1 := apiv3.IPPoolSpec{
		CIDR:         "1.2.3.0/24",
		IPIPMode:     apiv3.IPIPModeNever,
		VXLANMode:    apiv3.VXLANModeNever,
		BlockSize:    26,
		NodeSelector: "all()",
		AllowedUses:  []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload, apiv3.IPPoolAllowedUseTunnel},
	}

	It("should error when creating an IPPool with no name", func() {
		c, err := clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())

		pool := apiv3.IPPool{
			Spec: apiv3.IPPoolSpec{
				CIDR: "192.168.0.0/16",
			},
		}
		_, err = c.IPPools().Create(ctx, &pool, options.SetOptions{})
		Expect(err).To(HaveOccurred())
	})

	DescribeTable("IPPool e2e CRUD tests",
		func(name1, name2, name3 string, spec1, spec1_2, spec2, spec3, spec3_1 apiv3.IPPoolSpec) {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Updating the IPPool before it is created")
			_, outError := c.IPPools().Update(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: "test-fail-ippool"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: IPPool(" + name1 + ") with error:"))

			By("Attempting to creating a new IPPool with name1/spec1 and a non-empty ResourceVersion")
			_, outError = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Creating a new IPPool with name1/spec1")
			poolToCreate := &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
			}
			poolToCreateCopy := poolToCreate.DeepCopy()
			res1, outError := c.IPPools().Create(ctx, poolToCreate, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(poolToCreate).To(Equal(poolToCreateCopy), "Create() unexpectedly modified input")
			Expect(res1).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec1))

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same IPPool with name1 but with spec2")
			_, outError = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: IPPool(" + name1 + ")"))

			By("Getting IPPool (name1) and comparing the output against spec1")
			res, outError := c.IPPools().Get(ctx, name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Getting IPPool (name2) before it is created")
			_, outError = c.IPPools().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: IPPool(" + name2 + ") with error:"))

			By("Listing all the IPPools, expecting a single result with name1/spec1")
			outList, outError := c.IPPools().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec1),
			))

			By("Creating a new IPPool with name2/spec2")
			res2, outError := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name2, spec2))

			By("Getting IPPool (name2) and comparing the output against spec2")
			res, outError = c.IPPools().Get(ctx, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name2, spec2))
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the IPPools, expecting a two results with name1/spec1 and name2/spec2")
			outList, outError = c.IPPools().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec1),
				testutils.Resource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name2, spec2),
			))

			By("Updating IPPool name1 with spec1_2")
			res1.Spec = spec1_2
			res1Copy := res1.DeepCopy()
			res1Out, outError := c.IPPools().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(Equal(res1Copy), "Update() unexpectedly modified input")
			res1 = res1Out
			Expect(res1).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec1_2))

			By("Attempting to update the IPPool without a Creation Timestamp")
			res, outError = c.IPPools().Update(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", UID: "test-fail-ippool"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the IPPool without a UID")
			res, outError = c.IPPools().Update(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name1 data.
			rv1_2 := res1.ResourceVersion

			By("Updating IPPool name1 without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.IPPools().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating IPPool name1 using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			_, outError = c.IPPools().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: IPPool(" + name1 + ")"))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Getting IPPool (name1) with the original resource version and comparing the output against spec1")
				res, outError = c.IPPools().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(res).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec1))
				Expect(res.ResourceVersion).To(Equal(rv1_1))
			}

			By("Getting IPPool (name1) with the updated resource version and comparing the output against spec1_2")
			res, outError = c.IPPools().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec1_2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Listing IPPools with the original resource version and checking for a single result with name1/spec1")
				outList, outError = c.IPPools().List(ctx, options.ListOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(outList.Items).To(ConsistOf(
					testutils.Resource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec1),
				))
			}

			By("Listing IPPools with the latest resource version and checking for two results with name1/spec1_2 and name2/spec2")
			outList, outError = c.IPPools().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec1_2),
				testutils.Resource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name2, spec2),
			))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Deleting IPPool (name1) with the old resource version")
				_, outError = c.IPPools().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_1})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal("update conflict: IPPool(" + name1 + ")"))
			}

			By("Deleting IPPool (name1) with the new resource version")
			dres, outError := c.IPPools().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			// The pool will first be disabled, so tweak the Disabled field before doing the comparison.
			spec1_2.Disabled = true
			Expect(dres).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Updating IPPool name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.IPPools().Update(ctx, res2, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
				_, outError = c.IPPools().Get(ctx, name2, options.GetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(2 * time.Second)
				_, outError = c.IPPools().Get(ctx, name2, options.GetOptions{})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(ContainSubstring("resource does not exist: IPPool(" + name2 + ") with error:"))

				By("Creating IPPool name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.IPPools().Create(ctx, &apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
				}, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
				_, outError = c.IPPools().Get(ctx, name2, options.GetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(2 * time.Second)
				_, outError = c.IPPools().Get(ctx, name2, options.GetOptions{})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(ContainSubstring("resource does not exist: IPPool(" + name2 + ") with error:"))
			}

			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				// The pool will first be disabled, so tweak the Disabled field before doing the comparison.
				By("Deleting IPPool (name2)")
				dres, outError = c.IPPools().Delete(ctx, name2, options.DeleteOptions{})
				Expect(outError).NotTo(HaveOccurred())
				spec2.Disabled = true
				Expect(dres).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name2, spec2))
			}

			By("Attempting to deleting IPPool (name2) again")
			_, outError = c.IPPools().Delete(ctx, name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: IPPool(" + name2 + ") with error:"))

			By("Listing all IPPools and expecting no items")
			outList, outError = c.IPPools().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting IPPool (name2) and expecting an error")
			_, outError = c.IPPools().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: IPPool(" + name2 + ") with error:"))

			By("Adding an IPPool with empty string for IPIPMode and VXLANMode and expecting it to be defaulted to 'Never'")
			res, outError = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: name3},
				Spec:       spec3,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name3, spec3_1))

			res, outError = c.IPPools().Get(ctx, name3, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name3, spec3_1))

			outList, outError = c.IPPools().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name3, spec3_1),
			))

			By("Deleting IPPool (name3)")
			dres, outError = c.IPPools().Delete(ctx, name3, options.DeleteOptions{})
			Expect(outError).NotTo(HaveOccurred())
			spec3_1.Disabled = true
			Expect(dres).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name3, spec3_1))
		},

		// Test 1: Pass two fully populated IPPoolSpecs and expect the series of operations to succeed.
		Entry("Two fully populated IPPoolSpecs", name1, name2, name3, spec1, spec1_2, spec2, spec3, spec3_1),
	)

	Describe("IPPool watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing IPPools with no resource version and checking for no results")
			outList, outError := c.IPPools().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring an IPPool name1/spec1 and storing the response")
			outRes1, err := c.IPPools().Create(
				ctx,
				&apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			rev1 := outRes1.ResourceVersion

			By("Configuring an IPPool name2/spec2 and storing the response")
			outRes2, err := c.IPPools().Create(
				ctx,
				&apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.IPPools().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			outRes3, err := c.IPPools().Delete(ctx, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for three events, create res2 and disable and delete res1")
			testWatcher1.ExpectEvents(apiv3.KindIPPool, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Modified,
					Object:   outRes3,
					Previous: outRes1,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes3,
				},
			})
			testWatcher1.Stop()

			By("Starting a watcher from rev0 - this should get all events")
			w, err = c.IPPools().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes4, err := c.IPPools().Update(
				ctx,
				&apiv3.IPPool{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec2_1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindIPPool, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Modified,
					Object:   outRes3,
					Previous: outRes1,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes3,
				},
				{
					Type:     watch.Modified,
					Previous: outRes2,
					Object:   outRes4,
				},
			})
			testWatcher2.Stop()

			// Only etcdv3 supports watching a specific instance of a resource.
			if config.Spec.DatastoreType == apiconfig.EtcdV3 {
				By("Starting a watcher from rev0 watching name1 - this should get all events for name1")
				w, err = c.IPPools().Watch(ctx, options.ListOptions{Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(apiv3.KindIPPool, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes1,
					},
					{
						Type:     watch.Modified,
						Object:   outRes3,
						Previous: outRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: outRes3,
					},
				})
				testWatcher2_1.Stop()
			}

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.IPPools().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(apiv3.KindIPPool, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes4,
				},
			})
			testWatcher3.Stop()

			By("Configuring IPPool name1/spec1 again and storing the response")
			outRes1, err = c.IPPools().Create(
				ctx,
				&apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.IPPools().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEventsAnyOrder(apiv3.KindIPPool, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes4,
				},
			})
			testWatcher4.Stop()
		})
	})

	Describe("Verify handling of VXLAN mode", func() {
		missingVxlanPool := apiv3.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
			Spec: apiv3.IPPoolSpec{
				CIDR: "192.168.0.0/16",
			},
		}

		var err error
		var c clientv3.Interface

		BeforeEach(func() {
			c, err = clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()
		})

		getGlobalSetting := func() (*bool, error) {
			cfg, err := c.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
			if err != nil {
				return nil, err
			}
			return cfg.Spec.VXLANEnabled, nil
		}

		It("should create/update an IPPool when VXLAN is missing", func() {
			// create an ipppol with missing vxlan
			ipPoolV1 := missingVxlanPool.DeepCopy()
			ipPoolV2, err := c.IPPools().Create(ctx, ipPoolV1, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// update an ipppol with missing vxlan
			ipPoolV2.Spec.VXLANMode = ""
			_, err = c.IPPools().Update(ctx, ipPoolV2, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// delete the ipppol
			_, err = c.IPPools().Delete(ctx, ipPoolV2.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should enable VXLAN globally on an IPPool Create (VXLANModeAlways) if the global setting is not configured", func() {
			By("Getting the current felix configuration - checking does not exist")
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))

			By("Creating a non-VXLAN pool and verifying no felix configuration still and default VXLANMode set to Never")
			pool, err := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.0/24",
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(pool.Spec.VXLANMode).To(Equal(apiv3.VXLANModeNever))
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))

			By("Attempting to create a VXLAN IPv6 pool and verifying no felix configuration still")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "aa:bb::cc/120",
					VXLANMode: apiv3.VXLANModeAlways,
				},
			}, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorValidation{}))
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))

			By("Creating an VXLANModeAlways pool and verifying global felix config is not created")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool2"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "1.2.4.0/24",
					VXLANMode: apiv3.VXLANModeAlways,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))
		})

		It("should not enable VXLAN globally on an IPPool Update if the global setting is not configured", func() {
			By("Getting the current felix configuration - checking does not exist")
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))

			By("Creating a non-VXLAN pool and verifying no felix configuration still")
			pool, err := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.0/24",
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))

			By("Updating the pool to enabled VXLAN and checking felix configuration is not added")
			pool.Spec.VXLANMode = apiv3.VXLANModeAlways
			_, err = c.IPPools().Update(ctx, pool, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))
		})

		It("should not enable VXLAN globally on an IPPool Create if the global setting already configured to false", func() {
			By("Setting the global felix VXLAN enabled to false")
			ipipEnabled := false
			_, err = c.FelixConfigurations().Create(ctx, &apiv3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: apiv3.FelixConfigurationSpec{
					VXLANEnabled: &ipipEnabled,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Creating an VXLANModeAlways pool and verifying global felix config is not updated")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "1.2.4.0/24",
					VXLANMode: apiv3.VXLANModeAlways,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			enabled, err := getGlobalSetting()
			Expect(err).NotTo(HaveOccurred())
			Expect(*enabled).To(BeFalse())
		})
	})

	Describe("Verify handling of IPIP mode", func() {
		var err error
		var c clientv3.Interface

		BeforeEach(func() {
			c, err = clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()
		})

		getGlobalSetting := func() (*bool, error) {
			cfg, err := c.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
			if err != nil {
				return nil, err
			}
			return cfg.Spec.IPIPEnabled, nil
		}

		It("should not enable IPIP globally on an IPPool Create (IPIPModeAlways) if the global setting is not configured", func() {
			By("Getting the current felix configuration - checking does not exist")
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))

			By("Creating a non-IPIP pool and verifying no felix configuration still and default IPIPMode set to Never")
			pool, err := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.0/24",
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(pool.Spec.IPIPMode).To(Equal(apiv3.IPIPModeNever))
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))

			By("Attempting to create an IPIP IPv6 pool and verifying no felix configuration still")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:     "aa:bb::cc/120",
					IPIPMode: apiv3.IPIPModeAlways,
				},
			}, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorValidation{}))
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))

			By("Creating an IPIPModeAlways pool and verifying global felix config is not created")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool2"},
				Spec: apiv3.IPPoolSpec{
					CIDR:     "1.2.4.0/24",
					IPIPMode: apiv3.IPIPModeAlways,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))
		})

		It("should not enable IPIP globally on an IPPool Create (IPIPModeNever) if the global setting is not configured", func() {
			By("Getting the current felix configuration - checking does not exist")
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))

			By("Creating an IPIPModeCrossSubnet pool and verifying global felix config is not created")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:     "1.2.4.0/24",
					IPIPMode: apiv3.IPIPModeCrossSubnet,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))
		})

		It("should not enable IPIP globally on an IPPool Update if the global setting is not configured", func() {
			By("Getting the current felix configuration - checking does not exist")
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))

			By("Creating a non-IPIP pool and verifying no felix configuration still")
			pool, err := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.0/24",
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))

			By("Updating the pool to enabled IPIP and checking felix configuration is not added")
			pool.Spec.IPIPMode = apiv3.IPIPModeAlways
			_, err = c.IPPools().Update(ctx, pool, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = getGlobalSetting()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))
		})

		It("should not enable IPIP globally on an IPPool Create if the global setting already configured to false", func() {
			By("Setting the global felix IPIP enabled to false")
			ipipEnabled := false
			_, err = c.FelixConfigurations().Create(ctx, &apiv3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: apiv3.FelixConfigurationSpec{
					IPIPEnabled: &ipipEnabled,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Creating an IPIPModeCrossSubnet pool and verifying global felix config is not updated")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:     "1.2.4.0/24",
					IPIPMode: apiv3.IPIPModeCrossSubnet,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			enabled, err := getGlobalSetting()
			Expect(err).NotTo(HaveOccurred())
			Expect(*enabled).To(BeFalse())
		})
	})

	Describe("Verify pool CIDR validation", func() {
		var err error
		var c clientv3.Interface

		BeforeEach(func() {
			c, err = clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()
		})

		It("should prevent the CIDR being changed on an update", func() {
			By("Creating a pool")
			pool, err := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.0/24",
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Attempting to change the CIDR")
			pool.Spec.CIDR = "1.2.4.0/24"
			_, err = c.IPPools().Update(ctx, pool, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorValidation{}))
			Expect(err.Error()).To(ContainSubstring("IPPool CIDR cannot be modified"))
		})

		It("should prevent the creation of a pool with an identical or overlapping CIDR", func() {
			By("Creating a pool")
			_, err := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.0/24",
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Attempting to create the same pool and checking for the correct error")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.0/24",
				},
			}, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceAlreadyExists{}))

			By("Attempting to create a pool with the same CIDR")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool2"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.0/24",
				},
			}, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorValidation{}))
			Expect(err.Error()).To(ContainSubstring("IPPool(ippool2) CIDR overlaps with IPPool(ippool1) CIDR 1.2.3.0/24"))

			By("Attempting to create a pool with a larger overlapping CIDR")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool3"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.0.0/16",
				},
			}, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorValidation{}))
			Expect(err.Error()).To(ContainSubstring("IPPool(ippool3) CIDR overlaps with IPPool(ippool1) CIDR 1.2.3.0/24"))

			By("Attempting to create a pool with a smaller overlapping CIDR")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool4"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.128/25",
				},
			}, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorValidation{}))
			Expect(err.Error()).To(ContainSubstring("IPPool(ippool4) CIDR overlaps with IPPool(ippool1) CIDR 1.2.3.0/24"))
		})
	})

	Describe("Verify pool blocksize validation", func() {
		var err error
		var c clientv3.Interface

		BeforeEach(func() {
			c, err = clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()
		})

		It("should prevent the blocksize being changed on an update", func() {
			By("Creating a pool")
			pool, err := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "1.2.3.0/24",
					BlockSize: 25,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Attempting to change the blockSize")
			pool.Spec.BlockSize = 26
			_, err = c.IPPools().Update(ctx, pool, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorValidation{}))
			Expect(err.Error()).To(ContainSubstring("IPPool BlockSize cannot be modified"))
		})

		It("should prevent pools from being created with bad block sizes", func() {
			_, err := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "1.2.3.0/24",
					BlockSize: 19,
				},
			}, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorValidation{}))
			Expect(err.Error()).To(ContainSubstring("block size must be between"))

			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "1.2.3.0/24",
					BlockSize: 33,
				},
			}, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorValidation{}))
			Expect(err.Error()).To(ContainSubstring("block size must be between"))
		})

		It("should prevent the creation of a pool with an identical or overlapping CIDR using block sizes", func() {
			By("Creating a pool")
			_, err := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "1.2.3.0/24",
					BlockSize: 25,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Attempting to create a pool with the same CIDR")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool2"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "1.2.3.0/24",
					BlockSize: 25,
				},
			}, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorValidation{}))
			Expect(err.Error()).To(ContainSubstring("IPPool(ippool2) CIDR overlaps with IPPool(ippool1) CIDR 1.2.3.0/24"))

			By("Attempting to create a pool half overlapping CIDR and a different block size")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool3"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.8/31",
				},
			}, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(errors.ErrorValidation{}))
			Expect(err.Error()).To(ContainSubstring("IPPool(ippool3) CIDR overlaps with IPPool(ippool1) CIDR 1.2.3.0/24"))
		})
	})
})

var _ = testutils.E2eDatastoreDescribe("IPPool tests (etcd only)", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()

	Describe("Verify pool creation with changing blocksizes", func() {
		var c clientv3.Interface
		var err error

		BeforeEach(func() {
			c, err = clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()
		})

		It("should prevent the creation of a pool that covers existing blocks with a different blockSize", func() {
			By("Creating a pool with the default blockSize")
			_, err := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.0/26",
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Create test node
			host := "host-test"
			_, err = c.Nodes().Create(ctx, &libapiv3.Node{ObjectMeta: metav1.ObjectMeta{Name: host}}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Allocate an IP so that a block is allocated
			v4ia, _, err := c.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{Num4: 1, Hostname: host, IntendedUse: apiv3.IPPoolAllowedUseWorkload})
			Expect(err).NotTo(HaveOccurred())
			Expect(v4ia).ToNot(BeNil())
			var assigned []ipam.ReleaseOptions
			for _, ipnet := range v4ia.IPs {
				assigned = append(assigned, ipam.ReleaseOptions{Address: ipnet.IP.String()})
			}
			Expect(assigned).To(HaveLen(1))

			// Delete the pool
			_, err = c.IPPools().Delete(ctx, "ippool1", options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("creating a pool with a different blockSize")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "1.2.3.0/26",
					BlockSize: 28,
				},
			}, options.SetOptions{})
			Expect(err).To(HaveOccurred())

			By("creating a pool with the same blockSize")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "1.2.3.0/26",
					BlockSize: 26,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Delete the pool
			_, err = c.IPPools().Delete(ctx, "ippool1", options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("creating a pool with a different blockSize that overlaps")
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "1.2.2.0/23",
					BlockSize: 28,
				},
			}, options.SetOptions{})
			Expect(err).To(HaveOccurred())

			By("deleting the block and creating a pool with a different blockSize")
			unreleased, err := c.IPAM().ReleaseIPs(ctx, assigned...)
			Expect(err).NotTo(HaveOccurred())
			Expect(unreleased).To(HaveLen(0))
			_, err = c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "1.2.3.0/26",
					BlockSize: 28,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should allow the creation of a pool that covers different blocks with a different blockSize", func() {
			By("Creating a pool with the default blockSize")
			_, err := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool1"},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.0/24",
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			host := "host-test"
			_, err = c.Nodes().Create(ctx, &libapiv3.Node{ObjectMeta: metav1.ObjectMeta{Name: host}}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Allocate an IP so that a block is allocated
			v4ia, _, err := c.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{Num4: 1, Hostname: host, IntendedUse: apiv3.IPPoolAllowedUseWorkload})
			Expect(err).NotTo(HaveOccurred())
			Expect(v4ia).ToNot(BeNil())
			Expect(v4ia.IPs).To(HaveLen(1))

			By("creating a pool with a different cidr and block size")
			p2, err := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "ippool2"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "1.2.4.0/24",
					BlockSize: 29,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Allocate an IP so that a block is allocated
			pool2 := []cnet.IPNet{cnet.MustParseCIDR(p2.Spec.CIDR)}
			v4ia, _, err = c.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{IPv4Pools: pool2, Num4: 1, Hostname: host, IntendedUse: apiv3.IPPoolAllowedUseWorkload})
			Expect(err).NotTo(HaveOccurred())
			Expect(v4ia).ToNot(BeNil())
			Expect(v4ia.IPs).To(HaveLen(1))

			By("modifying the second IP pool")
			p2.Spec.NATOutgoing = true
			_, err = c.IPPools().Update(ctx, p2, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Delete the pools
			_, err = c.IPPools().Delete(ctx, "ippool1", options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = c.IPPools().Delete(ctx, "ippool2", options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
