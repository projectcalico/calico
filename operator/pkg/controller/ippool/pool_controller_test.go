// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package ippool

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/mock"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operator "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/render"
)

var twentySix int32 = 26

var _ = Describe("IP Pool controller tests", func() {
	var ctx context.Context
	var cancel context.CancelFunc
	var c client.Client
	var mockStatus *status.MockStatus
	var r Reconciler

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(schedv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operator.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).WithReturnManagedFields().Build()
		ctx, cancel = context.WithCancel(context.Background())

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		mockStatus = &status.MockStatus{}

		r = Reconciler{
			config:               nil, // there is no fake for config
			client:               c,
			scheme:               scheme,
			autoDetectedProvider: operator.ProviderNone,
			status:               mockStatus,
		}
	})

	AfterEach(func() {
		cancel()
	})

	It("should do nothing if there is no Installation", func() {
		mockStatus.On("OnCRNotFound")
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should wait for Installation defaulting before continuing", func() {
		instance := &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operator.InstallationSpec{
				Variant:  operator.Calico,
				Registry: "some.registry.org/",
			},
		}
		Expect(c.Create(ctx, instance)).ShouldNot(HaveOccurred())

		// Set up expected mocks.
		mockStatus.On("OnCRFound")
		mockStatus.On("SetDegraded", operator.ResourceNotReady, "Waiting for Installation defaulting to occur", nil, mock.Anything)
		mockStatus.On("SetMetaData", mock.Anything)

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should default an IPv4 pool and create it", func() {
		instance := &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Finalizers: []string{"tigera.io/operator-cleanup"},
			},
			Spec: operator.InstallationSpec{
				Variant:  operator.Calico,
				Registry: "some.registry.org/",
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
			},
		}
		createInstallation(ctx, c, instance)

		// Set up expected mocks.
		mockStatus.On("OnCRFound")
		mockStatus.On("SetMetaData", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())

		// Get the Installation.
		installation := &operator.Installation{}
		err = c.Get(ctx, utils.DefaultInstanceKey, installation)
		Expect(err).ShouldNot(HaveOccurred())

		// Verify the IP pool was defaulted onto the spec, and that nothing was recorded on the status.
		Expect(installation.Spec.CalicoNetwork.IPPools).To(HaveLen(1))
		pool := installation.Spec.CalicoNetwork.IPPools[0]
		Expect(pool.CIDR).To(Equal("192.168.0.0/16"))
		Expect(pool.Encapsulation).To(Equal(operator.EncapsulationIPIP))
		Expect(installation.Status.Defaults).To(BeNil())

		// Expect the IP pool to be created in the API server as well.
		ipPools := v3.IPPoolList{}
		err = c.List(ctx, &ipPools)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(ipPools.Items).To(HaveLen(1))
		Expect(ipPools.Items[0].Spec.CIDR).To(Equal(pool.CIDR))
	})

	It("should apply its IP pool defaults under its own field manager", func() {
		instance := &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Finalizers: []string{"tigera.io/operator-cleanup"},
			},
			Spec: operator.InstallationSpec{
				Variant:  operator.Calico,
				Registry: "some.registry.org/",
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
			},
		}
		createInstallation(ctx, c, instance)

		mockStatus.On("OnCRFound")
		mockStatus.On("SetMetaData", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())

		installation := &operator.Installation{}
		Expect(c.Get(ctx, utils.DefaultInstanceKey, installation)).ShouldNot(HaveOccurred())

		// The pools are owned by this controller's field manager, so another manager of the Installation
		// keeps the pools it declared.
		var applied *metav1.ManagedFieldsEntry
		for i := range installation.ManagedFields {
			if installation.ManagedFields[i].Manager == poolFieldManager {
				applied = &installation.ManagedFields[i]
			}
		}
		Expect(applied).NotTo(BeNil())
		Expect(applied.Operation).To(Equal(metav1.ManagedFieldsOperationApply))
		Expect(applied.FieldsV1).NotTo(BeNil())
		Expect(applied.FieldsV1.GetRawString()).To(ContainSubstring("ipPools"))
	})

	It("should keep its own default pool when it reconciles again before the computed config is republished", func() {
		instance := &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Finalizers: []string{"tigera.io/operator-cleanup"},
			},
			Spec: operator.InstallationSpec{
				Variant:  operator.Calico,
				Registry: "some.registry.org/",
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
			},
		}
		createInstallation(ctx, c, instance)

		// Use the projectcalico.org/v3 API path, so that a reconcile deciding to delete the pool
		// carries the deletion out rather than just marking the controller as degraded.
		r.clientv3 = c
		r.opts.UseV3CRDs = true

		// Set up expected mocks.
		mockStatus.On("OnCRFound")
		mockStatus.On("SetMetaData", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		// The first reconcile defaults the pool and creates it. The second stands in for the reconcile
		// triggered by that create, before the core controller has republished the computed config.
		for i := 0; i < 2; i++ {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
		}
		mockStatus.AssertExpectations(GinkgoT())

		installation := &operator.Installation{}
		err := c.Get(ctx, utils.DefaultInstanceKey, installation)
		Expect(err).ShouldNot(HaveOccurred())

		// The spec still declares the pool, rather than the empty list that means pools are managed
		// out-of-band.
		Expect(installation.Spec.CalicoNetwork.IPPools).To(HaveLen(1))
		Expect(installation.Spec.CalicoNetwork.IPPools[0].CIDR).To(Equal("192.168.0.0/16"))

		// And the pool is still in the cluster.
		ipPools := v3.IPPoolList{}
		err = c.List(ctx, &ipPools)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(ipPools.Items).To(HaveLen(1))
		Expect(ipPools.Items[0].Spec.CIDR).To(Equal("192.168.0.0/16"))
	})

	It("should re-apply the pools it owns when the spec's pool list is cleared", func() {
		instance := &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Finalizers: []string{"tigera.io/operator-cleanup"},
			},
			Spec: operator.InstallationSpec{
				Variant:  operator.Calico,
				Registry: "some.registry.org/",
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
			},
		}
		createInstallation(ctx, c, instance)

		// Use the projectcalico.org/v3 API path, so that a reconcile deciding to delete the pool
		// carries the deletion out rather than just marking the controller as degraded.
		r.clientv3 = c
		r.opts.UseV3CRDs = true

		mockStatus.On("OnCRFound")
		mockStatus.On("SetMetaData", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		// Clear the pool list. This is what a user reverting the field does, and also what an
		// Installation cache that has not caught up with this controller's own write serves.
		installation := &operator.Installation{}
		Expect(c.Get(ctx, utils.DefaultInstanceKey, installation)).ShouldNot(HaveOccurred())
		installation.Spec.CalicoNetwork.IPPools = nil
		Expect(c.Update(ctx, installation)).ShouldNot(HaveOccurred())

		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())

		// The cleared list reads as "keep what you own", not as a request to manage pools out-of-band,
		// so the pool survives and goes back on the spec.
		ipPools := v3.IPPoolList{}
		Expect(c.List(ctx, &ipPools)).ShouldNot(HaveOccurred())
		Expect(ipPools.Items).To(HaveLen(1))
		Expect(ipPools.Items[0].Spec.CIDR).To(Equal("192.168.0.0/16"))

		Expect(c.Get(ctx, utils.DefaultInstanceKey, installation)).ShouldNot(HaveOccurred())
		Expect(installation.Spec.CalicoNetwork.IPPools).To(HaveLen(1))
		Expect(installation.Spec.CalicoNetwork.IPPools[0].CIDR).To(Equal("192.168.0.0/16"))
	})

	It("should delete the pools it owns when the spec declares an empty list", func() {
		instance := &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Finalizers: []string{"tigera.io/operator-cleanup"},
			},
			Spec: operator.InstallationSpec{
				Variant:  operator.Calico,
				Registry: "some.registry.org/",
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
			},
		}
		createInstallation(ctx, c, instance)

		r.clientv3 = c
		r.opts.UseV3CRDs = true

		mockStatus.On("OnCRFound")
		mockStatus.On("SetMetaData", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		installation := &operator.Installation{}
		Expect(c.Get(ctx, utils.DefaultInstanceKey, installation)).ShouldNot(HaveOccurred())
		installation.Spec.CalicoNetwork.IPPools = []operator.IPPool{}
		updateInstallation(ctx, c, installation)

		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())

		ipPools := v3.IPPoolList{}
		Expect(c.List(ctx, &ipPools)).ShouldNot(HaveOccurred())
		Expect(ipPools.Items).To(BeEmpty())
	})

	It("should not create a default IP pool if one already exists", func() {
		instance := &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Finalizers: []string{"tigera.io/operator-cleanup"},
			},
			Spec: operator.InstallationSpec{
				Variant:  operator.Calico,
				Registry: "some.registry.org/",
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
			},
		}
		createInstallation(ctx, c, instance)

		// Create an IP pool. This simulates a user creating an IP pool before the operator has a chance to.
		ipPool := v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pool"},
			Spec:       v3.IPPoolSpec{},
		}
		Expect(c.Create(ctx, &ipPool)).ShouldNot(HaveOccurred())

		// Set up expected mocks.
		mockStatus.On("OnCRFound")
		mockStatus.On("SetMetaData", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())

		// Get the Installation.
		installation := &operator.Installation{}
		err = c.Get(ctx, utils.DefaultInstanceKey, installation)
		Expect(err).ShouldNot(HaveOccurred())

		// An explicitly empty pool list on the spec means pools are managed out-of-band.
		Expect(installation.Spec.CalicoNetwork.IPPools).To(Equal([]operator.IPPool{}))
		Expect(installation.Status.Defaults).To(BeNil())

		// No new IP pools should exist.
		ipPools := v3.IPPoolList{}
		err = c.List(ctx, &ipPools)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(ipPools.Items).To(HaveLen(1))
	})

	It("should create all IP pools provided by the user", func() {
		instance := &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Finalizers: []string{"tigera.io/operator-cleanup"},
			},
			Spec: operator.InstallationSpec{
				Variant:  operator.Calico,
				Registry: "some.registry.org/",
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{
						{CIDR: "192.168.0.0/16"},
						{CIDR: "172.15.0.0/16"},
						{CIDR: "dead:beef::/64"},
						{CIDR: "fd5f:abcd::/64"},
					},
				},
			},
		}
		createInstallation(ctx, c, instance)

		// Set up expected mocks.
		mockStatus.On("OnCRFound")
		mockStatus.On("SetMetaData", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())

		// Expect all IP pools to have been created.
		ipPools := v3.IPPoolList{}
		err = c.List(ctx, &ipPools)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(ipPools.Items).To(HaveLen(len(instance.Spec.CalicoNetwork.IPPools)))

		// Verify basic data about the created pools.
		poolsByCIDR := map[string]v3.IPPool{}
		for _, pool := range ipPools.Items {
			poolsByCIDR[pool.Spec.CIDR] = pool
		}
		for _, pool := range instance.Spec.CalicoNetwork.IPPools {
			Expect(poolsByCIDR).To(HaveKey(pool.CIDR))
			Expect(poolsByCIDR[pool.CIDR].Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "tigera-operator"))
		}
	})

	It("should disallow modification if there is no API server", func() {
		instance := &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Finalizers: []string{"tigera.io/operator-cleanup"},
			},
			Spec: operator.InstallationSpec{
				Variant:  operator.Calico,
				Registry: "some.registry.org/",
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{
						{CIDR: "192.168.0.0/16", NATOutgoing: "Disabled"},
					},
				},
			},
		}
		createInstallation(ctx, c, instance)

		// Set up expected mocks.
		mockStatus.On("OnCRFound")
		mockStatus.On("SetMetaData", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())

		// Now, modify the IP pool. This should be rejected, because we only allow modification
		// when the API server is available.
		Expect(c.Get(ctx, utils.DefaultInstanceKey, instance)).ShouldNot(HaveOccurred())
		instance.Spec.CalicoNetwork.IPPools[0].NATOutgoing = "Enabled"
		updateInstallation(ctx, c, instance)

		// Expect a new SetDegraded call.
		mockStatus.On("SetDegraded", operator.ResourceNotReady, "Unable to modify IP pools while Calico API server is unavailable", nil, mock.Anything)
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should disallow deletion if there is no API server", func() {
		instance := &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Finalizers: []string{"tigera.io/operator-cleanup"},
			},
			Spec: operator.InstallationSpec{
				Variant:  operator.Calico,
				Registry: "some.registry.org/",
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{
						{CIDR: "192.168.0.0/16", NATOutgoing: "Disabled"},
					},
				},
			},
		}
		createInstallation(ctx, c, instance)

		// Set up expected mocks.
		mockStatus.On("OnCRFound")
		mockStatus.On("SetMetaData", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())

		// Now, delete the IP pool. This should be rejected, because we only allow deletion
		// when the API server is available.
		Expect(c.Get(ctx, utils.DefaultInstanceKey, instance)).ShouldNot(HaveOccurred())
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{}
		updateInstallation(ctx, c, instance)

		// Assert SetDegraded is called as expected.
		mockStatus.On("SetDegraded", operator.ResourceNotReady, "Unable to delete IP pools while Calico API server is unavailable", nil, mock.Anything)
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())

		// Expect the IP pool to still exist.
		ipPools := v3.IPPoolList{}
		err = c.List(ctx, &ipPools)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(ipPools.Items).To(HaveLen(1))
	})

	It("should not delete and recreate a pool when the Installation uses a non-canonical IPv6 CIDR", func() {
		// Regression test for https://github.com/projectcalico/calico/operator/issues/4783.
		// The Calico API server stores IP pool CIDRs in canonical form, so a pool created from a
		// non-canonical CIDR in the Installation is persisted with a different textual representation
		// (e.g. with leading zeros stripped). The operator must treat the two as the same pool;
		// otherwise it repeatedly marks the pool for deletion and recreates it in an infinite loop.
		const nonCanonicalCIDR = "fd20:5213:94f6:01e9:001f::/96"
		const canonicalCIDR = "fd20:5213:94f6:1e9:1f::/96"

		instance := &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Finalizers: []string{"tigera.io/operator-cleanup"},
			},
			Spec: operator.InstallationSpec{
				Variant:  operator.Calico,
				Registry: "some.registry.org/",
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{
						{CIDR: nonCanonicalCIDR},
					},
				},
			},
		}
		createInstallation(ctx, c, instance)

		// Simulate a pool that the API server already normalized to its canonical form and that is
		// owned by the operator (as indicated by the managed-by label).
		existing := &v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "default-ipv6-ippool",
				Labels: map[string]string{managedByLabel: managedByValue},
			},
			Spec: v3.IPPoolSpec{CIDR: canonicalCIDR},
		}
		Expect(c.Create(ctx, existing)).ShouldNot(HaveOccurred())

		// Use the projectcalico.org/v3 API path so that, prior to the fix, the spurious deletion
		// would actually be carried out rather than just marking the controller as degraded.
		r.clientv3 = c
		r.opts.UseV3CRDs = true

		mockStatus.On("OnCRFound")
		mockStatus.On("SetMetaData", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		// Reconcile a couple of times to confirm we reach a steady state and aren't looping.
		for i := 0; i < 2; i++ {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
		}
		mockStatus.AssertExpectations(GinkgoT())

		// The pool must still exist exactly once, retaining its canonical CIDR, and must not have
		// been deleted and recreated.
		ipPools := v3.IPPoolList{}
		Expect(c.List(ctx, &ipPools)).ShouldNot(HaveOccurred())
		Expect(ipPools.Items).To(HaveLen(1))
		Expect(ipPools.Items[0].Spec.CIDR).To(Equal(canonicalCIDR))
	})
})

var _ = DescribeTable("cidrWithinCidr",
	func(CIDR, pool string, expectedResult bool) {
		if expectedResult {
			Expect(cidrWithinCidr(CIDR, pool)).To(BeTrue(), "Expected pool %s to be within CIDR %s", pool, CIDR)
		} else {
			Expect(cidrWithinCidr(CIDR, pool)).To(BeFalse(), "Expected pool %s to not be within CIDR %s", pool, CIDR)
		}
	},

	Entry("Default as CIDR and pool", "192.168.0.0/16", "192.168.0.0/16", true),
	Entry("Pool larger than CIDR should fail", "192.168.0.0/16", "192.168.0.0/15", false),
	Entry("Pool larger than CIDR should fail", "192.168.2.0/24", "192.168.0.0/16", false),
	Entry("Non overlapping CIDR and pool should fail", "192.168.0.0/16", "172.168.0.0/16", false),
	Entry("CIDR with smaller pool", "192.168.0.0/16", "192.168.2.0/24", true),
	Entry("IPv6 matching CIDR and pool", "fd00:1234::/32", "fd00:1234::/32", true),
	Entry("IPv6 Pool larger than CIDR should fail", "fd00:1234::/32", "fd00:1234::/31", false),
	Entry("IPv6 Pool larger than CIDR should fail", "fd00:1234:5600::/40", "fd00:1234::/32", false),
	Entry("IPv6 Non overlapping CIDR and pool should fail", "fd00:1234::/32", "fd00:5678::/32", false),
	Entry("IPv6 CIDR with smaller pool", "fd00:1234::/32", "fd00:1234:5600::/40", true),
)

var _ = DescribeTable("Test OpenShift IP pool defaulting",
	func(i *operator.Installation, on *configv1.Network, expectSuccess bool, expected *operator.CalicoNetworkSpec) {
		// Perform test setup.
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(configv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operator.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		ctx := context.Background()
		if on != nil {
			on.Name = "cluster"
			Expect(cli.Create(ctx, on)).To(BeNil())
		}
		currentPools := &v3.IPPoolList{}

		// The core Installation controller will normally handle defaulting the provider based on user input and
		// auto-detected cluster information. For this test, explicitly set it to OpenShift.
		i.Spec.KubernetesProvider = operator.ProviderOpenShift

		// Fill in prerequisite defaults.
		fillPrerequisiteDefaults(i)

		// Run the test.
		if expectSuccess {
			Expect(fillDefaults(ctx, cli, &i.Spec, currentPools)).To(BeNil())
		} else {
			Expect(fillDefaults(ctx, cli, &i.Spec, currentPools)).NotTo(BeNil())
			return
		}

		if expected == nil {
			Expect(i.Spec.CalicoNetwork).To(BeNil())
			return
		}
		if expected.IPPools == nil {
			Expect(i.Spec.CalicoNetwork).To(BeNil())
			return
		}
		if len(expected.IPPools) == 0 {
			Expect(i.Spec.CalicoNetwork.IPPools).To(HaveLen(0))
			return
		}

		Expect(i.Spec.CalicoNetwork.IPPools).To(HaveLen(1))

		pool := i.Spec.CalicoNetwork.IPPools[0]
		expectedPool := expected.IPPools[0]
		Expect(pool).To(Equal(expectedPool))
	},

	Entry("Empty config (with OpenShift) defaults IPPool", &operator.Installation{},
		&configv1.Network{
			Spec: configv1.NetworkSpec{
				ClusterNetwork: []configv1.ClusterNetworkEntry{
					{CIDR: "192.168.0.0/16"},
				},
			},
		},
		true,
		&operator.CalicoNetworkSpec{
			IPPools: []operator.IPPool{
				{
					Name:                  "default-ipv4-ippool",
					CIDR:                  "192.168.0.0/16",
					Encapsulation:         "IPIP",
					NATOutgoing:           "Enabled",
					NodeSelector:          "all()",
					BlockSize:             &twentySix,
					AllowedUses:           []operator.IPPoolAllowedUse{operator.IPPoolAllowedUseWorkload, operator.IPPoolAllowedUseTunnel},
					DisableNewAllocations: &false_,
					AssignmentMode:        "Automatic",
				},
			},
		}),

	Entry("Openshift only CIDR",
		&operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{},
			},
		},
		&configv1.Network{
			Spec: configv1.NetworkSpec{
				ClusterNetwork: []configv1.ClusterNetworkEntry{
					{CIDR: "10.0.0.0/8"},
				},
			},
		},
		true,
		&operator.CalicoNetworkSpec{
			IPPools: []operator.IPPool{
				{
					Name:                  "default-ipv4-ippool",
					CIDR:                  "10.0.0.0/8",
					Encapsulation:         "IPIP",
					NATOutgoing:           "Enabled",
					NodeSelector:          "all()",
					BlockSize:             &twentySix,
					AllowedUses:           []operator.IPPoolAllowedUse{operator.IPPoolAllowedUseWorkload, operator.IPPoolAllowedUseTunnel},
					DisableNewAllocations: &false_,
					AssignmentMode:        "Automatic",
				},
			},
		}),

	Entry("CIDR specified from OpenShift config and Calico config",
		&operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{
						{
							CIDR:          "10.0.0.0/24",
							Encapsulation: "VXLAN",
							NATOutgoing:   "Disabled",
						},
					},
				},
			},
		},
		&configv1.Network{
			Spec: configv1.NetworkSpec{
				ClusterNetwork: []configv1.ClusterNetworkEntry{
					{CIDR: "10.0.0.0/8"},
				},
			},
		},
		true,
		&operator.CalicoNetworkSpec{
			IPPools: []operator.IPPool{
				{
					Name:                  "default-ipv4-ippool",
					CIDR:                  "10.0.0.0/24",
					Encapsulation:         "VXLAN",
					NATOutgoing:           "Disabled",
					NodeSelector:          "all()",
					BlockSize:             &twentySix,
					AllowedUses:           []operator.IPPoolAllowedUse{operator.IPPoolAllowedUseWorkload, operator.IPPoolAllowedUseTunnel},
					DisableNewAllocations: &false_,
					AssignmentMode:        "Automatic",
				},
			},
		}),

	Entry("Failure when IPPool is smaller than OpenShift Network",
		&operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{
						{
							CIDR:          "10.0.0.0/16",
							Encapsulation: "VXLAN",
							NATOutgoing:   "Disabled",
						},
					},
				},
			},
		},
		&configv1.Network{
			Spec: configv1.NetworkSpec{
				ClusterNetwork: []configv1.ClusterNetworkEntry{
					{CIDR: "10.0.0.0/24"},
				},
			},
		},
		false,
		nil,
	),

	Entry("Empty IPPool list results in no IPPool with OpenShift",
		&operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{},
				},
			},
		},
		&configv1.Network{
			Spec: configv1.NetworkSpec{
				ClusterNetwork: []configv1.ClusterNetworkEntry{
					{CIDR: "10.0.0.0/8"},
				},
			},
		},
		true,
		&operator.CalicoNetworkSpec{
			IPPools: []operator.IPPool{},
		},
	),

	Entry("No OpenShift configuration provided",
		&operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{},
			},
		},
		nil,
		false,
		nil,
	),
)

var _ = Describe("fillDefaults()", func() {
	var cli client.Client
	var ctx context.Context
	var currentPools *v3.IPPoolList
	var instance *operator.Installation

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(configv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operator.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
		ctx = context.Background()
	})

	It("should reject an IP pool with no Encapsulation", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{
						{CIDR: "192.168.0.0/16"},
					},
				},
			},
		}

		// Fill defaults to make sure we pass other validation. Then remove the Encapsulation.
		// Fill in prerequisite defaults.
		fillPrerequisiteDefaults(instance)
		Expect(fillDefaults(ctx, cli, &instance.Spec, currentPools)).ToNot(HaveOccurred())
		instance.Spec.CalicoNetwork.IPPools[0].Encapsulation = ""

		err := ValidatePools(&instance.Spec)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("is invalid for ipPool.encapsulation, should be one of"))
	})

	// This table verifies that kubernetes provider configuration is accounted for in defaulting. Specifically, it
	// makes sure that defaulting takes OpenShift config.Network and the kubeadm configmap into account.
	DescribeTable("incorporation of kubernetesProvider config",
		func(i *operator.Installation, openshift *configv1.Network, kubeadm *v1.ConfigMap) {
			// Create the provided kubernetes provider configurations in the fake client.
			if openshift != nil {
				openshift.Name = "cluster"
				Expect(cli.Create(ctx, openshift)).ToNot(HaveOccurred())
			}
			if kubeadm != nil {
				kubeadm.Name = kubeadmConfigMap
				kubeadm.Namespace = metav1.NamespaceSystem
				Expect(cli.Create(ctx, kubeadm)).ToNot(HaveOccurred())
			}

			// Fill in prerequisite defaults.
			fillPrerequisiteDefaults(i)

			// Run the defaulting function under test.
			Expect(fillDefaults(ctx, cli, &i.Spec, currentPools)).ToNot(HaveOccurred())

			if i.Spec.CalicoNetwork != nil && i.Spec.CalicoNetwork.IPPools != nil && len(i.Spec.CalicoNetwork.IPPools) != 0 {
				v4pool := poolOfFamily(i.Spec.CalicoNetwork.IPPools, render.IsIPv4Pool)
				Expect(v4pool).ToNot(BeNil())
				Expect(v4pool.CIDR).ToNot(BeEmpty(), "CIDR should be set on pool %v", v4pool)
				Expect(v4pool.Encapsulation).To(BeElementOf(operator.EncapsulationTypes), "Encapsulation should be set on pool %q", v4pool)
				Expect(v4pool.NATOutgoing).To(BeElementOf(operator.NATOutgoingTypes), "NATOutgoing should be set on pool %v", v4pool)
				Expect(v4pool.NodeSelector).ToNot(BeEmpty(), "NodeSelector should be set on pool %v", v4pool)

				v6pool := poolOfFamily(i.Spec.CalicoNetwork.IPPools, render.IsIPv6Pool)
				Expect(v6pool).To(BeNil())
			}

			// Assert the resulting Installation is valid.
			Expect(ValidatePools(&i.Spec)).NotTo(HaveOccurred())
		},

		Entry("Empty config defaults IPPool", &operator.Installation{}, nil, nil),

		Entry("Openshift only CIDR",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{},
				},
			}, &configv1.Network{
				Spec: configv1.NetworkSpec{
					ClusterNetwork: []configv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			},
			nil,
		),

		Entry("CIDR specified from OS config and Calico config",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							{CIDR: "10.0.0.0/24"},
						},
					},
				},
			}, &configv1.Network{
				Spec: configv1.NetworkSpec{
					ClusterNetwork: []configv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			},
			nil,
		),

		Entry("kubeadm only CIDR",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{},
				},
			},
			nil,
			&v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: 10.0.0.0/8"}},
		),

		Entry("CIDR specified from kubeadm config and Calico config",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							{CIDR: "10.0.0.0/24"},
						},
					},
				},
			},
			nil,
			&v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: 10.0.0.0/8"}},
		),
	)

	It("should properly fill defaults for an IPv6-only instance", func() {
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{{CIDR: "fd00::0/64"}},
				},
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
			},
		}

		err := fillDefaults(ctx, cli, &instance.Spec, currentPools)
		Expect(err).NotTo(HaveOccurred())
		Expect(instance.Spec.CalicoNetwork.IPPools).To(HaveLen(1))

		v4pool := poolOfFamily(instance.Spec.CalicoNetwork.IPPools, render.IsIPv4Pool)
		Expect(v4pool).To(BeNil())

		v6pool := poolOfFamily(instance.Spec.CalicoNetwork.IPPools, render.IsIPv6Pool)
		Expect(v6pool).NotTo(BeNil())
		Expect(v6pool.CIDR).To(Equal("fd00::0/64"))
		Expect(v6pool.BlockSize).NotTo(BeNil())
		Expect(*v6pool.BlockSize).To(Equal(int32(122)))

		Expect(ValidatePools(&instance.Spec)).NotTo(HaveOccurred())
	})

	// Tests for Calico Networking on EKS should go in this context.
	Context("with Calico Networking on EKS", func() {
		BeforeEach(func() {
			instance = &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderEKS,
					CNI: &operator.CNISpec{
						Type: operator.PluginCalico,
						IPAM: &operator.IPAMSpec{
							Type: operator.IPAMPluginCalico,
						},
					},
				},
			}
		})

		It("should default properly", func() {
			err := fillDefaults(ctx, cli, &instance.Spec, currentPools)
			Expect(err).NotTo(HaveOccurred())
			Expect(instance.Spec.CalicoNetwork.IPPools[0].Encapsulation).To(Equal(operator.EncapsulationVXLAN))
			Expect(instance.Spec.CalicoNetwork.IPPools[0].CIDR).To(Equal("172.16.0.0/16"))
			Expect(ValidatePools(&instance.Spec)).NotTo(HaveOccurred())
		})
	})
})

var _ = Describe("ownedPoolMembership()", func() {
	ownedPool := func(cidr string) v3.IPPool {
		return v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "owned",
				Labels: map[string]string{managedByLabel: managedByValue},
			},
			Spec: v3.IPPoolSpec{CIDR: cidr},
		}
	}

	It("should return nil when the cluster has no pools", func() {
		Expect(ownedPoolMembership(nil)).To(BeNil())
		Expect(ownedPoolMembership(&v3.IPPoolList{})).To(BeNil())
	})

	It("should return the pools the operator owns", func() {
		pools := &v3.IPPoolList{Items: []v3.IPPool{ownedPool("192.168.0.0/16")}}
		membership := ownedPoolMembership(pools)
		Expect(membership).To(HaveLen(1))
		Expect(membership[0].CIDR).To(Equal("192.168.0.0/16"))
	})

	It("should return an empty list when any pool is unowned", func() {
		unowned := v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: "theirs"},
			Spec:       v3.IPPoolSpec{CIDR: "10.0.0.0/16"},
		}
		pools := &v3.IPPoolList{Items: []v3.IPPool{ownedPool("192.168.0.0/16"), unowned}}
		Expect(ownedPoolMembership(pools)).To(Equal([]operator.IPPool{}))
	})
})

var _ = Describe("validate()", func() {
	var instance *operator.Installation

	BeforeEach(func() {
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{},
				Variant:       operator.Calico,
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
			},
		}
	})

	It("should not allow blocksize to exceed the pool size", func() {
		// Try with an invalid block size.
		var twentySix int32 = 26
		instance.Spec.CalicoNetwork.BGP = ptr.To(operator.BGPEnabled)
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.168.0.0/27",
				BlockSize:     &twentySix,
				Encapsulation: operator.EncapsulationNone,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := ValidatePools(&instance.Spec)
		Expect(err).To(HaveOccurred())

		// Try with a valid block size
		instance.Spec.CalicoNetwork.IPPools[0].CIDR = "192.168.0.0/26"
		err = ValidatePools(&instance.Spec)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not allow out-of-bounds block sizes", func() {
		// Try with an invalid block size.
		var blockSizeTooBig int32 = 33
		var blockSizeTooSmall int32 = 19
		var blockSizeJustRight int32 = 32

		// Start with a valid block size - /32 - just on the border.
		instance.Spec.CalicoNetwork.BGP = ptr.To(operator.BGPEnabled)
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.0.0.0/8",
				BlockSize:     &blockSizeJustRight,
				Encapsulation: operator.EncapsulationNone,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := ValidatePools(&instance.Spec)
		Expect(err).NotTo(HaveOccurred())

		// Try with out-of-bounds sizes now.
		instance.Spec.CalicoNetwork.IPPools[0].BlockSize = &blockSizeTooBig
		err = ValidatePools(&instance.Spec)
		Expect(err).To(HaveOccurred())
		instance.Spec.CalicoNetwork.IPPools[0].BlockSize = &blockSizeTooSmall
		err = ValidatePools(&instance.Spec)
		Expect(err).To(HaveOccurred())
	})
})

// fillPrerequisiteDefaults fills in some defaults the IP pool controller relies on.
// This mimics the behavior of the core Installation controller by setting some defaults that the IP pool
// controller relies on.
func fillPrerequisiteDefaults(i *operator.Installation) {
	if i.Spec.CalicoNetwork == nil {
		i.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
	}
	if i.Spec.CNI == nil {
		i.Spec.CNI = &operator.CNISpec{}
	}
	if i.Spec.CNI.IPAM == nil {
		i.Spec.CNI.IPAM = &operator.IPAMSpec{}
	}
	if i.Spec.CNI.Type == "" {
		i.Spec.CNI.Type = operator.PluginCalico
	}
	if i.Spec.CNI.IPAM.Type == "" {
		i.Spec.CNI.IPAM.Type = operator.IPAMPluginCalico
	}
}

// createInstallation creates the Installation with its effective config published on the status.
// poolOfFamily returns the one pool matching the family predicate. These tests never declare two
// pools of the same family, so a second match is a bug in the test rather than a choice to make.
func poolOfFamily(pools []operator.IPPool, matches func(operator.IPPool) bool) *operator.IPPool {
	var found *operator.IPPool
	for i := range pools {
		if !matches(pools[i]) {
			continue
		}

		ExpectWithOffset(1, found).To(BeNil(), "more than one pool of the same family")
		found = &pools[i]
	}
	return found
}

func createInstallation(ctx context.Context, c client.Client, instance *operator.Installation) {
	instance.Status.Computed = instance.Spec.DeepCopy()
	ExpectWithOffset(1, c.Create(ctx, instance)).ShouldNot(HaveOccurred())
}

// updateInstallation writes the spec and republishes it on the status, as the core controller does.
func updateInstallation(ctx context.Context, c client.Client, instance *operator.Installation) {
	ExpectWithOffset(1, c.Update(ctx, instance)).ShouldNot(HaveOccurred())
	instance.Status.Computed = instance.Spec.DeepCopy()
	ExpectWithOffset(1, c.Status().Update(ctx, instance)).ShouldNot(HaveOccurred())
}
