// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package test

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/elastic/cloud-on-k8s/v2/pkg/utils/maps"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
)

// This test suite covers the installation of IP pools. The vast majority should be covered in the pkg/controller/ippool UTs
// However, the defaulting behavior for the Installation resource is split between the core installation
// controller and the IP pool controller, making an FV appropriate for testing those interactions.
var _ = Describe("IPPool FV tests", func() {
	var c client.Client
	var clientv3 client.Client
	var mgr manager.Manager
	var shutdownContext context.Context
	var cancel context.CancelFunc
	var operatorDone chan struct{}

	BeforeEach(func() {
		c, shutdownContext, cancel, mgr = setupManager(ManageCRDsDisable, SingleTenant, operator.Calico)

		// We need a v3 client as well.
		var err error
		clientv3, err = utils.V3Client(mgr.GetConfig())
		Expect(err).NotTo(HaveOccurred())

		By("Cleaning up resources before the test")
		cleanupResources(c)

		By("Verifying CRDs are installed")
		verifyCRDsExist(c, operator.CalicoEnterprise)

		By("Creating the tigera-operator namespace, if it doesn't exist")
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator"},
			Spec:       corev1.NamespaceSpec{},
		}
		err = c.Create(context.Background(), ns)
		if err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}

		By("Checking no Installation is left over from previous tests")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err = c.Get(context.Background(), types.NamespacedName{Name: "default"}, instance)
		Expect(errors.IsNotFound(err)).To(BeTrue(), fmt.Sprintf("Expected Installation not to exist, but got: %s", err))
	})

	AfterEach(func() {
		defer func() {
			By("shutting down the operator")
			cancel()
			Eventually(func() error {
				select {
				case <-operatorDone:
					return nil
				default:
					return fmt.Errorf("operator did not shutdown")
				}
			}, 60*time.Second).ShouldNot(HaveOccurred())
		}()

		By("Cleaning up resources after the test")
		cleanupResources(c)

		// Clean up Calico data that might be left behind.
		By("Cleaning up Node annotations after test")
		Eventually(func() error {
			cs := kubernetes.NewForConfigOrDie(mgr.GetConfig())
			nodes, err := cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				return err
			}
			if len(nodes.Items) == 0 {
				return fmt.Errorf("No nodes found")
			}
			for _, n := range nodes.Items {
				for k := range n.ObjectMeta.Annotations {
					if strings.Contains(k, "projectcalico") {
						delete(n.ObjectMeta.Annotations, k)
					}
				}
				_, err = cs.CoreV1().Nodes().Update(context.Background(), &n, metav1.UpdateOptions{})
				if err != nil {
					return err
				}
			}
			return nil
		}, 30*time.Second).Should(BeNil())

		mgr = nil
	})

	It("Should install default IP pools", func() {
		operatorDone = createInstallation(c, mgr, shutdownContext, nil)
		verifyCalicoHasDeployed(c)

		// Get IP pools installed in the cluster.
		ipPools := &v3.IPPoolList{}
		Eventually(func() error {
			return c.List(context.Background(), ipPools)
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())

		// We should have one v4 and one v6 pool, based on the kubeadm config in the cluster.
		Expect(len(ipPools.Items)).To(Equal(2), fmt.Sprintf("Expected 2 IP pools, but got: %+v", ipPools.Items))

		// Verify that a default IPv4 pool was created.
		Expect(ipPools.Items[0].Name).To(Equal("default-ipv4-ippool"))
		Expect(ipPools.Items[0].Spec.CIDR).To(Equal("192.168.0.0/16"))
		Expect(ipPools.Items[0].Spec.NATOutgoing).To(Equal(true))
		Expect(ipPools.Items[0].Spec.Disabled).To(Equal(false))
		Expect(ipPools.Items[0].Spec.BlockSize).To(Equal(26))
		Expect(ipPools.Items[0].Spec.NodeSelector).To(Equal("all()"))
		Expect(*ipPools.Items[0].Spec.AssignmentMode).To(Equal(v3.Automatic))

		// Verify that a default IPv6 pool was created.
		Expect(ipPools.Items[1].Name).To(Equal("default-ipv6-ippool"))
		Expect(ipPools.Items[1].Spec.CIDR).To(Equal("fd00:10:244::/64"))
		Expect(ipPools.Items[1].Spec.NATOutgoing).To(Equal(false))
		Expect(ipPools.Items[1].Spec.Disabled).To(Equal(false))
		Expect(ipPools.Items[1].Spec.BlockSize).To(Equal(122))
		Expect(ipPools.Items[1].Spec.NodeSelector).To(Equal("all()"))
		Expect(*ipPools.Items[1].Spec.AssignmentMode).To(Equal(v3.Automatic))

		// Expect the default pools to be marked as managed by the operator.
		for _, p := range ipPools.Items {
			Expect(p.Labels).To(HaveKey("app.kubernetes.io/managed-by"))
		}
	})

	It("should not default pools if explicit pools are given", func() {
		// Specify a single IPv4 pool within the cluster CIDR. This should prevent the operator from creating the defaulting
		// pools, but still allow Calico to deploy.
		spec := operator.InstallationSpec{
			CalicoNetwork: &operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{
					{
						Name:          "my-pool-name",
						CIDR:          "192.168.0.0/24",
						Encapsulation: operator.EncapsulationNone,
					},
				},
			},
		}
		operatorDone = createInstallation(c, mgr, shutdownContext, &spec)
		verifyCalicoHasDeployed(c)

		// Get IP pools installed in the cluster.
		ipPools := &v3.IPPoolList{}
		Eventually(func() error {
			return c.List(context.Background(), ipPools)
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())

		Expect(len(ipPools.Items)).To(Equal(1), fmt.Sprintf("Expected 1 IP pool, but got: %+v", ipPools.Items))

		// Verify that a default IPv4 pool was created.
		Expect(ipPools.Items[0].Name).To(Equal("my-pool-name"))
		Expect(ipPools.Items[0].Spec.CIDR).To(Equal("192.168.0.0/24"))
		Expect(ipPools.Items[0].Spec.NATOutgoing).To(Equal(true))
		Expect(ipPools.Items[0].Spec.Disabled).To(Equal(false))
		Expect(ipPools.Items[0].Spec.BlockSize).To(Equal(26))
		Expect(ipPools.Items[0].Spec.NodeSelector).To(Equal("all()"))
		Expect(ipPools.Items[0].Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "tigera-operator"))
		Expect(*ipPools.Items[0].Spec.AssignmentMode).To(Equal(v3.Automatic))
	})

	It("should assume ownership of legacy default IP pools", func() {
		// Create an IP pool directly - this simulates a pre-existing IP pool created by Calico prior to
		// the operator supporting direct IP pool management.
		ipPool := v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: "default-ipv4-ippool"},
			Spec: v3.IPPoolSpec{
				CIDR:             "192.168.0.0/24",
				IPIPMode:         v3.IPIPModeAlways,
				VXLANMode:        v3.VXLANModeNever,
				BlockSize:        26,
				NATOutgoing:      true,
				NodeSelector:     "all()",
				DisableBGPExport: false,
				AllowedUses: []v3.IPPoolAllowedUse{
					v3.IPPoolAllowedUseWorkload,
					v3.IPPoolAllowedUseTunnel,
				},
				AssignmentMode: ptr.To(v3.Automatic),
			},
		}
		Expect(c.Create(context.Background(), &ipPool)).To(Succeed())

		// Create an Installation referencing the IP pool by CIDR, mimicing the upgrade case. We expect
		// the operator to assume ownership of the IP pool, filling in any missing fields and updating the
		// IP pool in the cluster to match the given configuration.
		spec := operator.InstallationSpec{
			CalicoNetwork: &operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{
					{
						CIDR:          "192.168.0.0/24",
						Encapsulation: operator.EncapsulationIPIP,
					},
				},
			},
		}
		operatorDone = createInstallation(c, mgr, shutdownContext, &spec)
		verifyCalicoHasDeployed(c)

		// Query the Installation and verify the IP pool name has been defaulted.
		instance := &operator.Installation{}
		Eventually(func() error {
			if err := c.Get(context.Background(), types.NamespacedName{Name: "default"}, instance); err != nil {
				return err
			}
			if instance.Status.Computed == nil || instance.Status.Computed.CalicoNetwork == nil {
				return fmt.Errorf("Installation defaults have not been recorded yet")
			}
			pools := instance.Status.Computed.CalicoNetwork.IPPools
			if len(pools) != 1 || pools[0].Name == "" {
				return fmt.Errorf("IP pool defaults have not been recorded yet: %+v", pools)
			}
			return nil
		}, 30*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
		Expect(instance.Spec.CalicoNetwork.IPPools[0].Name).To(BeEmpty())
		Expect(instance.Status.Computed.CalicoNetwork.IPPools).To(HaveLen(1))
		Expect(instance.Status.Computed.CalicoNetwork.IPPools[0].Name).To(Equal("default-ipv4-ippool"))

		// In order to modify IP pools, the operator needs the API server. We can assert the IP pool has not yet
		// been controlled by the operator at this point.

		// Get IP pools installed in the cluster.
		ipPools := &v3.IPPoolList{}
		Eventually(func() error {
			return c.List(context.Background(), ipPools)
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())

		Expect(len(ipPools.Items)).To(Equal(1), fmt.Sprintf("Expected 1 IP pool, but got: %+v", ipPools.Items))

		// This proves the operator has not assumed control.
		Expect(ipPools.Items[0].Labels).NotTo(HaveKey("app.kubernetes.io/managed-by"))

		// Now, install the API server.
		createAPIServer(c, mgr, shutdownContext, nil)
		verifyAPIServerHasDeployed(c)

		// We can now query using the v3 API!
		// This proves that the operator has assumed ownership of the legacy IP pool.
		v3Pools := &v3.IPPoolList{}
		Eventually(func() error {
			err := clientv3.List(context.Background(), v3Pools)
			if err != nil {
				return err
			}
			if len(v3Pools.Items) != 1 {
				return fmt.Errorf("Expected 1 IP pool, but got: %+v", v3Pools.Items)
			}
			if !maps.ContainsKeys(v3Pools.Items[0].Labels, "app.kubernetes.io/managed-by") {
				return fmt.Errorf("Expected app.kubernetes.io/managed-by label, but got: %+v", v3Pools.Items[0].Labels)
			}
			return nil
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())

		// Verify that the default IPv4 pool has been subsumed by the operator.
		Expect(v3Pools.Items[0].Name).To(Equal("default-ipv4-ippool"))
		Expect(v3Pools.Items[0].Spec.CIDR).To(Equal("192.168.0.0/24"))
		Expect(v3Pools.Items[0].Spec.NATOutgoing).To(Equal(true))
		Expect(v3Pools.Items[0].Spec.Disabled).To(Equal(false))
		Expect(v3Pools.Items[0].Spec.BlockSize).To(Equal(26))
		Expect(v3Pools.Items[0].Spec.NodeSelector).To(Equal("all()"))
		Expect(v3Pools.Items[0].Spec.IPIPMode).To(Equal(v3.IPIPMode(v3.IPIPModeAlways)))
		Expect(v3Pools.Items[0].Spec.VXLANMode).To(Equal(v3.VXLANMode(v3.VXLANModeNever)))
		Expect(*ipPools.Items[0].Spec.AssignmentMode).To(Equal(v3.Automatic))
	})

	// This test verifies that the IP pool controller doesn't assume ownership of IP pools that may exist in the
	// Installation spec, but that do not match exactly. This ensures that we don't accidentally reconcile away changes
	// that a user made to an IP pool created by the operator but prior to this controller existing.
	It("should NOT assume ownership of modified IP pools on upgrade", func() {
		// Create an IP pool directly - this simulates a pre-existing IP pool created by Calico prior to
		// the operator supporting direct IP pool management.
		ipPool := v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: "default-ipv4-ippool"},
			Spec: v3.IPPoolSpec{
				CIDR:             "192.168.0.0/24",
				IPIPMode:         v3.IPIPModeAlways,
				VXLANMode:        v3.VXLANModeNever,
				BlockSize:        26,
				NATOutgoing:      true,
				DisableBGPExport: false,
				AllowedUses: []v3.IPPoolAllowedUse{
					v3.IPPoolAllowedUseWorkload,
					v3.IPPoolAllowedUseTunnel,
				},
				// Use a non-default selector. This mimics a user modifying the IP pool after it was created,
				// since we will use the default selector in the Installation spec.
				NodeSelector: "has(kubernetes.io/os)",
			},
		}
		Expect(c.Create(context.Background(), &ipPool)).To(Succeed())

		// Create an Installation referencing the IP pool by CIDR, mimicking the upgrade case. We expect
		// the operator to default the IP pool, filling in any missing fields. But it won't
		// update IP pool in the cluster since it doesn't match exactly.
		spec := operator.InstallationSpec{
			CalicoNetwork: &operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{
					{
						CIDR:          "192.168.0.0/24",
						Encapsulation: operator.EncapsulationIPIP,
					},
				},
			},
		}
		operatorDone = createInstallation(c, mgr, shutdownContext, &spec)
		verifyCalicoHasDeployed(c)

		// Query the Installation and verify the IP pool name has been defaulted.
		instance := &operator.Installation{}
		Eventually(func() error {
			if err := c.Get(context.Background(), types.NamespacedName{Name: "default"}, instance); err != nil {
				return err
			}
			if instance.Status.Computed == nil || instance.Status.Computed.CalicoNetwork == nil {
				return fmt.Errorf("Installation defaults have not been recorded yet")
			}
			pools := instance.Status.Computed.CalicoNetwork.IPPools
			if len(pools) != 1 || pools[0].Name == "" {
				return fmt.Errorf("IP pool defaults have not been recorded yet: %+v", pools)
			}
			return nil
		}, 30*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
		Expect(instance.Spec.CalicoNetwork.IPPools[0].Name).To(BeEmpty())
		Expect(instance.Status.Computed.CalicoNetwork.IPPools).To(HaveLen(1))
		Expect(instance.Status.Computed.CalicoNetwork.IPPools[0].Name).To(Equal("default-ipv4-ippool"))
		Expect(instance.Status.Computed.CalicoNetwork.IPPools[0].NodeSelector).To(Equal("all()"))

		// In order to modify IP pools, the operator needs the API server. We can assert the IP pool has not yet
		// been controlled by the operator at this point.

		// Get IP pools installed in the cluster.
		ipPools := &v3.IPPoolList{}
		Eventually(func() error {
			return c.List(context.Background(), ipPools)
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())

		Expect(len(ipPools.Items)).To(Equal(1), fmt.Sprintf("Expected 1 IP pool, but got: %+v", ipPools.Items))

		// This proves the operator has not assumed control.
		Expect(ipPools.Items[0].Labels).NotTo(HaveKey("app.kubernetes.io/managed-by"))

		// Now, install the API server.
		createAPIServer(c, mgr, shutdownContext, nil)
		verifyAPIServerHasDeployed(c)

		// We can now query using the v3 API!
		// Verify that the IP pool has not been modified by the operator.
		v3Pools := &v3.IPPoolList{}
		Consistently(func() error {
			err := clientv3.List(context.Background(), v3Pools)
			if err != nil {
				return err
			}
			if len(v3Pools.Items) != 1 {
				return fmt.Errorf("Expected 1 IP pool, but got: %+v", v3Pools.Items)
			}
			if len(v3Pools.Items[0].Labels) != 0 {
				return fmt.Errorf("Expected no labels on IP pool, but got: %+v", v3Pools.Items[0].Labels)
			}
			return nil
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())

		Expect(v3Pools.Items[0].Labels).NotTo(HaveKey("app.kubernetes.io/managed-by"))

		// Verify that the default IPv4 pool has NOT been modified by the operator.
		Expect(v3Pools.Items[0].Name).To(Equal("default-ipv4-ippool"))
		Expect(v3Pools.Items[0].Spec.CIDR).To(Equal("192.168.0.0/24"))
		Expect(v3Pools.Items[0].Spec.NATOutgoing).To(Equal(true))
		Expect(v3Pools.Items[0].Spec.Disabled).To(Equal(false))
		Expect(v3Pools.Items[0].Spec.BlockSize).To(Equal(26))
		Expect(v3Pools.Items[0].Spec.NodeSelector).To(Equal("has(kubernetes.io/os)"))
		Expect(v3Pools.Items[0].Spec.IPIPMode).To(Equal(v3.IPIPMode(v3.IPIPModeAlways)))
		Expect(v3Pools.Items[0].Spec.VXLANMode).To(Equal(v3.VXLANMode(v3.VXLANModeNever)))
	})

	// The operator applies its IP pool list under its own field manager, so these tests cover what
	// happens when a second manager writes to the same field against a real API server.
	It("should share the IP pool list with another field manager", func() {
		operatorDone = createInstallation(c, mgr, shutdownContext, nil)
		verifyCalicoHasDeployed(c)

		instance := &operator.Installation{}
		Eventually(func() error {
			return installationHasPools(c, instance, 2)
		}, 30*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
		Expect(managerOwningPools(instance)).To(Equal(poolFieldManager))

		By("Applying an extra IP pool as a different field manager")
		extra := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "operator.tigera.io/v1",
			"kind":       "Installation",
			"metadata":   map[string]any{"name": "default"},
			"spec": map[string]any{
				"calicoNetwork": map[string]any{
					"ipPools": []any{
						map[string]any{"cidr": "172.31.0.0/16", "encapsulation": "VXLAN"},
					},
				},
			},
		}}
		Expect(c.Apply(context.Background(), client.ApplyConfigurationFromUnstructured(extra), client.FieldOwner("fv-writer"))).To(Succeed())

		By("Verifying the two managers' pools are merged rather than replacing each other")
		Eventually(func() error {
			return installationHasPools(c, instance, 3)
		}, 30*time.Second, 1*time.Second).ShouldNot(HaveOccurred())

		cidrs := []string{}
		for _, pool := range instance.Spec.CalicoNetwork.IPPools {
			cidrs = append(cidrs, pool.CIDR)
		}
		Expect(cidrs).To(ConsistOf("192.168.0.0/16", "fd00:10:244::/64", "172.31.0.0/16"))

		// The pool the other manager declared stays uncreated here. Past bootstrap this controller
		// only writes pools through the Calico API server, which this suite doesn't run.
	})

	It("should restore the pools it owns when the list is removed from the spec", func() {
		operatorDone = createInstallation(c, mgr, shutdownContext, nil)
		verifyCalicoHasDeployed(c)

		instance := &operator.Installation{}
		Eventually(func() error {
			return installationHasPools(c, instance, 2)
		}, 30*time.Second, 1*time.Second).ShouldNot(HaveOccurred())

		By("Clearing the pool list the way a kubectl edit would")
		Eventually(func() error {
			if err := c.Get(context.Background(), types.NamespacedName{Name: "default"}, instance); err != nil {
				return err
			}

			instance.Spec.CalicoNetwork.IPPools = nil
			return c.Update(context.Background(), instance)
		}, 30*time.Second, 1*time.Second).ShouldNot(HaveOccurred())

		By("Verifying the operator puts its pools back rather than reading the clear as a deletion")
		Eventually(func() error {
			return installationHasPools(c, instance, 2)
		}, 60*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
		Expect(managerOwningPools(instance)).To(Equal(poolFieldManager))

		ipPools := &v3.IPPoolList{}
		Consistently(func() error {
			if err := c.List(context.Background(), ipPools); err != nil {
				return err
			}
			if len(ipPools.Items) != 2 {
				return fmt.Errorf("Expected 2 IP pools, but got: %+v", ipPools.Items)
			}
			return nil
		}, 10*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
	})
})

// poolFieldManager matches the unexported field manager the IP pool controller applies under.
const poolFieldManager = "tigera-operator-ippools"

// installationHasPools reads the Installation into instance and reports whether its spec declares
// the expected number of IP pools.
func installationHasPools(c client.Client, instance *operator.Installation, expected int) error {
	if err := c.Get(context.Background(), types.NamespacedName{Name: "default"}, instance); err != nil {
		return err
	}
	if instance.Spec.CalicoNetwork == nil {
		return fmt.Errorf("Installation has no calicoNetwork yet")
	}

	pools := instance.Spec.CalicoNetwork.IPPools
	if len(pools) != expected {
		return fmt.Errorf("Expected %d IP pools on the spec, but got: %+v", expected, pools)
	}
	return nil
}

// managerOwningPools returns the name of the applying field manager that owns the IP pool list.
func managerOwningPools(instance *operator.Installation) string {
	for _, entry := range instance.ManagedFields {
		if entry.Operation != metav1.ManagedFieldsOperationApply || entry.FieldsV1 == nil {
			continue
		}

		if strings.Contains(entry.FieldsV1.GetRawString(), "ipPools") {
			return entry.Manager
		}
	}
	return ""
}
