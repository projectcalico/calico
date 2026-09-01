// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package calico

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("IPPool"),
	describe.WithCategory(describe.Operator),
	describe.RequiresOperator(),

	// Validation on non-Calico CNI clusters forces IP pools to use the 'all()' node selector.
	describe.RequiresCalicoCNI(),

	// Mutates the default Installation, which every other spec shares.
	describe.WithSerial(),
	"operator IPPool management tests",
	func() {
		f := utils.NewDefaultFramework("pool-management")

		var (
			cli           ctrlclient.Client
			ctx           context.Context
			installation  *operatorv1.Installation
			originalPools []operatorv1.IPPool
		)

		ginkgo.BeforeEach(func() {
			ctx = context.Background()

			// Create a controller runtime client for interacting with the Calico resources in the test.
			// Calicoctl doesn't support operator.tigera.io/v1 APIs.
			scheme := runtime.NewScheme()
			err := v3.AddToScheme(scheme)
			Expect(err).NotTo(HaveOccurred())
			err = operatorv1.AddToScheme(scheme)
			Expect(err).NotTo(HaveOccurred())
			cli, err = ctrlclient.NewWithWatch(f.ClientConfig(), ctrlclient.Options{Scheme: scheme})
			Expect(err).NotTo(HaveOccurred())

			// Query the installation.
			installation = &operatorv1.Installation{}
			err = cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, installation)
			Expect(err).NotTo(HaveOccurred(), "Error querying Installation resource")

			config := installation.Status.Computed
			Expect(config).NotTo(BeNil(), "No computed configuration on the Installation")
			Expect(config.CalicoNetwork).NotTo(BeNil(), "CalicoNetwork is not configured in the Installation")
			Expect(config.CNI).NotTo(BeNil(), "No CNI configured in the Installation")
			Expect(config.CNI.Type).To(Equal(operatorv1.PluginCalico), "Cluster is not using the Calico CNI plugin")

			// Save the original pool list so we can revert the cluster after the test.
			// Only the pool list is saved, and only it is written back: this spec must
			// not round-trip the whole Installation (see patchPools).
			if installation.Spec.CalicoNetwork != nil {
				originalPools = slices.Clone(installation.Spec.CalicoNetwork.IPPools)
			} else {
				originalPools = nil
			}
		})

		// patchPools applies mutate to the Installation's IP pool list and sends only
		// that field.
		//
		// It must not be a full-object Update. An Update round-trips the stored object
		// through this build's Installation struct, which silently drops any field the
		// struct does not know - the CRD can carry fields newer than the vendored
		// operator API. The CRD then re-defaults the dropped field, changing the
		// calico-node pod template and rolling the DaemonSet mid-suite, which every
		// spec after this one runs into. A merge patch leaves absent fields alone.
		patchPools := func(mutate func(*operatorv1.Installation)) error {
			current := &operatorv1.Installation{}
			if err := cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, current); err != nil {
				return err
			}
			patch := ctrlclient.MergeFrom(current.DeepCopy())
			if current.Spec.CalicoNetwork == nil {
				current.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
			}
			mutate(current)
			return cli.Patch(ctx, current, patch)
		}

		ginkgo.AfterEach(func() {
			// Revert the pool list to its original state. This might take an attempt or
			// two if we hit resource version conflicts.
			Eventually(func() error {
				return patchPools(func(i *operatorv1.Installation) {
					i.Spec.CalicoNetwork.IPPools = originalPools
				})
			}, 20*time.Second, 2*time.Second).ShouldNot(HaveOccurred())
		})

		// This test verifies that the operator properly creates and deletes IP pools when added / removed
		// from the Installation spec.
		ginkgo.It("should create and delete IP pools", func() {
			// Determine a free CIDR.
			var newCIDR string
			pools := v3.IPPoolList{}
			err := cli.List(ctx, &pools)
			Expect(err).NotTo(HaveOccurred())
			usedCIDRs := map[string]bool{}
			for _, pool := range pools.Items {
				usedCIDRs[pool.Spec.CIDR] = true
			}
			for i := range 256 {
				if !usedCIDRs[fmt.Sprintf("172.%d.0.0/16", i)] {
					newCIDR = fmt.Sprintf("172.%d.0.0/16", i)
					break
				}
			}
			Expect(newCIDR).NotTo(BeEmpty(), "Unable to find a free CIDR for the test")

			// Add an IP pool to the installation.
			poolName := "test-pool"
			newPool := operatorv1.IPPool{
				Name: poolName,
				CIDR: newCIDR,
				// Use a dummy node selector to ensure we don't allocate real IPs.
				NodeSelector: "!all()",
			}

			// The operator's defaulted pools are absent from the spec, so declare them too or the update deletes them.
			desiredPools := append(slices.Clone(installation.Status.Computed.CalicoNetwork.IPPools), newPool)

			Eventually(func() error {
				return patchPools(func(i *operatorv1.Installation) {
					i.Spec.CalicoNetwork.IPPools = desiredPools
				})
			}, 20*time.Second, 2*time.Second).ShouldNot(HaveOccurred())

			// Wait for the IP pool to be created.
			pool := &v3.IPPool{}
			Eventually(func() error {
				return cli.Get(ctx, ctrlclient.ObjectKey{Name: poolName}, pool)
			}, 20*time.Second, 2*time.Second).ShouldNot(HaveOccurred())

			// Modify the IP pool - the operator should revert the change.
			Eventually(func() error {
				err := cli.Get(ctx, ctrlclient.ObjectKey{Name: poolName}, pool)
				if err != nil {
					return err
				}
				pool.Spec.NodeSelector = "has(dummy-key)"
				return cli.Update(ctx, pool)
			}, 20*time.Second, 2*time.Second).ShouldNot(HaveOccurred())

			Eventually(func() error {
				err := cli.Get(ctx, ctrlclient.ObjectKey{Name: poolName}, pool)
				if err != nil {
					return err
				}
				if pool.Spec.NodeSelector != "!all()" {
					return fmt.Errorf("operator did not revert the change to the IP pool")
				}
				return nil
			}, 20*time.Second, 2*time.Second).ShouldNot(HaveOccurred())

			// The operator reverted the IP pool. Now modify the IP pool via the Installation. We expect
			// the operator to make the change to the pool.
			Eventually(func() error {
				return patchPools(func(i *operatorv1.Installation) {
					for p := range i.Spec.CalicoNetwork.IPPools {
						if i.Spec.CalicoNetwork.IPPools[p].Name == poolName {
							i.Spec.CalicoNetwork.IPPools[p].NodeSelector = "has(dummy-key)"
						}
					}
				})
			}, 20*time.Second, 2*time.Second).ShouldNot(HaveOccurred())

			Eventually(func() error {
				err := cli.Get(ctx, ctrlclient.ObjectKey{Name: poolName}, pool)
				if err != nil {
					return err
				}
				if pool.Spec.NodeSelector != "has(dummy-key)" {
					return fmt.Errorf("operator did not apply the change to the IP pool")
				}
				return nil
			}).ShouldNot(HaveOccurred())

			// Remove the IP pool from the installation.
			Eventually(func() error {
				return patchPools(func(i *operatorv1.Installation) {
					i.Spec.CalicoNetwork.IPPools = originalPools
				})
			}, 20*time.Second, 2*time.Second).ShouldNot(HaveOccurred())

			// The IP pool should be deleted.
			Eventually(func() error {
				err := cli.Get(ctx, ctrlclient.ObjectKey{Name: poolName}, pool)
				if errors.IsNotFound(err) {
					return nil
				} else if err != nil {
					return err
				}
				return fmt.Errorf("pool still exists")
			}).ShouldNot(HaveOccurred())
		})
	})
