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
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
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
			cli          ctrlclient.Client
			ctx          context.Context
			installation *operatorv1.Installation
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
			originalPools := slices.Clone(installation.Status.Computed.CalicoNetwork.IPPools)
			desiredPools := append(slices.Clone(originalPools), newPool)

			restore, err := utils.ConfigureWithCleanup(cli, ctrlclient.ObjectKey{Name: "default"}, &operatorv1.Installation{}, func(i *operatorv1.Installation) {
				if i.Spec.CalicoNetwork == nil {
					i.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
				}
				i.Spec.CalicoNetwork.IPPools = desiredPools
			})
			Expect(err).NotTo(HaveOccurred())
			ginkgo.DeferCleanup(restore)

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
				err = cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, installation)
				if err != nil {
					return err
				}
				for i := range installation.Spec.CalicoNetwork.IPPools {
					if installation.Spec.CalicoNetwork.IPPools[i].Name == poolName {
						installation.Spec.CalicoNetwork.IPPools[i].NodeSelector = "has(dummy-key)"
					}
				}
				return cli.Update(ctx, installation)
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
				err = cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, installation)
				if err != nil {
					return err
				}
				installation.Spec.CalicoNetwork.IPPools = originalPools
				return cli.Update(ctx, installation)
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
