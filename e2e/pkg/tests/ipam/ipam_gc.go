// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package ipam

import (
	"context"
	"fmt"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("IPAM"),
	describe.WithSerial(), // Modifies global state, so run serially.
	describe.WithCategory(describe.Networking),
	"IPAM GC",
	func() {
		var cli ctrlclient.Client
		var lcgc clientv3.Interface

		f := utils.NewDefaultFramework("calico-ipam-gc")

		BeforeEach(func() {
			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "failed to create controller-runtime client")

			// Ensure a clean starting environment before each test.
			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred(), "failed to clean datastore")

			// Verify that the cluster uses Calico IPAM. The Installation resource
			// provides a definitive answer when available; IP pools serve as a
			// fallback indicator for manifest-based installs.
			Expect(utils.UsesCalicoIPAM(cli)).To(BeTrue(), "cluster does not use Calico IPAM; this test requires Calico IPAM")

			// Additionally verify IP pools exist as a sanity check.
			poolList := &v3.IPPoolList{}
			err = cli.List(context.Background(), poolList)
			Expect(err).NotTo(HaveOccurred(), "failed to list IP pools")
			Expect(poolList.Items).NotTo(BeEmpty(), "no IP pools found; cluster may not be using Calico IPAM")

			// Build a libcalico-go client for IPAM operations. The controller-runtime client
			// does not support IPAM, so we talk directly via the libcalico-go backend.
			cfg := apiconfig.NewCalicoAPIConfig()
			cfg.Spec.DatastoreType = apiconfig.Kubernetes
			cfg.Spec.Kubeconfig = framework.TestContext.KubeConfig
			lcgc, err = clientv3.New(*cfg)
			Expect(err).NotTo(HaveOccurred(), "failed to create libcalico-go client")
		})

		// Verifies that kube-controllers garbage-collects IP addresses allocated to
		// non-existent pods. We create a fake IPAM allocation referencing a pod that
		// doesn't exist, shorten the leak grace period so GC runs quickly, and then
		// wait for the allocation to be released.
		It("should garbage-collect leaked IP addresses", func() {
			ctx := context.Background()

			// Shorten the leak grace period so GC detects the leak quickly.
			By("Shortening the KubeControllersConfiguration leak grace period to 5s")
			kcc := v3.NewKubeControllersConfiguration()
			err := cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, kcc)
			Expect(err).NotTo(HaveOccurred(), "failed to get KubeControllersConfiguration")
			logrus.Infof("KubeControllersConfiguration before modification: %+v", kcc.Spec)

			// Save original value for restoration. Initialize the Node controller
			// config if it's nil (it's enabled by default but may not be explicit).
			if kcc.Spec.Controllers.Node == nil {
				kcc.Spec.Controllers.Node = &v3.NodeControllerConfig{}
			}
			origLeakGracePeriod := kcc.Spec.Controllers.Node.LeakGracePeriod

			kcc.Spec.Controllers.Node.LeakGracePeriod = &metav1.Duration{Duration: 5 * time.Second}
			err = cli.Update(ctx, kcc)
			Expect(err).NotTo(HaveOccurred(), "failed to update KubeControllersConfiguration leak grace period")

			// Restore the original leak grace period when the test completes.
			DeferCleanup(func() {
				err := cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, kcc)
				if err != nil {
					framework.Logf("WARNING: failed to get KubeControllersConfiguration for restoration: %v", err)
					return
				}
				kcc.Spec.Controllers.Node.LeakGracePeriod = origLeakGracePeriod
				if err := cli.Update(ctx, kcc); err != nil {
					framework.Logf("WARNING: failed to restore KubeControllersConfiguration leak grace period: %v", err)
				}
			})

			// Pick a real node for the IPAM allocation. Using a real node makes the
			// allocation look realistic to the GC code, which asserts that the
			// allocation is on a known node.
			By("Selecting a schedulable node for the fake allocation")
			nodeCtx, nodeCancel := context.WithTimeout(ctx, 30*time.Second)
			defer nodeCancel()
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(nodeCtx, f.ClientSet, 3)
			Expect(err).NotTo(HaveOccurred(), "failed to list schedulable nodes")
			Expect(nodes.Items).NotTo(BeEmpty(), "no schedulable nodes found")
			n := nodes.Items[0]

			// Allocate an IP address referencing a non-existent pod. This simulates
			// a leaked allocation that GC should clean up.
			By("Allocating a fake IP address for a non-existent pod")
			handle := "e2e-ipam-gc-handle"
			args := ipam.AutoAssignArgs{
				Num4:        1,
				HandleID:    &handle,
				Attrs:       map[string]string{ipam.AttributePod: "fake-pod", ipam.AttributeNode: n.Name, ipam.AttributeNamespace: "default"},
				IntendedUse: v3.IPPoolAllowedUseWorkload,
				Hostname:    n.Name,
			}
			assignCtx, assignCancel := context.WithTimeout(ctx, 30*time.Second)
			defer assignCancel()
			v4s, _, err := lcgc.IPAM().AutoAssign(assignCtx, args)
			Expect(err).NotTo(HaveOccurred(), "failed to auto-assign IP")
			Expect(v4s.PartialFulfillmentError()).NotTo(HaveOccurred(), "partial fulfillment error on IP assignment")
			Expect(v4s.IPs).To(HaveLen(1), "expected exactly one IP to be assigned")
			logrus.Infof("Allocated fake IP: %v", v4s.IPs[0])

			// Ensure cleanup in case GC doesn't release it.
			DeferCleanup(func() {
				releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer releaseCancel()
				_ = lcgc.IPAM().ReleaseByHandle(releaseCtx, handle)
			})

			// Wait for kube-controllers IPAM GC to detect the leak and release the allocation.
			By("Waiting for the leaked IP to be garbage-collected")
			Eventually(func() error {
				checkCtx, checkCancel := context.WithTimeout(ctx, 30*time.Second)
				defer checkCancel()
				ips, err := lcgc.IPAM().IPsByHandle(checkCtx, handle)
				if err != nil {
					if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
						return nil // IP has been released
					}
					return fmt.Errorf("unexpected error checking handle: %w", err)
				}
				if len(ips) != 0 {
					return fmt.Errorf("IP %v still allocated, waiting for GC", ips)
				}
				return nil
			}, 2*time.Minute, 5*time.Second).Should(Succeed(), "timed out waiting for leaked IP to be garbage-collected")
		})
	})
