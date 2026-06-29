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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

const (
	strictAffinityPoolCIDR = "198.51.100.0/29"

	strictAffinityLabelKey   = "app"
	strictAffinityLabelValue = "e2e-strict-affinity"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("IPAM"),
	describe.WithSerial(), // Modifies global IPAMConfiguration state.
	describe.WithCategory(describe.Networking),
	"IPAM StrictAffinity",
	func() {
		var cli ctrlclient.Client

		f := utils.NewDefaultFramework("calico-ipam-strict-affinity")

		BeforeEach(func() {
			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "failed to create controller-runtime client")

			Expect(utils.UsesCalicoIPAM(cli)).To(BeTrue(), "cluster does not use Calico IPAM")

			// Require at least 2 schedulable worker nodes so the deployment can
			// spread replicas across nodes.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(ctx, f.ClientSet, 3)
			Expect(err).NotTo(HaveOccurred(), "failed to list schedulable nodes")
			Expect(len(nodes.Items)).To(BeNumerically(">=", 2), "need at least 2 schedulable nodes for StrictAffinity test")
		})

		// Verifies that toggling IPAMConfiguration.StrictAffinity affects real pod
		// IP allocation. With a tiny IPPool (/29 = single block), StrictAffinity=true
		// means the block can only be affine to one node, so pods on other nodes
		// can't borrow IPs and will fail to get an address.
		It("should respect StrictAffinity when toggled", func() {
			ctx := context.Background()

			// --- Phase 0: Setup ---

			poolName := utils.GenerateRandomName("e2e-strict-affinity")
			deploymentName := utils.GenerateRandomName("e2e-strict-affinity")

			By("Creating a small IPPool with a single block")
			pool := v3.NewIPPool()
			pool.Name = poolName
			pool.Spec.CIDR = strictAffinityPoolCIDR
			pool.Spec.BlockSize = 29
			pool.Spec.IPIPMode = v3.IPIPModeNever
			pool.Spec.VXLANMode = v3.VXLANModeNever
			pool.Spec.NATOutgoing = true
			pool.Spec.NodeSelector = "all()"
			err := cli.Create(ctx, pool)
			Expect(err).NotTo(HaveOccurred(), "failed to create IPPool")
			DeferCleanup(func() {
				if err := cli.Delete(context.Background(), pool); err != nil && !apierrors.IsNotFound(err) {
					framework.Logf("WARNING: failed to delete IPPool %s: %v", poolName, err)
				}
			})

			By("Annotating namespace to use the test IPPool")
			ns := &corev1.Namespace{}
			err = cli.Get(ctx, ctrlclient.ObjectKey{Name: f.Namespace.Name}, ns)
			Expect(err).NotTo(HaveOccurred())
			if ns.Annotations == nil {
				ns.Annotations = map[string]string{}
			}
			ns.Annotations["cni.projectcalico.org/ipv4pools"] = fmt.Sprintf(`["%s"]`, poolName)
			err = cli.Update(ctx, ns)
			Expect(err).NotTo(HaveOccurred(), "failed to annotate namespace")

			By("Configuring IPAMConfiguration with StrictAffinity=false")
			restore, err := utils.ConfigureWithCleanup(cli, ctrlclient.ObjectKey{Name: "default"}, &v3.IPAMConfiguration{}, func(cfg *v3.IPAMConfiguration) {
				cfg.Spec.StrictAffinity = false
				cfg.Spec.AutoAllocateBlocks = true
			})
			Expect(err).NotTo(HaveOccurred(), "failed to configure IPAMConfiguration")
			DeferCleanup(restore)

			setStrictAffinity := func(strict bool) {
				cfg := &v3.IPAMConfiguration{}
				err := cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, cfg)
				Expect(err).NotTo(HaveOccurred(), "failed to get IPAMConfiguration")
				cfg.Spec.StrictAffinity = strict
				err = cli.Update(ctx, cfg)
				Expect(err).NotTo(HaveOccurred(), "failed to update StrictAffinity to %v", strict)
				logrus.Infof("Set StrictAffinity=%v", strict)
			}

			labels := map[string]string{strictAffinityLabelKey: strictAffinityLabelValue}

			makeDeployment := func(replicas int32) *appsv1.Deployment {
				return &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      deploymentName,
						Namespace: f.Namespace.Name,
					},
					Spec: appsv1.DeploymentSpec{
						Replicas: ptr.To(replicas),
						Selector: &metav1.LabelSelector{MatchLabels: labels},
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: labels},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:    "pause",
									Image:   images.Alpine,
									Command: []string{"sleep", "3600"},
								}},
								// Force spread across nodes so the single-block pool
								// is forced to serve multiple nodes.
								TopologySpreadConstraints: []corev1.TopologySpreadConstraint{{
									MaxSkew:           1,
									TopologyKey:       "kubernetes.io/hostname",
									WhenUnsatisfiable: corev1.DoNotSchedule,
									LabelSelector:     &metav1.LabelSelector{MatchLabels: labels},
								}},
								TerminationGracePeriodSeconds: ptr.To(int64(1)),
							},
						},
					},
				}
			}

			deleteDeploymentAndWait := func() {
				dep := &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      deploymentName,
						Namespace: f.Namespace.Name,
					},
				}
				err := cli.Delete(ctx, dep)
				if apierrors.IsNotFound(err) {
					return
				}
				Expect(err).NotTo(HaveOccurred(), "failed to delete deployment")

				Eventually(func() (int, error) {
					return countPodsByLabel(f, strictAffinityLabelKey, strictAffinityLabelValue)
				}, 2*time.Minute, 5*time.Second).Should(Equal(0), "timed out waiting for pods to be deleted")
			}

			// --- Phase 1: StrictAffinity=false, all pods should get IPs ---

			By("Phase 1: Setting StrictAffinity=false and creating a 2-replica deployment")
			setStrictAffinity(false)

			dep := makeDeployment(2)
			err = cli.Create(ctx, dep)
			Expect(err).NotTo(HaveOccurred(), "failed to create deployment")
			DeferCleanup(deleteDeploymentAndWait)

			Eventually(func() (int, error) {
				return countPodsWithNoIP(f, strictAffinityLabelKey, strictAffinityLabelValue)
			}, 2*time.Minute, 5*time.Second).Should(Equal(0), "all pods should have IPs with StrictAffinity=false")
			logrus.Info("Phase 1 passed: all pods have IPs with StrictAffinity=false")

			By("Deleting the deployment before Phase 2")
			deleteDeploymentAndWait()

			// --- Phase 2: StrictAffinity=true, some pods should lack IPs ---

			By("Phase 2: Setting StrictAffinity=true and creating a 4-replica deployment")
			setStrictAffinity(true)

			dep = makeDeployment(4)
			err = cli.Create(ctx, dep)
			Expect(err).NotTo(HaveOccurred(), "failed to create deployment")

			// Wait for pods to be created and attempted scheduling before checking.
			// With StrictAffinity=true and a /29 pool (single block), only one node
			// gets the block. Pods on other nodes can't borrow IPs. First wait for
			// the expected number of pods to exist, then verify some never got IPs.
			Eventually(func() (int, error) {
				return countPodsByLabel(f, strictAffinityLabelKey, strictAffinityLabelValue)
			}, 2*time.Minute, 5*time.Second).Should(Equal(4), "expected 4 pods to be created")

			Consistently(func() (int, error) {
				return countPodsWithNoIP(f, strictAffinityLabelKey, strictAffinityLabelValue)
			}, 30*time.Second, 5*time.Second).Should(BeNumerically(">", 0),
				"some pods should lack IPs with StrictAffinity=true and a single-block pool")
			logrus.Info("Phase 2 passed: some pods lack IPs with StrictAffinity=true")

			// --- Phase 3: StrictAffinity=false again, all pods should get IPs ---

			By("Phase 3: Setting StrictAffinity=false again — all pods should get IPs")
			setStrictAffinity(false)

			Eventually(func() (int, error) {
				return countPodsWithNoIP(f, strictAffinityLabelKey, strictAffinityLabelValue)
			}, 2*time.Minute, 5*time.Second).Should(Equal(0),
				"all pods should have IPs after toggling StrictAffinity back to false")
			logrus.Info("Phase 3 passed: all pods have IPs after toggling StrictAffinity back to false")
		})
	})

// countPodsWithNoIP returns the number of pods matching the given label that
// don't have a PodIP assigned. Returns an error on transient API failures so
// that callers using Eventually can retry instead of panicking.
func countPodsWithNoIP(f *framework.Framework, labelKey, labelValue string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pods, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", labelKey, labelValue),
	})
	if err != nil {
		return -1, fmt.Errorf("failed to list pods: %w", err)
	}

	count := 0
	for i := range pods.Items {
		if pods.Items[i].Status.PodIP == "" {
			count++
		}
	}
	return count, nil
}

// countPodsByLabel returns the total number of pods matching the given label.
func countPodsByLabel(f *framework.Framework, labelKey, labelValue string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pods, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", labelKey, labelValue),
	})
	if err != nil {
		return -1, fmt.Errorf("failed to list pods: %w", err)
	}
	return len(pods.Items), nil
}
