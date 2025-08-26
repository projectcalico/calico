// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("IPPool"),
	describe.WithCategory(describe.Configuration),
	"IPPool namespaceSelector tests",
	func() {
		f := utils.NewDefaultFramework("namespace-selector")

		var (
			cli          ctrlclient.Client
			ctx          context.Context
			calicoClient client.Interface
			checker      conncheck.ConnectionTester
		)

		BeforeEach(func() {
			ctx = context.Background()

			// Create Calico client for managing resources
			var err error
			calicoClient, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())
			Expect(utils.CleanDatastore(calicoClient)).ShouldNot(HaveOccurred())

			// Create controller runtime client for Kubernetes resources
			scheme := runtime.NewScheme()
			err = v3.AddToScheme(scheme)
			Expect(err).NotTo(HaveOccurred())
			err = corev1.AddToScheme(scheme)
			Expect(err).NotTo(HaveOccurred())
			cli, err = ctrlclient.NewWithWatch(f.ClientConfig(), ctrlclient.Options{Scheme: scheme})
			Expect(err).NotTo(HaveOccurred())

			// Create connection tester
			checker = conncheck.NewConnectionTester(f)
		})

		AfterEach(func() {
			checker.Stop()
			// Clean up test resources
			Expect(utils.CleanDatastore(calicoClient)).ShouldNot(HaveOccurred())
		})

		Context("when using namespaceSelector with nodeSelector", func() {
			var (
				eastProdNS, westProdNS, eastDevNS, noLabelsNS *corev1.Namespace
				eastProdPool, westProdPool, eastDevPool, defaultPool *v3.IPPool
			)

			BeforeEach(func() {
				By("Creating test namespaces with different labels")
				
				// East + Production namespace
				eastProdNS = &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-east-prod-" + f.UniqueName,
						Labels: map[string]string{
							"region":      "east",
							"environment": "production",
							"team":        "backend",
						},
					},
				}
				Expect(cli.Create(ctx, eastProdNS)).To(Succeed())

				// West + Production namespace
				westProdNS = &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-west-prod-" + f.UniqueName,
						Labels: map[string]string{
							"region":      "west",
							"environment": "production",
							"team":        "frontend",
						},
					},
				}
				Expect(cli.Create(ctx, westProdNS)).To(Succeed())

				// East + Development namespace
				eastDevNS = &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-east-dev-" + f.UniqueName,
						Labels: map[string]string{
							"region":      "east",
							"environment": "development",
							"team":        "backend",
						},
					},
				}
				Expect(cli.Create(ctx, eastDevNS)).To(Succeed())

				// Namespace without labels
				noLabelsNS = &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-no-labels-" + f.UniqueName,
					},
				}
				Expect(cli.Create(ctx, noLabelsNS)).To(Succeed())

				By("Creating IP pools with different selectors")
				
				// Find available CIDR ranges
				pools := v3.IPPoolList{}
				err := calicoClient.IPPools().List(ctx, options.ListOptions{}, "")
				Expect(err).NotTo(HaveOccurred())
				
				usedCIDRs := make(map[string]bool)
				for _, pool := range pools.Items {
					usedCIDRs[pool.Spec.CIDR] = true
				}

				// Helper function to find free CIDR
				findFreeCIDR := func(base string) string {
					for i := 100; i < 200; i++ {
						cidr := fmt.Sprintf("10.%d.0.0/24", i)
						if !usedCIDRs[cidr] {
							usedCIDRs[cidr] = true
							return cidr
						}
					}
					Fail("Unable to find free CIDR for test")
					return ""
				}

				// East + Production pool
				eastProdPool = &v3.IPPool{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-east-prod-pool-" + f.UniqueName,
					},
					Spec: v3.IPPoolSpec{
						CIDR:              findFreeCIDR("east-prod"),
						NodeSelector:      `region == "east"`,
						NamespaceSelector: `region == "east" && environment == "production"`,
						BlockSize:         26,
						IPIPMode:          v3.IPIPModeAlways,
						NATOutgoing:       true,
					},
				}
				_, err = calicoClient.IPPools().Create(ctx, eastProdPool, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				// West + Production pool
				westProdPool = &v3.IPPool{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-west-prod-pool-" + f.UniqueName,
					},
					Spec: v3.IPPoolSpec{
						CIDR:              findFreeCIDR("west-prod"),
						NodeSelector:      `region == "west"`,
						NamespaceSelector: `region == "west" && environment == "production"`,
						BlockSize:         26,
						IPIPMode:          v3.IPIPModeAlways,
						NATOutgoing:       true,
					},
				}
				_, err = calicoClient.IPPools().Create(ctx, westProdPool, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				// East + Development pool
				eastDevPool = &v3.IPPool{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-east-dev-pool-" + f.UniqueName,
					},
					Spec: v3.IPPoolSpec{
						CIDR:              findFreeCIDR("east-dev"),
						NodeSelector:      `region == "east"`,
						NamespaceSelector: `region == "east" && environment == "development"`,
						BlockSize:         26,
						IPIPMode:          v3.IPIPModeAlways,
						NATOutgoing:       true,
					},
				}
				_, err = calicoClient.IPPools().Create(ctx, eastDevPool, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Default pool (no selectors)
				defaultPool = &v3.IPPool{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-default-pool-" + f.UniqueName,
					},
					Spec: v3.IPPoolSpec{
						CIDR:        findFreeCIDR("default"),
						BlockSize:   26,
						IPIPMode:    v3.IPIPModeAlways,
						NATOutgoing: true,
					},
				}
				_, err = calicoClient.IPPools().Create(ctx, defaultPool, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				By("Cleaning up test resources")
				
				// Delete IP pools
				for _, pool := range []*v3.IPPool{eastProdPool, westProdPool, eastDevPool, defaultPool} {
					if pool != nil {
						_ = calicoClient.IPPools().Delete(ctx, pool.Name, options.DeleteOptions{})
					}
				}

				// Delete namespaces
				for _, ns := range []*corev1.Namespace{eastProdNS, westProdNS, eastDevNS, noLabelsNS} {
					if ns != nil {
						_ = cli.Delete(ctx, ns)
					}
				}
			})

			It("should allocate IPs from pools matching both nodeSelector and namespaceSelector", func() {
				By("Creating pods in different namespaces")

				// Create server pods in each namespace
				eastProdServer := conncheck.NewServer("server-east-prod", eastProdNS, 
					conncheck.WithServerLabels(map[string]string{"app": "test-server"}),
					conncheck.WithNodeSelector(map[string]string{"region": "east"}))
				
				westProdServer := conncheck.NewServer("server-west-prod", westProdNS,
					conncheck.WithServerLabels(map[string]string{"app": "test-server"}),
					conncheck.WithNodeSelector(map[string]string{"region": "west"}))
				
				eastDevServer := conncheck.NewServer("server-east-dev", eastDevNS,
					conncheck.WithServerLabels(map[string]string{"app": "test-server"}),
					conncheck.WithNodeSelector(map[string]string{"region": "east"}))
				
				noLabelsServer := conncheck.NewServer("server-no-labels", noLabelsNS,
					conncheck.WithServerLabels(map[string]string{"app": "test-server"}))

				// Add servers to connection tester
				checker.AddServer(eastProdServer)
				checker.AddServer(westProdServer)
				checker.AddServer(eastDevServer)
				checker.AddServer(noLabelsServer)

				// Deploy all pods
				checker.Deploy()

				By("Verifying IP allocation from correct pools")
				
				// Helper function to check if IP is in CIDR
				ipInCIDR := func(ip, cidr string) bool {
					_, network, err := net.ParseCIDR(cidr)
					if err != nil {
						return false
					}
					parsedIP := net.ParseIP(ip)
					return network.Contains(parsedIP)
				}

				// Check East + Production pod uses east-prod pool
				Eventually(func() bool {
					pod, err := f.ClientSet.CoreV1().Pods(eastProdNS.Name).Get(ctx, eastProdServer.PodName(), metav1.GetOptions{})
					if err != nil || pod.Status.PodIP == "" {
						return false
					}
					return ipInCIDR(pod.Status.PodIP, eastProdPool.Spec.CIDR)
				}, 60*time.Second, 5*time.Second).Should(BeTrue(), 
					fmt.Sprintf("East+Production pod should get IP from pool %s", eastProdPool.Spec.CIDR))

				// Check West + Production pod uses west-prod pool
				Eventually(func() bool {
					pod, err := f.ClientSet.CoreV1().Pods(westProdNS.Name).Get(ctx, westProdServer.PodName(), metav1.GetOptions{})
					if err != nil || pod.Status.PodIP == "" {
						return false
					}
					return ipInCIDR(pod.Status.PodIP, westProdPool.Spec.CIDR)
				}, 60*time.Second, 5*time.Second).Should(BeTrue(),
					fmt.Sprintf("West+Production pod should get IP from pool %s", westProdPool.Spec.CIDR))

				// Check East + Development pod uses east-dev pool
				Eventually(func() bool {
					pod, err := f.ClientSet.CoreV1().Pods(eastDevNS.Name).Get(ctx, eastDevServer.PodName(), metav1.GetOptions{})
					if err != nil || pod.Status.PodIP == "" {
						return false
					}
					return ipInCIDR(pod.Status.PodIP, eastDevPool.Spec.CIDR)
				}, 60*time.Second, 5*time.Second).Should(BeTrue(),
					fmt.Sprintf("East+Development pod should get IP from pool %s", eastDevPool.Spec.CIDR))

				// Check pod without labels uses default pool
				Eventually(func() bool {
					pod, err := f.ClientSet.CoreV1().Pods(noLabelsNS.Name).Get(ctx, noLabelsServer.PodName(), metav1.GetOptions{})
					if err != nil || pod.Status.PodIP == "" {
						return false
					}
					return ipInCIDR(pod.Status.PodIP, defaultPool.Spec.CIDR)
				}, 60*time.Second, 5*time.Second).Should(BeTrue(),
					fmt.Sprintf("Pod without labels should get IP from default pool %s", defaultPool.Spec.CIDR))
			})

			It("should respect namespace annotation over selectors", func() {
				By("Creating namespace with annotation that overrides selectors")
				
				annotatedNS := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-annotated-" + f.UniqueName,
						Labels: map[string]string{
							"region":      "west",
							"environment": "production",
						},
						Annotations: map[string]string{
							"cni.projectcalico.org/ipv4pools": fmt.Sprintf(`["%s"]`, eastDevPool.Name),
						},
					},
				}
				Expect(cli.Create(ctx, annotatedNS)).To(Succeed())
				defer func() {
					_ = cli.Delete(ctx, annotatedNS)
				}()

				By("Creating pod in annotated namespace")
				annotatedServer := conncheck.NewServer("server-annotated", annotatedNS,
					conncheck.WithServerLabels(map[string]string{"app": "test-server"}),
					conncheck.WithNodeSelector(map[string]string{"region": "west"}))
				
				checker.AddServer(annotatedServer)
				checker.Deploy()

				By("Verifying pod uses pool specified in annotation, not selector-matched pool")
				Eventually(func() bool {
					pod, err := f.ClientSet.CoreV1().Pods(annotatedNS.Name).Get(ctx, annotatedServer.PodName(), metav1.GetOptions{})
					if err != nil || pod.Status.PodIP == "" {
						return false
					}
					// Should use eastDevPool (from annotation), not westProdPool (from selectors)
					_, eastDevNet, _ := net.ParseCIDR(eastDevPool.Spec.CIDR)
					parsedIP := net.ParseIP(pod.Status.PodIP)
					return eastDevNet.Contains(parsedIP)
				}, 60*time.Second, 5*time.Second).Should(BeTrue(),
					"Pod should use pool from annotation, ignoring namespace labels")
			})
		})

		Context("when testing complex namespace selectors", func() {
			It("should support complex selector expressions", func() {
				By("Creating namespace with multiple labels")
				complexNS := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-complex-" + f.UniqueName,
						Labels: map[string]string{
							"region":      "east",
							"environment": "production",
							"team":        "backend",
							"criticality": "high",
							"version":     "v2.0.0",
						},
					},
				}
				Expect(cli.Create(ctx, complexNS)).To(Succeed())
				defer func() {
					_ = cli.Delete(ctx, complexNS)
				}()

				By("Creating IP pool with complex namespaceSelector")
				// Find available CIDR
				pools := v3.IPPoolList{}
				err := calicoClient.IPPools().List(ctx, options.ListOptions{}, "")
				Expect(err).NotTo(HaveOccurred())
				
				usedCIDRs := make(map[string]bool)
				for _, pool := range pools.Items {
					usedCIDRs[pool.Spec.CIDR] = true
				}

				var complexCIDR string
				for i := 200; i < 250; i++ {
					cidr := fmt.Sprintf("10.%d.0.0/24", i)
					if !usedCIDRs[cidr] {
						complexCIDR = cidr
						break
					}
				}
				Expect(complexCIDR).NotTo(BeEmpty())

				complexPool := &v3.IPPool{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-complex-pool-" + f.UniqueName,
					},
					Spec: v3.IPPoolSpec{
						CIDR: complexCIDR,
						NamespaceSelector: `region in {"east", "west"} && environment == "production" && has(team) && criticality == "high"`,
						BlockSize:         26,
						IPIPMode:          v3.IPIPModeAlways,
						NATOutgoing:       true,
					},
				}
				_, err = calicoClient.IPPools().Create(ctx, complexPool, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					_ = calicoClient.IPPools().Delete(ctx, complexPool.Name, options.DeleteOptions{})
				}()

				By("Creating pod in complex namespace")
				complexServer := conncheck.NewServer("server-complex", complexNS,
					conncheck.WithServerLabels(map[string]string{"app": "test-server"}))
				
				checker.AddServer(complexServer)
				checker.Deploy()

				By("Verifying pod uses complex selector pool")
				Eventually(func() bool {
					pod, err := f.ClientSet.CoreV1().Pods(complexNS.Name).Get(ctx, complexServer.PodName(), metav1.GetOptions{})
					if err != nil || pod.Status.PodIP == "" {
						return false
					}
					_, complexNet, _ := net.ParseCIDR(complexPool.Spec.CIDR)
					parsedIP := net.ParseIP(pod.Status.PodIP)
					return complexNet.Contains(parsedIP)
				}, 60*time.Second, 5*time.Second).Should(BeTrue(),
					"Pod should use pool matching complex selector")
			})
		})
	})
