// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

package policy

import (
	"context"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

// DESCRIPTION: Verify tiers.
// DOCS_URL: https://docs.tigera.io/calico/latest/network-policy/policy-tiers/
// PRECONDITIONS:  Because tiers are not namespaced, these tests cannot be run in parallel.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Policy),
	describe.WithFeature("Tiered-Policy"),
	describe.WithWindows(),
	describe.WithSerial(),
	"Tiered policy tests",
	func() {
		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester
		var client1 *conncheck.Client
		var server *conncheck.Server
		var ctx context.Context
		var cancel context.CancelFunc

		f := utils.NewDefaultFramework("tiers")

		pDefaultDeny := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "deny-all",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				Ingress:     []networkingv1.NetworkPolicyIngressRule{},
			},
		}

		var tier0 *v3.Tier

		BeforeEach(func() {
			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Ensure a clean starting environment before each test.
			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred())

			// Create a default-deny policy. We don't bother to explicitly delete this after since it will get wiped when the
			// namespace is deleted.
			By("Creating a default-deny policy.")
			ctx, cancel = context.WithCancel(context.Background())
			_, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(ctx, pDefaultDeny, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			checker = conncheck.NewConnectionTester(f)
			client1 = conncheck.NewClient("client", f.Namespace)
			server = conncheck.NewServer("server", f.Namespace)
			checker.AddClient(client1)
			checker.AddServer(server)
			checker.Deploy()

			// Defauly deny should be in effect.
			checker.ExpectFailure(client1, server.ClusterIPs()...)
			checker.Execute()
			checker.ResetExpectations()

			By("Creating tier0")
			tier0 = v3.NewTier()
			tier0.Name = "t0"
			tier0.Spec.Order = ptr.To(98.0)
			tier0.Labels = map[string]string{utils.TestResourceLabel: "true"}
			err = cli.Create(ctx, tier0)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			defer cancel()
			checker.Stop()

			By("Deleting tier0")
			err := cli.Delete(ctx, tier0)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("with a single tier taking precedence over the default tier", func() {
			framework.ConformanceIt("can pass to the default tier, and allow traffic explicitly.", func() {
				// Use a lower order here
				By("Creating a policy in tier0 with rules to pass to next tier.")
				fifty := float64(50)
				passPolicy := v3.NewNetworkPolicy()
				passPolicy.Name = "t0.server-pass"
				passPolicy.Namespace = f.Namespace.Name
				passPolicy.Spec.Order = &fifty
				passPolicy.Spec.Selector = `pod-name == "server"`
				passPolicy.Spec.Tier = "t0"
				passPolicy.Spec.Ingress = []v3.Rule{
					{
						Action: v3.Pass,
					},
				}

				err := cli.Create(ctx, passPolicy)
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					err := cli.Delete(ctx, passPolicy)
					Expect(err).NotTo(HaveOccurred())
				}()

				By("Testing server pod should not be accessible with default deny.")
				checker.ExpectFailure(client1, server.ClusterIPs()...)
				checker.Execute()
				checker.ResetExpectations()

				By("Creating a policy in default tier with rules to allow traffic.")
				oneHundred := float64(100)
				allowPolicy := v3.NewNetworkPolicy()
				allowPolicy.Name = "server-allow"
				allowPolicy.Namespace = f.Namespace.Name
				allowPolicy.Spec.Order = &oneHundred
				allowPolicy.Spec.Selector = `pod-name == "server"`
				allowPolicy.Spec.Tier = "default"
				allowPolicy.Spec.Ingress = []v3.Rule{
					{
						Action: v3.Allow,
					},
				}
				err = cli.Create(ctx, allowPolicy)
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					err := cli.Delete(ctx, allowPolicy)
					Expect(err).NotTo(HaveOccurred())
				}()

				By("Testing server pod should be accessible.")
				checker.ExpectSuccess(client1, server.ClusterIPs()...)
				checker.Execute()
			})
		})

		Context("with a second tier", func() {
			var tier1 *v3.Tier

			BeforeEach(func() {
				tier1 = v3.NewTier()
				tier1.Name = "t1"
				tier1.Labels = map[string]string{utils.TestResourceLabel: "true"}
				tier1.Spec.Order = ptr.To(99.0)

				By("Creating tier1 with higher order number than tier0")
				err := cli.Create(ctx, tier1)
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				By("Deleting tier1")
				err := cli.Delete(ctx, tier1)
				Expect(err).NotTo(HaveOccurred())
			})

			It("can explicitly pass traffic", func() {
				By("Creating a policy in tier0 with rules to pass to next tier.")
				passPolicy := &v3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "t0.test-pass",
						Namespace: f.Namespace.Name,
					},
					Spec: v3.NetworkPolicySpec{
						Selector: "pod-name == 'server'",
						Tier:     "t0",
						Ingress: []v3.Rule{
							{
								Action: v3.Pass,
							},
						},
					},
				}
				err := cli.Create(ctx, passPolicy)
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					err := cli.Delete(ctx, passPolicy)
					Expect(err).NotTo(HaveOccurred())
				}()

				By("Testing server pod should not be accessible due to default deny.")
				checker.ExpectFailure(client1, server.ClusterIP())
				checker.Execute()
				checker.ResetExpectations()

				By("Creating a policy tier1 with rules to allow the passed traffic.")
				t1Allow := &v3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "t1.test-allow",
						Namespace: f.Namespace.Name,
					},
					Spec: v3.NetworkPolicySpec{
						Selector: "pod-name == \"server\"",
						Tier:     "t1",
						Ingress: []v3.Rule{
							{
								Action: v3.Allow,
							},
						},
					},
				}
				err = cli.Create(ctx, t1Allow)
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					err := cli.Delete(ctx, t1Allow)
					Expect(err).NotTo(HaveOccurred())
				}()

				By("Testing server pod should be accessible.")
				checker.ExpectSuccess(client1, server.ClusterIP())
				checker.Execute()
			})

			It("should enforce a default deny", func() {
				By("Creating a policy in tier0 with rules to log traffic.")
				np := &v3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "t0.test-pass",
						Namespace: f.Namespace.Name,
					},
					Spec: v3.NetworkPolicySpec{
						Selector: "pod-name == \"server\"",
						Tier:     "t0",
						Ingress: []v3.Rule{
							{
								Action: v3.Log,
							},
						},
					},
				}
				err := cli.Create(ctx, np)
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					err := cli.Delete(ctx, np)
					Expect(err).NotTo(HaveOccurred())
				}()

				By("Testing server pod should not be accessible.")
				checker.ExpectFailure(client1, server.ClusterIP())
				checker.Execute()
			})
		})
	})
