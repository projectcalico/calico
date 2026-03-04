// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/smithy-go/ptr"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("NetworkPolicy"),
	describe.WithCategory(describe.Policy),
	describe.WithWindows(),
	"Calico NetworkPolicy",
	func() {
		// Define variables common across all tests.
		var err error
		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester
		var server1 *conncheck.Server
		var client1 *conncheck.Client

		// Create a new framework for the tests.
		f := utils.NewDefaultFramework("networkpolicy")

		BeforeEach(func() {
			// Create a connection tester for the test.
			checker = conncheck.NewConnectionTester(f)

			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Ensure a clean starting environment before each test.
			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred())
		})

		// Before each test, perform the following steps:
		// - Create a server pod and corresponding service in the main namespace for the test.
		// - Create a client pod and assert that it can connect to the service.
		BeforeEach(func() {
			By(fmt.Sprintf("Creating server pod in namespace %s", f.Namespace.Name))
			server1 = conncheck.NewServer("server", f.Namespace, conncheck.WithServerLabels(map[string]string{"role": "server"}))
			client1 = conncheck.NewClient("client", f.Namespace)
			checker.AddServer(server1)
			checker.AddClient(client1)
			checker.Deploy()
		})

		AfterEach(func() {
			checker.Stop()
		})

		// This is a baseline test to ensure that the test framework is working as expected.
		framework.ConformanceIt("should provide a default allow", func() {
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.Execute()
		})

		// This test performs the following steps.
		// - Creates a second namespace, "namespace B"
		// - Creating a server pod in namespace B.
		// - Creating a client in namespace B and asserting it can access the server pod in namespace B.
		// - Creating a default-deny policy applied to both namespaces using a GlobalNetworkPolicy.
		// - Isolating both namespaces with ingress and egress policies
		// - Asserting only same namespace connectivity exists.
		framework.ConformanceIt("should correctly isolate namespaces", func() {
			nsA := f.Namespace

			By("Creating a second namespace B")
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			nsB, err := f.CreateNamespace(ctx, f.BaseName+"-b", nil)
			Expect(err).NotTo(HaveOccurred())

			// Create a second server pod and wait for it to start.
			server2 := conncheck.NewServer("server-b", nsB)
			client2 := conncheck.NewClient("client-b", nsB)
			checker.AddServer(server2)
			checker.AddClient(client2)
			checker.Deploy()

			// Create a client and assert it can talk to the second server pod.
			By("Verifying that the client in namespace B can talk to the server in the same namespace")
			checker.ExpectSuccess(client2, server2.ClusterIP())
			checker.Execute()

			// Create a GNP that selects the two namespaces by name, enacting a default deny for
			// all traffic to / from pods within the test's namespaces, but leaving all other namespaces and
			// any host endpoints untouched.
			testNamespacesOnly := fmt.Sprintf(
				"kubernetes.io/metadata.name == '%s' || kubernetes.io/metadata.name == '%s'",
				nsA.Name,
				nsB.Name,
			)

			By("Creating a default-deny policy selecting both namespaces")
			var defaultDenyPriority float64 = 5000
			defaultDenyGNP := v3.NewGlobalNetworkPolicy()
			defaultDenyGNP.Name = "default-deny-all"
			defaultDenyGNP.Spec.Order = &defaultDenyPriority
			defaultDenyGNP.Spec.NamespaceSelector = testNamespacesOnly
			err = cli.Create(ctx, defaultDenyGNP)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, defaultDenyGNP)
				if err != nil {
					framework.Failf("failed to delete resource: %s", err)
				}
			}()

			// Create a GlobalNetworkPolicy that allows any pods access to DNS. This is needed so
			// that pods can lookup service IPs by service name in subsequent steps.
			// We only apply this to the test namespaces, as other namespaces shouldn't be impacted by
			// the policies created by this test.
			By("Creating global network policy which allows pods to access kube-dns")
			var dnsPriority float64 = 400
			allowEgressToDNS := v3.NewGlobalNetworkPolicy()
			allowEgressToDNS.Name = "allow-egress-to-kube-dns"
			allowEgressToDNS.Spec.Order = &dnsPriority
			allowEgressToDNS.Spec.NamespaceSelector = testNamespacesOnly
			allowEgressToDNS.Spec.Egress = []v3.Rule{
				{
					// Allow to kube-system DNS.
					Action: "Allow",
					Destination: v3.EntityRule{
						NamespaceSelector: "kubernetes.io/metadata.name == 'kube-system'",
						Selector:          "k8s-app == 'kube-dns'",
					},
				},
				{
					// Allow to openshift DNS.
					Action: "Allow",
					Destination: v3.EntityRule{
						NamespaceSelector: "kubernetes.io/metadata.name == 'openshift-dns'",
					},
				},
			}
			err = cli.Create(ctx, allowEgressToDNS)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, allowEgressToDNS)
				if err != nil {
					framework.Failf("failed to delete resource: %s", err)
				}
			}()

			By("Checking the default deny is functioning")
			checker.ResetExpectations()
			checker.ExpectFailure(client1, server1.ClusterIP(), server2.ClusterIP())
			checker.ExpectFailure(client2, server1.ClusterIP(), server2.ClusterIP())
			checker.Execute()

			// Create a policy which prevents ingress and egress traffic to / from pods in
			// namespace A, unless the traffic is from / to another pod in namespace A.
			By("Creating namespace isolation policy in the first namespace")
			policyName := "namespace-isolation-a"
			namespaceASelector := fmt.Sprintf("e2e-framework == '%s'", f.BaseName)
			isolateNamespaceA := newNamespaceIsolationPolicy(policyName, nsA.Name, namespaceASelector, namespaceASelector)
			err = cli.Create(ctx, isolateNamespaceA)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, isolateNamespaceA)
				if err != nil {
					framework.Failf("failed to delete resource: %s", err)
				}
			}()

			// Create a policy which prevents ingress and egress traffic to / from pods in
			// namespace B, unless the traffic is from / to another pod in namespace B.
			By("Creating namespace isolation policy in the second namespace")
			policyNameB := "namespace-isolation-b"
			namespaceBSelector := fmt.Sprintf("kubernetes.io/metadata.name == '%s'", nsB.Name)
			isolateNamespaceB := newNamespaceIsolationPolicy(policyNameB, nsB.Name, namespaceBSelector, namespaceBSelector)
			err = cli.Create(ctx, isolateNamespaceB)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, isolateNamespaceB)
				if err != nil {
					framework.Failf("failed to delete resource: %s", err)
				}
			}()

			By("Checking clients can only communicate within their own Namespace")
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIP())
			checker.ExpectFailure(client1, server2.ClusterIP())
			checker.ExpectSuccess(client2, server2.ClusterIP())
			checker.ExpectFailure(client2, server1.ClusterIP())
			checker.Execute()
		})

		framework.ConformanceIt("should support service account selectors", func() {
			ns := f.Namespace
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			By(fmt.Sprintf("Applying a default-deny policy to namespace %s", ns.Name))
			defaultDeny := newDefaultDenyIngressPolicy(ns.Name)
			err = cli.Create(ctx, defaultDeny)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, defaultDeny)
				Expect(err).NotTo(HaveOccurred())
			}()

			// Verify the default deny.
			checker.ExpectFailure(client1, server1.ClusterIP())
			checker.Execute()

			By("Allowing traffic through a service account selector")
			sa, err := f.ClientSet.CoreV1().ServiceAccounts(ns.Name).Get(ctx, "default", metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			sa.Labels = map[string]string{"ns-name": ns.Name}
			_, err = f.ClientSet.CoreV1().ServiceAccounts(ns.Name).Update(ctx, sa, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			np := &v3.NetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "NetworkPolicy",
					APIVersion: v3.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "allow-through-service-account",
					Namespace: ns.Name,
				},
				Spec: v3.NetworkPolicySpec{
					ServiceAccountSelector: fmt.Sprintf("ns-name == '%s'", ns.Name),
					Order:                  ptr.Float64(100),
					Ingress: []v3.Rule{
						{
							Action: v3.Allow,
							Source: v3.EntityRule{
								ServiceAccounts: &v3.ServiceAccountMatch{
									Selector: fmt.Sprintf("ns-name == '%s'", ns.Name),
								},
							},
						},
					},
				},
			}

			err = cli.Create(ctx, np)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, np)
				if err != nil {
					framework.Failf("failed to delete resource: %s", err)
				}
			}()

			// Verify the policy allows traffic.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIP())
			checker.Execute()
		})

		framework.ConformanceIt("should support namespace selectors", func() {
			ns := f.Namespace
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			By(fmt.Sprintf("Applying a default-deny policy to namespace %s", ns.Name))
			defaultDeny := newDefaultDenyIngressPolicy(ns.Name)
			err := cli.Create(ctx, defaultDeny)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, defaultDeny)
				Expect(err).NotTo(HaveOccurred())
			}()
			logrus.Info("Applied default-deny policy.")

			// Verify the default deny.
			checker.ExpectFailure(client1, server1.ClusterIP())
			checker.Execute()

			By("Allowing traffic through a namespace selector")

			np := &v3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-through-namespace-selector",
				},
				Spec: v3.GlobalNetworkPolicySpec{
					NamespaceSelector: fmt.Sprintf("kubernetes.io/metadata.name == '%s'", ns.Name),
					Order:             ptr.Float64(100),
					Ingress: []v3.Rule{
						{
							Action: "Allow",
							Source: v3.EntityRule{
								NamespaceSelector: fmt.Sprintf("kubernetes.io/metadata.name == '%s'", ns.Name),
							},
						},
					},
					Egress: []v3.Rule{
						{
							Action: "Allow",
							Destination: v3.EntityRule{
								NamespaceSelector: fmt.Sprintf("kubernetes.io/metadata.name == '%s'", ns.Name),
							},
						},
					},
				},
			}

			err = cli.Create(ctx, np)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(ctx, np)
				if err != nil {
					framework.Failf("failed to delete resource: %s", err)
				}
			}()

			// Verify the policy allows traffic.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIP())
			checker.Execute()
		})

		framework.ConformanceIt("should support a 'deny egress' policy", func() {
			By("Creating calico egress policy which denies traffic within namespace.")
			nsName := f.Namespace.Name
			policyName := "deny-egress"
			o := 500.0

			// Create an egress policy that explicitly denies all egress traffic from the namespace.
			defaultDeny := v3.NewNetworkPolicy()
			defaultDeny.Name = policyName
			defaultDeny.Namespace = nsName
			defaultDeny.Spec.Selector = "all()"
			defaultDeny.Spec.Order = &o
			defaultDeny.Spec.Egress = []v3.Rule{
				{
					Action: v3.Deny,
				},
				{
					// This rule shouldn't be hit.
					Action: v3.Allow,
				},
			}

			err := cli.Create(context.Background(), defaultDeny)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				Expect(cli.Delete(context.Background(), defaultDeny)).NotTo(HaveOccurred())
			}()

			By("checking client not able to contact the server since deny egress rule created.")
			checker.ExpectFailure(client1, server1.ClusterIP())
			checker.Execute()
		})
	})

// Creates a new NetworkPolicy that isolates a namespace by allowing ingress and egress traffic only from / to pods in the same namespace.
func newNamespaceIsolationPolicy(name, namespace, ingressSelector, egressSelector string) *v3.NetworkPolicy {
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: v3.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order: ptr.Float64(1000),
			Ingress: []v3.Rule{
				{
					Action: v3.Allow,
					Source: v3.EntityRule{
						NamespaceSelector: ingressSelector,
					},
				},
			},
			Egress: []v3.Rule{
				{
					Action: v3.Allow,
					Destination: v3.EntityRule{
						NamespaceSelector: egressSelector,
					},
				},
			},
		},
	}
}

func newDefaultDenyIngressPolicy(namespace string) *v3.NetworkPolicy {
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: v3.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-deny",
			Namespace: namespace,
		},
		Spec: v3.NetworkPolicySpec{
			// If the spec.types field is not set, it defaults to "Ingress" only.
			Order:    ptr.Float64(5000),
			Selector: "all()",
		},
	}
}
