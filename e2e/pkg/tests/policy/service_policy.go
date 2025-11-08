// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
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

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
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
	framework.WithConformance(),
	"service network policy",
	func() {
		var checker conncheck.ConnectionTester
		var server *conncheck.Server
		var client1 *conncheck.Client

		f := utils.NewDefaultFramework("service-policy")

		Context("Calico service network policy", func() {
			var cli ctrlclient.Client
			var allowClientByNamePolicy, allowServerByServicePolicy, allowServerByNamePolicy *v3.NetworkPolicy
			var allowClientByServicePolicy *v3.NetworkPolicy

			BeforeEach(func() {
				var err error
				cli, err = client.New(f.ClientConfig())
				Expect(err).NotTo(HaveOccurred())

				// Ensure a clean starting environment before each test.
				Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred())

				checker = conncheck.NewConnectionTester(f)
				server = conncheck.NewServer("server", f.Namespace)
				client1 = conncheck.NewClient("client-1", f.Namespace)
				checker.AddServer(server)
				checker.AddClient(client1)
				checker.Deploy()
			})

			JustBeforeEach(func() {
				// Verify initial connectivity.
				checker.ExpectSuccess(client1, server.ClusterIP())
				checker.Execute()
				checker.ResetExpectations()

				// Policy to allow client egress using ServiceMatch for the server's service
				allowClientByServicePolicy = &v3.NetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						Kind:       "NetworkPolicy",
						APIVersion: v3.SchemeGroupVersion.String(),
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "allow-client-egress",
						Namespace: f.Namespace.Name,
					},
					Spec: v3.NetworkPolicySpec{
						Selector: fmt.Sprintf("pod-name == '%s'", client1.Name()),
						Types:    []v3.PolicyType{v3.PolicyTypeEgress},
						Egress: []v3.Rule{
							{
								Action: v3.Allow,
								Destination: v3.EntityRule{
									Services: &v3.ServiceMatch{
										Name:      server.Service().Name,
										Namespace: f.Namespace.Name,
									},
								},
							},
						},
					},
				}

				// Policy to allow client egress using the server's pod-name
				allowClientByNamePolicy = &v3.NetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						Kind:       "NetworkPolicy",
						APIVersion: v3.SchemeGroupVersion.String(),
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "allow-client-egress",
						Namespace: f.Namespace.Name,
					},
					Spec: v3.NetworkPolicySpec{
						Selector: fmt.Sprintf("pod-name == '%s'", client1.Name()),
						Types:    []v3.PolicyType{v3.PolicyTypeEgress},
						Egress: []v3.Rule{
							{
								Action: v3.Allow,
								Destination: v3.EntityRule{
									Selector: fmt.Sprintf("pod-name == '%s'", server.Name()),
								},
							},
						},
					},
				}

				// Policy to allow server ingress using ServiceMatch for the client's service
				allowServerByServicePolicy = &v3.NetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						Kind:       "NetworkPolicy",
						APIVersion: v3.SchemeGroupVersion.String(),
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "allow-server-ingress",
						Namespace: f.Namespace.Name,
					},
					Spec: v3.NetworkPolicySpec{
						Selector: fmt.Sprintf("pod-name == '%s'", server.Name()),
						Types:    []v3.PolicyType{v3.PolicyTypeIngress},
						Ingress: []v3.Rule{
							{
								Action: v3.Allow,
								Source: v3.EntityRule{
									Services: &v3.ServiceMatch{
										Name:      "client-svc",
										Namespace: f.Namespace.Name,
									},
								},
							},
						},
					},
				}

				// Policy to allow server ingress using the client's pod-name
				allowServerByNamePolicy = &v3.NetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						Kind:       "NetworkPolicy",
						APIVersion: v3.SchemeGroupVersion.String(),
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "allow-server-ingress",
						Namespace: f.Namespace.Name,
					},
					Spec: v3.NetworkPolicySpec{
						Selector: fmt.Sprintf("pod-name == '%s'", server.Name()),
						Types:    []v3.PolicyType{v3.PolicyTypeIngress},
						Ingress: []v3.Rule{
							{
								Action: v3.Allow,
								Source: v3.EntityRule{
									Selector: fmt.Sprintf("pod-name == '%s'", client1.Name()),
								},
							},
						},
					},
				}
			})

			AfterEach(func() {
				checker.Stop()
			})

			// Test service match policy:
			// 1. Create a default-deny policy
			// 2. Create a policy to allow dns so that services can be contacted by name
			// 3. Verify client cannot reach the server
			// 4. Create a policy to allow client egress
			// 5. Create a policy to allow server ingress
			// 6. Optionally, create a service with the client pod (when the client is referred to by service)
			// 7. Verify client can now reach the server
			DescribeTable("test ServiceMatch policy",
				// these need to be closures because they are evaluated in JustBeforeEach(), see https://github.com/onsi/ginkgo/issues/378
				func(getAllowClientPolicy, getAllowServerPolicy func() *v3.NetworkPolicy, createClientService bool) {
					By("Creating default-deny policy, no client should be able to contact the server.")
					defaultDeny := newDefaultDenyPolicy(f.Namespace.Name)
					err := cli.Create(context.Background(), defaultDeny)
					Expect(err).NotTo(HaveOccurred())
					defer func() {
						err := cli.Delete(context.Background(), defaultDeny)
						Expect(err).NotTo(HaveOccurred())
					}()

					By("Creating allow-kube-dns policy, so that services can be contacted by name.")

					allowDNSPolicy := &v3.GlobalNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name: "allow-kube-dns",
						},
						Spec: v3.GlobalNetworkPolicySpec{
							Selector: "all()",
							Egress: []v3.Rule{
								{
									// For the majority of cluster provisioners, this will be kube-dns.
									Action: v3.Allow,
									Destination: v3.EntityRule{
										Services: &v3.ServiceMatch{
											Name:      "kube-dns",
											Namespace: "kube-system",
										},
									},
								},
								{
									// For Openshift, this will be dns-default.
									Action: v3.Allow,
									Destination: v3.EntityRule{
										Services: &v3.ServiceMatch{
											Name:      "dns-default",
											Namespace: "openshift-dns",
										},
									},
								},
							},
						},
					}
					err = cli.Create(context.Background(), allowDNSPolicy)
					Expect(err).NotTo(HaveOccurred())
					defer func() {
						err := cli.Delete(context.Background(), allowDNSPolicy)
						Expect(err).NotTo(HaveOccurred())
					}()

					By("Expecting the client will not be able to contact the server.")
					checker.ExpectFailure(client1, server.ClusterIP().Port(80))
					checker.Execute()
					checker.ResetExpectations()

					By("Creating allow-client-egress policy.")
					allowClientPolicy := getAllowClientPolicy()
					err = cli.Create(context.Background(), allowClientPolicy)
					Expect(err).NotTo(HaveOccurred())
					defer func() {
						err := cli.Delete(context.Background(), allowClientPolicy)
						Expect(err).NotTo(HaveOccurred())
					}()

					By("Creating allow-server-ingress policy.")
					allowServerPolicy := getAllowServerPolicy()
					err = cli.Create(context.Background(), allowServerPolicy)
					Expect(err).NotTo(HaveOccurred())
					defer func() {
						err := cli.Delete(context.Background(), allowServerPolicy)
						Expect(err).NotTo(HaveOccurred())
					}()

					if createClientService {
						By("Creating service for client so that a ServiceMatch policy can be used to allow ingress traffic from the client.")
						clientService := &v1.Service{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "client-svc",
								Namespace: f.Namespace.Name,
							},
							Spec: v1.ServiceSpec{
								Selector:       map[string]string{"pod-name": client1.Name()},
								IPFamilies:     server.Service().Spec.IPFamilies,
								IPFamilyPolicy: server.Service().Spec.IPFamilyPolicy,
								Ports: []v1.ServicePort{
									{
										Port:     80,
										Protocol: v1.ProtocolTCP,
									},
								},
							},
							Status: v1.ServiceStatus{},
						}

						ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						defer cancel()
						clientService, err = f.ClientSet.CoreV1().Services(f.Namespace.Name).Create(ctx, clientService, metav1.CreateOptions{})
						Expect(err).NotTo(HaveOccurred(), "Failed to create client service.")
						defer func() {
							ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
							defer cancel()
							err := f.ClientSet.CoreV1().Services(f.Namespace.Name).Delete(ctx, clientService.Name, metav1.DeleteOptions{})
							Expect(err).NotTo(HaveOccurred(), "Failed to delete client service.")
						}()
					}

					By("Creating client which will be able to contact the server since allow policies were put in place.")
					checker.ExpectSuccess(client1, server.ClusterIP().Port(80))
					checker.Execute()
				},
				Entry("client egress by service, server ingress by service", func() *v3.NetworkPolicy { return allowClientByServicePolicy }, func() *v3.NetworkPolicy { return allowServerByServicePolicy }, true),
				Entry("client egress by pod-name, server ingress by service", func() *v3.NetworkPolicy { return allowClientByNamePolicy }, func() *v3.NetworkPolicy { return allowServerByServicePolicy }, true),
				Entry("client egress by service, server ingress by pod-name", func() *v3.NetworkPolicy { return allowClientByServicePolicy }, func() *v3.NetworkPolicy { return allowServerByNamePolicy }, false),
			)
		})
	})
