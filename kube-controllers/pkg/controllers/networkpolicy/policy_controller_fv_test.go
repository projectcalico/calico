// Copyright (c) 2017-2026 Tigera, Inc. All rights reserved.
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

package networkpolicy_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/networkpolicy"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("Calico networkpolicy controller FV tests (etcd mode)", Ordered, func() {
	var (
		etcd         *containers.Container
		calicoClient client.Interface
		k8sClient    *fake.Clientset
		stopCh       chan struct{}
	)

	BeforeAll(func() {
		// Run etcd for the Calico datastore.
		etcd = testutils.RunEtcd()
		calicoClient = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

		// Create the default tier, which is required for network policy creation.
		_, err := calicoClient.Tiers().Create(context.Background(), &api.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		_ = calicoClient.Close()
		etcd.Stop()
	})

	AfterEach(func() {
		close(stopCh)

		// Clean up Calico network policies.
		ctx := context.Background()
		cnpList, err := calicoClient.NetworkPolicies().List(ctx, options.ListOptions{})
		if err != nil {
			log.WithError(err).Warn("Failed to list Calico network policies during cleanup")
		}
		if cnpList != nil {
			for _, cnp := range cnpList.Items {
				if _, err := calicoClient.NetworkPolicies().Delete(ctx, cnp.Namespace, cnp.Name, options.DeleteOptions{}); err != nil {
					log.WithError(err).WithField("policy", cnp.Name).Debug("Failed to delete Calico network policy during cleanup")
				}
			}
		}
	})

	// startController creates a fresh fake K8s client seeded with the given
	// objects, then starts the policy controller in-process. By creating
	// objects before the controller, the informer's initial List picks them
	// up deterministically without any watch-establishment race.
	startController := func(objects ...networkingv1.NetworkPolicy) {
		runtimeObjs := make([]k8sRuntime.Object, len(objects))
		for i := range objects {
			runtimeObjs[i] = &objects[i]
		}
		k8sClient = fake.NewSimpleClientset(runtimeObjs...)
		stopCh = make(chan struct{})

		ctrl := networkpolicy.NewPolicyController(
			context.Background(),
			k8sClient,
			calicoClient,
			config.GenericControllerConfig{
				ReconcilerPeriod: time.Second,
				NumberOfWorkers:  1,
			},
		)
		go ctrl.Run(stopCh)
	}

	Context("NetworkPolicy FV tests", func() {
		var (
			policyName      string
			genPolicyName   string
			policyNamespace string
		)

		BeforeEach(func() {
			policyName = "jelly"
			genPolicyName = "knp.default." + policyName
			policyNamespace = "default"

			np := networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: policyNamespace,
					Annotations: map[string]string{
						"annotK": "annotV",
					},
					Labels: map[string]string{
						"labelK": "labelV",
					},
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"fools": "gold",
						},
					},
				},
			}

			startController(np)

			// Wait for it to appear in Calico's etcd. This also confirms the
			// informer's initial List has been processed and its Watch is active.
			Eventually(func() *api.NetworkPolicy {
				policy, _ := calicoClient.NetworkPolicies().Get(context.Background(), policyNamespace, genPolicyName, options.GetOptions{})
				return policy
			}, time.Second*5, 500*time.Millisecond).ShouldNot(BeNil())
		})

		It("should re-write policies in etcd when deleted in order to match policies in k8s", func() {
			// Delete the Policy.
			_, err := calicoClient.NetworkPolicies().Delete(context.Background(), policyNamespace, genPolicyName, options.DeleteOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			// Wait for the policy-controller to write it back.
			Eventually(func() error {
				_, err := calicoClient.NetworkPolicies().Get(context.Background(), policyNamespace, genPolicyName, options.GetOptions{})
				return err
			}, time.Second*15, 500*time.Millisecond).ShouldNot(HaveOccurred())
		})

		It("should re-program policies that have changed in etcd", func() {
			p, err := calicoClient.NetworkPolicies().Get(context.Background(), policyNamespace, genPolicyName, options.GetOptions{})
			By("getting the policy", func() {
				Expect(err).ShouldNot(HaveOccurred())
			})

			By("updating the selector on the policy", func() {
				p.Spec.Selector = "ping == 'pong'"
				p2, err := calicoClient.NetworkPolicies().Update(context.Background(), p, options.SetOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(p2.Spec.Selector).To(Equal("ping == 'pong'"))
			})

			By("waiting for the controller to write back the correct selector", func() {
				Eventually(func() string {
					p, _ := calicoClient.NetworkPolicies().Get(context.Background(), policyNamespace, genPolicyName, options.GetOptions{})
					return p.Spec.Selector
				}, time.Second*15, 500*time.Millisecond).Should(Equal("projectcalico.org/orchestrator == 'k8s' && fools == 'gold'"))
			})
		})

		It("should delete policies when they are deleted from the Kubernetes API", func() {
			By("deleting the policy", func() {
				err := k8sClient.NetworkingV1().NetworkPolicies(policyNamespace).Delete(context.Background(),
					policyName, metav1.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			By("waiting for it to be removed from etcd", func() {
				Eventually(func() error {
					_, err := calicoClient.NetworkPolicies().Get(context.Background(), policyNamespace, genPolicyName, options.GetOptions{})
					return err
				}, time.Second*15, 500*time.Millisecond).Should(HaveOccurred())
			})
		})
	})

	Context("NetworkPolicy egress FV tests", func() {
		var (
			genPolicyName   string
			policyNamespace string
		)

		BeforeEach(func() {
			genPolicyName = "knp.default.jelly"
			policyNamespace = "default"
			np := networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "jelly",
					Namespace: policyNamespace,
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"fools": "gold",
						},
					},
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							To: []networkingv1.NetworkPolicyPeer{
								{
									IPBlock: &networkingv1.IPBlock{
										CIDR:   "192.168.0.0/16",
										Except: []string{"192.168.3.0/24"},
									},
								},
							},
						},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				},
			}

			startController(np)

			// Wait for it to appear in Calico's etcd.
			Eventually(func() *api.NetworkPolicy {
				p, _ := calicoClient.NetworkPolicies().Get(context.Background(), policyNamespace, genPolicyName, options.GetOptions{})
				return p
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeNil())
		})

		It("should contain the correct rules", func() {
			var p *api.NetworkPolicy
			By("getting the network policy created by the controller", func() {
				Eventually(func() error {
					var err error
					p, err = calicoClient.NetworkPolicies().Get(context.Background(), policyNamespace, genPolicyName, options.GetOptions{})
					return err
				}, time.Second*10, 500*time.Millisecond).Should(BeNil())
			})

			By("checking the policy's selector is correct", func() {
				Expect(p.Spec.Selector).Should(Equal("projectcalico.org/orchestrator == 'k8s' && fools == 'gold'"))
			})

			By("checking the policy's egress rule is correct", func() {
				Expect(len(p.Spec.Egress)).Should(Equal(1))
			})

			By("checking the policy has type 'Egress'", func() {
				Expect(p.Spec.Types).Should(Equal([]api.PolicyType{api.PolicyTypeEgress}))
			})

			By("checking the policy has no ingress rule", func() {
				Expect(len(p.Spec.Ingress)).Should(Equal(0))
			})
		})
	})
})
