// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package fv_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/kube-controllers/tests/testutils"
	api "github.com/projectcalico/libcalico-go/lib/apis/v2"
	client "github.com/projectcalico/libcalico-go/lib/clientv2"
	"github.com/projectcalico/libcalico-go/lib/names"
	"github.com/projectcalico/libcalico-go/lib/options"
)

var _ = Describe("kube-controllers FV tests", func() {
	var (
		etcd             *containers.Container
		policyController *containers.Container
		apiserver        *containers.Container
		calicoClient     client.Interface
		k8sClient        *kubernetes.Clientset
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		calicoClient = testutils.GetCalicoClient(etcd.IP)
		err := calicoClient.EnsureInitialized()
		Expect(err).NotTo(HaveOccurred())

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		kfconfigfile, err := ioutil.TempFile("", "ginkgo-policycontroller")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(kfconfigfile.Name())
		data := fmt.Sprintf(testutils.KubeconfigTemplate, apiserver.IP)
		kfconfigfile.Write([]byte(data))

		policyController = testutils.RunPolicyController(etcd.IP, kfconfigfile.Name())

		k8sClient, err = testutils.GetK8sClient(kfconfigfile.Name())
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(metav1.ListOptions{})
			return err
		}, 15*time.Second, 500*time.Millisecond).Should(BeNil())
	})

	AfterEach(func() {
		etcd.Stop()
		policyController.Stop()
		apiserver.Stop()
	})

	Context("Profile FV tests", func() {
		var profName string
		BeforeEach(func() {
			nsName := "peanutbutter"
			profName = "kns." + nsName
			ns := &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: nsName,
					Labels: map[string]string{
						"peanut": "butter",
					},
				},
				Spec: v1.NamespaceSpec{},
			}
			_, err := k8sClient.CoreV1().Namespaces().Create(ns)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() *api.Profile {
				profile, _ := calicoClient.Profiles().Get(context.Background(), profName, options.GetOptions{})
				return profile
			}).ShouldNot(BeNil())
		})

		It("should write new profiles in etcd to match namespaces in k8s ", func() {
			_, err := calicoClient.Profiles().Delete(context.Background(), profName, options.DeleteOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Eventually(func() error {
				_, err := calicoClient.Profiles().Get(context.Background(), profName, options.GetOptions{})
				return err
			}, time.Second*15, 500*time.Millisecond).ShouldNot(HaveOccurred())
		})

		It("should update existing profiles in etcd to match namespaces in k8s", func() {
			profile, err := calicoClient.Profiles().Get(context.Background(), profName, options.GetOptions{})
			By("getting the profile", func() {
				Expect(err).ShouldNot(HaveOccurred())

			})

			By("updating the profile to have no labels to apply", func() {
				profile.Spec.LabelsToApply = map[string]string{}
				profile, err := calicoClient.Profiles().Update(context.Background(), profile, options.SetOptions{})

				Expect(err).ShouldNot(HaveOccurred())
				Expect(profile.Spec.LabelsToApply).To(BeEmpty())
			})

			By("waiting for the controller to write back the original labels to apply", func() {
				Eventually(func() map[string]string {
					prof, _ := calicoClient.Profiles().Get(context.Background(), profName, options.GetOptions{})
					return prof.Spec.LabelsToApply
				}, time.Second*15, 500*time.Millisecond).ShouldNot(BeEmpty())
			})
		})
	})

	Describe("NetworkPolicy FV tests", func() {
		var (
			policyName        string
			genPolicyName     string
			policyNamespace   string
			policyLabels      map[string]string
			policyAnnotations map[string]string
		)

		BeforeEach(func() {
			// Create a Kubernetes NetworkPolicy.
			policyName = "jelly"
			genPolicyName = "knp.default." + policyName
			policyNamespace = "default"
			policyAnnotations = map[string]string{
				"annotK": "annotV",
			}
			policyLabels = map[string]string{
				"labelK": "labelV",
			}

			np := &v1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:        policyName,
					Namespace:   policyNamespace,
					Annotations: policyAnnotations,
					Labels:      policyLabels,
				},
				Spec: v1beta1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"fools": "gold",
						},
					},
				},
			}
			err := k8sClient.ExtensionsV1beta1().RESTClient().
				Post().
				Resource("networkpolicies").
				Namespace("default").
				Body(np).
				Do().Error()
			Expect(err).NotTo(HaveOccurred())

			// Wait for it to appear in Calico's etcd.
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
				err := k8sClient.ExtensionsV1beta1().RESTClient().
					Delete().
					Resource("networkpolicies").
					Namespace("default").
					Name(policyName).
					Do().Error()
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

	Describe("NetworkPolicy egress FV tests", func() {
		var (
			policyName      string
			genPolicyName   string
			policyNamespace string
		)

		BeforeEach(func() {
			// Create a Kubernetes NetworkPolicy.
			policyName = "jelly"
			genPolicyName = "knp.default." + policyName
			policyNamespace = "default"
			var np *v1beta1.NetworkPolicy
			np = &v1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: policyNamespace,
				},
				Spec: v1beta1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"fools": "gold",
						},
					},
					Egress: []v1beta1.NetworkPolicyEgressRule{
						{
							To: []v1beta1.NetworkPolicyPeer{
								{
									IPBlock: &v1beta1.IPBlock{
										CIDR:   "192.168.0.0/16",
										Except: []string{"192.168.3.0/24"},
									},
								},
							},
						},
					},
					PolicyTypes: []v1beta1.PolicyType{v1beta1.PolicyTypeEgress},
				},
			}

			err := k8sClient.ExtensionsV1beta1().RESTClient().
				Post().
				Resource("networkpolicies").
				Namespace("default").
				Body(np).
				Do().Error()
			Expect(err).NotTo(HaveOccurred())

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
				Expect(len(p.Spec.EgressRules)).Should(Equal(1))
			})

			By("checking the policy has type 'Egress'", func() {
				Expect(p.Spec.Types).Should(Equal([]api.PolicyType{api.PolicyTypeEgress}))
			})

			By("checking the policy has no ingress rule", func() {
				Expect(len(p.Spec.IngressRules)).Should(Equal(0))
			})
		})
	})

	Describe("Pod FV tests", func() {
		It("should not overwrite a workload endpoints container ID", func() {
			// Create a Pod
			podName := "testpod"
			podNamespace := "default"
			nodeName := "127.0.0.1"
			pod := v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: podNamespace,
					Labels: map[string]string{
						"foo": "label1",
					},
				},
				Spec: v1.PodSpec{
					NodeName: nodeName,
					Containers: []v1.Container{
						v1.Container{
							Name:    "container1",
							Image:   "busybox",
							Command: []string{"sleep", "3600"},
						},
					},
				},
			}

			By("creating a Pod in the k8s API", func() {
				_, err := k8sClient.CoreV1().Pods("default").Create(&pod)
				Expect(err).NotTo(HaveOccurred())
			})

			By("updating the pod's status to be running", func() {
				pod.Status.PodIP = "192.168.1.1"
				pod.Status.Phase = v1.PodRunning
				_, err := k8sClient.CoreV1().Pods("default").UpdateStatus(&pod)
				Expect(err).NotTo(HaveOccurred())
			})

			// Mock the job of the CNI plugin by creating the wep in etcd, providing a container ID.
			wep := api.NewWorkloadEndpoint()
			wep.Name = fmt.Sprintf("%s-k8s-%s-eth0", nodeName, podName)
			wep.Namespace = podNamespace
			wep.Labels = map[string]string{
				"foo": "label1",
				"projectcalico.org/namespace":    podNamespace,
				"projectcalico.org/orchestrator": api.OrchestratorKubernetes,
			}
			wep.Spec = api.WorkloadEndpointSpec{
				ContainerID:  "container_id_1",
				Orchestrator: "k8s",
				Pod:          podName,
				Node:         nodeName,
				Endpoint:     "eth0",
				IPNetworks:   []string{"192.168.1.1"},
			}

			By("creating a corresponding workload endpoint", func() {
				_, err := calicoClient.WorkloadEndpoints().Create(context.Background(), wep, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			By("updating the pod's labels to trigger a cache update", func() {
				// Definitively trigger a pod controller cache update by updating the pod's labels
				// in the Kubernetes API. This ensures the controller has the cached WEP with container_id_1.
				pod.Labels["foo"] = "label2"
				_, err := k8sClient.CoreV1().Pods("default").Update(&pod)
				Expect(err).NotTo(HaveOccurred())
			})

			By("waiting for the new labels to appear in the datastore", func() {
				Eventually(func() error {
					w, err := calicoClient.WorkloadEndpoints().Get(context.Background(), wep.Namespace, wep.Name, options.GetOptions{})
					if err != nil {
						return err
					}

					if w.Labels["foo"] != "label2" {
						return fmt.Errorf("%v should equal 'label2'", w.Labels["foo"])
					}
					return nil
				}, 3*time.Second).ShouldNot(HaveOccurred())
			})

			By("updating the workload endpoint's container ID", func() {
				var err error
				var gwep *api.WorkloadEndpoint
				for i := 0; i < 5; i++ {
					// This emulates a scenario in which the CNI plugin can be called for the same Kubernetes
					// Pod multiple times with a different container ID.
					gwep, err = calicoClient.WorkloadEndpoints().Get(context.Background(), wep.Namespace, wep.Name, options.GetOptions{})
					if err != nil {
						time.Sleep(1 * time.Second)
						continue
					}

					gwep.Spec.ContainerID = "container_id_2"
					_, err = calicoClient.WorkloadEndpoints().Update(context.Background(), gwep, options.SetOptions{})
					if err != nil {
						time.Sleep(1 * time.Second)
						continue
					}
				}
				Expect(err).NotTo(HaveOccurred())
			})

			By("updating the pod's labels a second time to trigger a datastore sync", func() {
				// Trigger a pod 'update' in the pod controller by updating the pod's labels.
				pod.Labels["foo"] = "label3"
				_, err := k8sClient.CoreV1().Pods(podNamespace).Update(&pod)
				Expect(err).NotTo(HaveOccurred())
			})

			var w *api.WorkloadEndpoint
			By("waiting for the labels to appear in the datastore", func() {
				Eventually(func() error {
					var err error
					w, err = calicoClient.WorkloadEndpoints().Get(context.Background(), wep.Namespace, wep.Name, options.GetOptions{})
					if err != nil {
						return err
					}
					if w.Labels["foo"] != "label3" {
						return fmt.Errorf("%v should equal 'label3'", w.Labels["foo"])
					}
					return nil
				}, 3*time.Second).ShouldNot(HaveOccurred())
			})

			By("expecting the container ID to be correct", func() {
				Expect(w.Spec.ContainerID).To(Equal("container_id_2"))
			})
		})
	})

	It("should not create a workload endpoint when one does not already exist", func() {
		// Create a Pod
		podName := "testpod"
		pod := v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: "default",
				Labels: map[string]string{
					"foo": "label1",
				},
			},
			Spec: v1.PodSpec{
				NodeName: "127.0.0.1",
				Containers: []v1.Container{
					v1.Container{
						Name:    "container1",
						Image:   "busybox",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}

		By("creating a Pod in the k8s API", func() {
			_, err := k8sClient.CoreV1().Pods("default").Create(&pod)
			Expect(err).NotTo(HaveOccurred())
		})

		By("updating that pod's labels", func() {
			pod.Labels["foo"] = "label2"
			_, err := k8sClient.CoreV1().Pods("default").Update(&pod)
			Expect(err).NotTo(HaveOccurred())
		})

		wepName, err := names.WorkloadEndpointIdentifiers{
			Node:         "127.0.0.1",
			Orchestrator: "k8s",
			Endpoint:     "eth0",
			Pod:          pod.Name,
		}.CalculateWorkloadEndpointName(false)
		By("calculating the name for a corresponding workload endpoint", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		By("checking no corresponding workload endpoint exists", func() {
			Consistently(func() error {
				_, err := calicoClient.WorkloadEndpoints().Get(context.Background(), "default", wepName, options.GetOptions{})
				return err
			}, 10*time.Second).Should(HaveOccurred())
		})
	})
})
