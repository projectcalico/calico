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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"

	extensions "github.com/projectcalico/libcalico-go/lib/backend/extensions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/kube-controllers/tests/testutils"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"k8s.io/client-go/rest"
)

var _ = Describe("PolicyController", func() {
	var (
		etcd             *containers.Container
		policyController *containers.Container
		apiserver        *containers.Container
		calicoClient     *client.Client
		k8sClient        *kubernetes.Clientset
		extensionsClient *rest.RESTClient
	)

	const kNodeName = "k8snodename"
	const cNodeName = "caliconodename"

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

		extensionsClient, err = testutils.GetExtensionsClient(kfconfigfile.Name())
		Expect(err).NotTo(HaveOccurred())

		// TODO: Use upcoming port checker functions to wait until apiserver is responding to requests.
		time.Sleep(time.Second * 15)
	})

	AfterEach(func() {
		etcd.Stop()
		policyController.Stop()
		apiserver.Stop()
	})

	Context("nodes", func() {
		It("should be removed in response to a k8s node delete", func() {
			kn := &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: kNodeName,
				},
			}
			_, err := k8sClient.CoreV1().Nodes().Create(kn)
			Expect(err).NotTo(HaveOccurred())

			cn := &api.Node{
				Metadata: api.NodeMetadata{
					Name: cNodeName,
				},
				Spec: api.NodeSpec{
					OrchRefs: []api.OrchRef{
						{
							NodeName:     kNodeName,
							Orchestrator: "k8s",
						},
					},
				},
			}
			_, err = calicoClient.Nodes().Create(cn)
			Expect(err).NotTo(HaveOccurred())

			k8sClient.CoreV1().Nodes().Delete(kNodeName, &metav1.DeleteOptions{})
			Eventually(func() *api.Node {
				node, _ := calicoClient.Nodes().Get(api.NodeMetadata{Name: cNodeName})
				return node
			}, time.Second*2, 500*time.Millisecond).Should(BeNil())
		})

		It("should be removed if they reference a k8sNode that doesn't exist", func() {
			cn := &api.Node{
				Metadata: api.NodeMetadata{
					Name: cNodeName,
				},
				Spec: api.NodeSpec{
					OrchRefs: []api.OrchRef{
						{
							NodeName:     "k8sfakenode",
							Orchestrator: "k8s",
						},
					},
				},
			}
			_, err := calicoClient.Nodes().Create(cn)
			Expect(err).NotTo(HaveOccurred())

			k8sClient.CoreV1().Nodes().Delete(kNodeName, &metav1.DeleteOptions{})
			Eventually(func() *api.Node {
				node, _ := calicoClient.Nodes().Get(api.NodeMetadata{Name: cNodeName})
				return node
			}, time.Second*15, 500*time.Millisecond).Should(BeNil())
		})

		It("should not be removed in response to a k8s node delete if another orchestrator owns it", func() {
			kn := &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: kNodeName,
				},
			}
			_, err := k8sClient.CoreV1().Nodes().Create(kn)
			Expect(err).NotTo(HaveOccurred())

			cn := &api.Node{
				Metadata: api.NodeMetadata{
					Name: cNodeName,
				},
				Spec: api.NodeSpec{
					OrchRefs: []api.OrchRef{
						{
							NodeName:     kNodeName,
							Orchestrator: "mesos",
						},
					},
				},
			}
			_, err = calicoClient.Nodes().Create(cn)
			Expect(err).NotTo(HaveOccurred())

			k8sClient.CoreV1().Nodes().Delete(kNodeName, &metav1.DeleteOptions{})
			Consistently(func() *api.Node {
				node, _ := calicoClient.Nodes().Get(api.NodeMetadata{Name: cNodeName})
				return node
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeNil())

			node, _ := calicoClient.Nodes().Get(api.NodeMetadata{Name: cNodeName})
			Expect(len(node.Spec.OrchRefs)).Should(Equal(1))
			Expect(node.Spec.OrchRefs[0].Orchestrator).Should(Equal("mesos"))
		})

		It("should not be removed if orchrefs are nil.", func() {
			cn := &api.Node{
				Metadata: api.NodeMetadata{
					Name: cNodeName,
				},
				Spec: api.NodeSpec{},
			}
			_, err := calicoClient.Nodes().Create(cn)
			Expect(err).NotTo(HaveOccurred())

			Consistently(func() *api.Node {
				node, _ := calicoClient.Nodes().Get(api.NodeMetadata{Name: cNodeName})
				return node
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeNil())
		})

		It("should clean up weps, IPAM allocations, etc. when deleting a node", func() {
			// Create a calico pool
			pool := api.IPPool{
				Metadata: api.IPPoolMetadata{
					CIDR: cnet.IPNet{
						IPNet: net.IPNet{
							IP:   net.IP{192, 168, 0, 0},
							Mask: net.IPMask{255, 255, 0, 0},
						},
					},
				},
			}

			affBlock := cnet.IPNet{
				IPNet: net.IPNet{
					IP:   net.IP{192, 168, 0, 0},
					Mask: net.IPMask{255, 255, 255, 0},
				},
			}

			wepIp := net.IP{192, 168, 0, 1}

			_, err := calicoClient.IPPools().Create(&pool)
			Expect(err).NotTo(HaveOccurred())

			kn := &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: kNodeName,
				},
			}
			_, err = k8sClient.CoreV1().Nodes().Create(kn)
			Expect(err).NotTo(HaveOccurred())

			cn := &api.Node{
				Metadata: api.NodeMetadata{
					Name: cNodeName,
				},
				Spec: api.NodeSpec{
					OrchRefs: []api.OrchRef{
						api.OrchRef{
							NodeName:     kNodeName,
							Orchestrator: "k8s",
						},
					},
				},
			}
			_, err = calicoClient.Nodes().Create(cn)
			Expect(err).NotTo(HaveOccurred())

			_, _, err = calicoClient.IPAM().ClaimAffinity(affBlock, cNodeName)
			Expect(err).NotTo(HaveOccurred())

			handle := "myhandle"
			err = calicoClient.IPAM().AssignIP(client.AssignIPArgs{
				IP:       cnet.IP{wepIp},
				Hostname: cNodeName,
				HandleID: &handle,
			})
			Expect(err).NotTo(HaveOccurred())

			wep := api.WorkloadEndpoint{
				Metadata: api.WorkloadEndpointMetadata{
					Name:             "eth0",
					Node:             cNodeName,
					Orchestrator:     "k8s",
					Workload:         "default.fakepod",
					ActiveInstanceID: "aii1",
					Labels: map[string]string{
						"foo": "label1",
					},
				},
				Spec: api.WorkloadEndpointSpec{
					InterfaceName: "eth0",
					IPNetworks: []cnet.IPNet{
						{
							IPNet: net.IPNet{
								IP:   wepIp,
								Mask: net.IPMask{255, 255, 255, 255},
							},
						},
					},
				},
			}
			_, err = calicoClient.WorkloadEndpoints().Create(&wep)
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.CoreV1().Nodes().Delete(kNodeName, &metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Check that the node is removed from Calico
			Eventually(func() *api.Node {
				node, _ := calicoClient.Nodes().Get(api.NodeMetadata{Name: cNodeName})
				return node
			}, time.Second*2, 500*time.Millisecond).Should(BeNil())

			// Check that all other node-specific data was also removed
			// starting with the wep.
			_, err = calicoClient.WorkloadEndpoints().Get(api.WorkloadEndpointMetadata{
				Name:         "eth0",
				Node:         cNodeName,
				Orchestrator: "k8s",
				Workload:     "default.fakepod",
			})

			_, ok := err.(cerrors.ErrorResourceDoesNotExist)
			Expect(ok).Should(BeTrue(), fmt.Sprintf("Got error: %v", err))

			// Check that the wep's IP was released
			ips, err := calicoClient.IPAM().IPsByHandle(handle)
			_, ok = err.(cerrors.ErrorResourceDoesNotExist)
			Expect(ok).Should(BeTrue(), fmt.Sprintf("Got error: %v", err))
			Expect(ips).Should(BeEmpty())

			// Check that the host affinity pool was released. Since there's no method to do this directly,
			// just try to claim the same pool
			_, _, err = calicoClient.IPAM().ClaimAffinity(affBlock, cNodeName)
			Expect(err).NotTo(HaveOccurred())

		})
	})

	Context("profiles", func() {
		var profName string
		BeforeEach(func() {
			nsName := "peanutbutter"
			profName = "k8s_ns." + nsName
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
				profile, _ := calicoClient.Profiles().Get(api.ProfileMetadata{Name: "k8s_ns.peanutbutter"})
				return profile
			}).ShouldNot(BeNil())
		})

		It("should write new profiles in etcd to match namespaces in k8s ", func() {
			err := calicoClient.Profiles().Delete(api.ProfileMetadata{Name: profName})
			Expect(err).ShouldNot(HaveOccurred())
			Eventually(func() error {
				_, err := calicoClient.Profiles().Get(api.ProfileMetadata{Name: profName})
				return err
			}, time.Second*15, 500*time.Millisecond).ShouldNot(HaveOccurred())
		})
		It("should update existing profiles in etcd to match namespaces in k8s", func() {
			profile, err := calicoClient.Profiles().Update(&api.Profile{Metadata: api.ProfileMetadata{Name: profName}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(profile.Metadata.Labels).To(BeNil())
			Eventually(func() map[string]string {
				prof, _ := calicoClient.Profiles().Get(api.ProfileMetadata{Name: profName})
				return prof.Metadata.Labels
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeEmpty())
		})
	})

	Describe("policies", func() {
		var policyName string
		var genPolicyName string

		BeforeEach(func() {
			// Create a Kubernetes NetworkPolicy.
			policyName = "jelly"
			genPolicyName = "knp.default.default." + policyName
			var np *extensions.NetworkPolicy
			np = &extensions.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: "default",
				},
				Spec: extensions.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"fools": "gold",
						},
					},
				},
			}
			err := extensionsClient.
				Post().
				Resource("networkpolicies").
				Namespace("default").
				Body(np).
				Do().Error()
			Expect(err).NotTo(HaveOccurred())

			// Wait for it to appear in Calico's etcd.
			Eventually(func() *api.Policy {
				policy, _ := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return policy
			}).ShouldNot(BeNil())
		})

		It("should re-write policies in etcd to match policies in k8s", func() {
			// Delete the Policy.
			err := calicoClient.Policies().Delete(api.PolicyMetadata{Name: genPolicyName})
			Expect(err).ShouldNot(HaveOccurred())

			// Wait for the policy-controller to write it back.
			Eventually(func() error {
				_, err := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return err
			}, time.Second*15, 500*time.Millisecond).ShouldNot(HaveOccurred())
		})

		It("should re-program policies", func() {
			// Change the selector of the policy in etcd.
			_, err := calicoClient.Policies().Update(&api.Policy{
				Metadata: api.PolicyMetadata{Name: genPolicyName},
				Spec: api.PolicySpec{
					Selector: "calico/k8s_ns == 'default' && ping == 'pong'",
				},
			})
			Expect(err).ShouldNot(HaveOccurred())

			// Wait for the policy-controller to set it back to its original value.
			Eventually(func() string {
				p, _ := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return p.Spec.Selector
			}, time.Second*15, 500*time.Millisecond).Should(Equal("calico/k8s_ns == 'default' && fools == 'gold'"))
		})
	})

	Describe("policies", func() {
		var policyName string
		var genPolicyName string

		BeforeEach(func() {
			// Create a Kubernetes NetworkPolicy.
			policyName = "jelly"
			genPolicyName = "knp.default.default." + policyName
			var np *extensions.NetworkPolicy
			np = &extensions.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: "default",
				},
				Spec: extensions.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"fools": "gold",
						},
					},
					Egress: []extensions.NetworkPolicyEgressRule{
						{
							To: []extensions.NetworkPolicyPeer{
								{
									IPBlock: &extensions.IPBlock{
										CIDR:   "192.168.0.0/16",
										Except: []string{"192.168.3.0/24"},
									},
								},
							},
						},
					},
					PolicyTypes: []extensions.PolicyType{extensions.PolicyTypeEgress},
				},
			}

			err := extensionsClient.
				Post().
				Resource("networkpolicies").
				Namespace("default").
				Body(np).
				Do().Error()
			Expect(err).NotTo(HaveOccurred())

			// Wait for it to appear in Calico's etcd.
			Eventually(func() *api.Policy {
				policy, _ := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return policy
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeNil())
		})

		It("contains correct egress rule", func() {
			// Verify policy controller indicates correct namespace
			Eventually(func() string {
				p, _ := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return p.Spec.Selector
			}, time.Second*10, 500*time.Millisecond).Should(Equal("calico/k8s_ns == 'default' && fools == 'gold'"))

			// Verify one egress rule
			Eventually(func() int {
				p, _ := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return len(p.Spec.EgressRules)
			}, time.Second*10, 500*time.Millisecond).Should(Equal(1))

			// Verify egress rule's types
			Eventually(func() []api.PolicyType {
				p, _ := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return p.Spec.Types
			}, time.Second*10, 500*time.Millisecond).Should(Equal([]api.PolicyType{"egress"}))

			// Verify no ingress rule
			Eventually(func() int {
				p, _ := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return len(p.Spec.IngressRules)
			}, time.Second*10, 500*time.Millisecond).Should(Equal(0))
		})
	})

	Describe("pod", func() {
		It("labels are updated and active instance ids are respected", func() {
			// Create a Pod
			var wep api.WorkloadEndpoint
			podName := "pod"
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
			_, err := k8sClient.CoreV1().Pods("default").Create(&pod)
			Expect(err).NotTo(HaveOccurred())

			// Update the Pod to 'running' and an IP.
			pod.Status.PodIP = "192.168.1.1"
			pod.Status.Phase = v1.PodRunning
			_, err = k8sClient.Pods("default").UpdateStatus(&pod)
			Expect(err).NotTo(HaveOccurred())

			// Mock the job of the CNI plugin by creating the wep in etcd, and assign the ActiveInstanceID.
			wep = api.WorkloadEndpoint{
				Metadata: api.WorkloadEndpointMetadata{
					Name:             "eth0",
					Node:             pod.Spec.NodeName,
					Orchestrator:     "k8s",
					Workload:         "default." + podName,
					ActiveInstanceID: "aii1",
					Labels: map[string]string{
						"foo": "label1",
					},
				},
				Spec: api.WorkloadEndpointSpec{
					InterfaceName: "eth0",
				},
			}
			_, err = calicoClient.WorkloadEndpoints().Create(&wep)
			Expect(err).NotTo(HaveOccurred())

			// Definitively trigger a policy controller cache update by updating a pod's labels
			idMetadata := api.WorkloadEndpointMetadata{
				Name:         "eth0",
				Node:         pod.Spec.NodeName,
				Orchestrator: "k8s",
				Workload:     "default." + podName,
			}
			pod.ObjectMeta.Labels["foo"] = "label2"
			_, err = k8sClient.CoreV1().Pods("default").Update(&pod)
			Expect(err).NotTo(HaveOccurred())

			// Wait for the policy controller to update the web with the new labels
			Eventually(func() error {
				w, err := calicoClient.WorkloadEndpoints().Get(idMetadata)
				if err != nil {
					return err
				}
				if w.Metadata.Labels["foo"] != "label2" {
					return fmt.Errorf("%v should equal 'label2'", w.Metadata.Labels["foo"])
				}
				return nil
			}, 3*time.Second).ShouldNot(HaveOccurred())

			// Update the wep's ActiveInstanceID.
			wep.Metadata.ActiveInstanceID = "aii2"
			_, err = calicoClient.WorkloadEndpoints().Update(&wep)
			Expect(err).NotTo(HaveOccurred())

			// Trigger a pod 'update' in policy controller by updating the pods labels
			pod.Labels["foo"] = "label3"
			_, err = k8sClient.CoreV1().Pods("default").Update(&pod)
			Expect(err).NotTo(HaveOccurred())

			var w *api.WorkloadEndpoint
			Eventually(func() error {
				var err error
				w, err = calicoClient.WorkloadEndpoints().Get(idMetadata)
				if err != nil {
					return err
				}
				if w.Metadata.Labels["foo"] != "label3" {
					return fmt.Errorf("%v should equal 'label3'", w.Metadata.Labels["foo"])
				}
				return nil
			}, 3*time.Second).ShouldNot(HaveOccurred())

			// Check that the policy controller updated its cache to the new ActiveInstanceID.
			Expect(w.Metadata.ActiveInstanceID).To(Equal("aii2"))
		})
	})

	It("doesn't create a wep when it hears a label update for a pod that is not running yet", func() {
		// Create a Pod
		podName := "pod"
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
		_, err := k8sClient.CoreV1().Pods("default").Create(&pod)
		Expect(err).NotTo(HaveOccurred())

		// Update the pod's labels
		pod.ObjectMeta.Labels["foo"] = "label2"
		_, err = k8sClient.CoreV1().Pods("default").Update(&pod)
		Expect(err).NotTo(HaveOccurred())

		// Check that policy controller *does not* write the wep
		idMetadata := api.WorkloadEndpointMetadata{
			Name:         "eth0",
			Node:         pod.Spec.NodeName,
			Orchestrator: "k8s",
			Workload:     "default." + podName,
		}
		Consistently(func() error {
			_, err := calicoClient.WorkloadEndpoints().Get(idMetadata)
			return err
		}, 10*time.Second).Should(HaveOccurred())
	})
})
