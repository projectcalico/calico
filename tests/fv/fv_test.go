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
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/satori/go.uuid"

	"k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/kube-controllers/tests/testutils"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/names"
	"github.com/projectcalico/libcalico-go/lib/options"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

var _ = Describe("kube-controllers FV tests", func() {
	var (
		etcd              *containers.Container
		policyController  *containers.Container
		apiserver         *containers.Container
		calicoClient      client.Interface
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
	)

	const kNodeName = "k8snodename"
	const cNodeName = "caliconodename"

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		calicoClient = testutils.GetCalicoClient(etcd.IP)

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

		// Run controller manager.  Empirically it can take around 10s until the
		// controller manager is ready to create default service accounts, even
		// when the hyperkube image has already been downloaded to run the API
		// server.  We use Eventually to allow for possible delay when doing
		// initial pod creation below.
		controllerManager = testutils.RunK8sControllerManager(apiserver.IP)
	})

	AfterEach(func() {
		controllerManager.Stop()
		policyController.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	It("should initialize the datastore at start-of-day", func() {
		var info *api.ClusterInformation
		Eventually(func() *api.ClusterInformation {
			info, _ = calicoClient.ClusterInformation().Get(context.Background(), "default", options.GetOptions{})
			return info
		}).ShouldNot(BeNil())

		Expect(info.Spec.ClusterGUID).To(MatchRegexp("^[a-f0-9]{32}$"))
		Expect(info.Spec.ClusterType).To(Equal("k8s"))
		Expect(*info.Spec.DatastoreReady).To(BeTrue())
	})

	Context("Healthcheck FV tests", func() {
		It("should pass health check", func() {
			By("Waiting for an initial readiness report")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", policyController.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 20*time.Second, 500*time.Millisecond).ShouldNot(ContainSubstring("initialized to false"))

			By("Waiting for the controller to be ready")
			Eventually(func() string {
				cmd := exec.Command("docker", "exec", policyController.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return strings.TrimSpace(string(stdoutStderr))
			}, 20*time.Second, 500*time.Millisecond).Should(Equal("Ready"))
		})

		It("should fail health check if apiserver is not running", func() {
			By("Waiting for an initial readiness report")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", policyController.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 20*time.Second, 500*time.Millisecond).ShouldNot(ContainSubstring("initialized to false"))

			By("Stopping the apiserver")
			apiserver.Stop()

			By("Waiting for the readiness to change")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", policyController.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 20*time.Second, 500*time.Millisecond).Should(ContainSubstring("Error reaching apiserver"))
		})

		It("should fail health check if etcd not running", func() {
			By("Waiting for an initial readiness report")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", policyController.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 20*time.Second, 500*time.Millisecond).ShouldNot(ContainSubstring("initialized to false"))

			By("Stopping etcd")
			etcd.Stop()

			By("Waiting for the readiness to change")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", policyController.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 20*time.Second, 500*time.Millisecond).Should(ContainSubstring("Error verifying datastore"))
		})
	})

	Context("Node FV tests", func() {
		It("should be removed in response to a k8s node delete", func() {
			kn := &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: kNodeName,
				},
			}
			_, err := k8sClient.CoreV1().Nodes().Create(kn)
			Expect(err).NotTo(HaveOccurred())
			cn := api.NewNode()
			cn.Name = cNodeName
			cn.Spec = api.NodeSpec{
				OrchRefs: []api.OrchRef{
					{
						NodeName:     kNodeName,
						Orchestrator: "k8s",
					},
				},
			}

			_, err = calicoClient.Nodes().Create(context.Background(), cn, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			k8sClient.CoreV1().Nodes().Delete(kNodeName, &metav1.DeleteOptions{})
			Eventually(func() *api.Node {
				node, _ := calicoClient.Nodes().Get(context.Background(), cNodeName, options.GetOptions{})
				return node
			}, time.Second*2, 500*time.Millisecond).Should(BeNil())
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
				ObjectMeta: metav1.ObjectMeta{
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
			_, err = calicoClient.Nodes().Create(context.Background(), cn, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			k8sClient.CoreV1().Nodes().Delete(kNodeName, &metav1.DeleteOptions{})
			Consistently(func() *api.Node {
				node, _ := calicoClient.Nodes().Get(context.Background(), cNodeName, options.GetOptions{})
				return node
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeNil())

			node, _ := calicoClient.Nodes().Get(context.Background(), cNodeName, options.GetOptions{})
			Expect(len(node.Spec.OrchRefs)).Should(Equal(1))
			Expect(node.Spec.OrchRefs[0].Orchestrator).Should(Equal("mesos"))
		})

		It("should not be removed if orchrefs are nil.", func() {
			cn := &api.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: cNodeName,
				},
				Spec: api.NodeSpec{},
			}
			_, err := calicoClient.Nodes().Create(context.Background(), cn, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			Consistently(func() *api.Node {
				node, _ := calicoClient.Nodes().Get(context.Background(), cNodeName, options.GetOptions{})
				return node
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeNil())
		})

		It("should clean up weps, IPAM allocations, etc. when deleting a node", func() {
			// Create the node in the Kubernetes API.
			kn := &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: kNodeName,
				},
			}
			_, err := k8sClient.CoreV1().Nodes().Create(kn)
			Expect(err).NotTo(HaveOccurred())

			// Create the node object in Calico's datastore.
			cn := &api.Node{
				ObjectMeta: metav1.ObjectMeta{
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
			_, err = calicoClient.Nodes().Create(context.Background(), cn, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Create objects associated with this node.
			pool := api.IPPool{
				Spec: api.IPPoolSpec{
					CIDR: "192.168.0.0/16",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "mypool",
				},
			}
			_, err = calicoClient.IPPools().Create(context.Background(), &pool, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			affBlock := cnet.IPNet{
				IPNet: net.IPNet{
					IP:   net.IP{192, 168, 0, 0},
					Mask: net.IPMask{255, 255, 255, 0},
				},
			}
			_, _, err = calicoClient.IPAM().ClaimAffinity(context.Background(), affBlock, cNodeName)
			Expect(err).NotTo(HaveOccurred())

			handle := "myhandle"
			wepIp := net.IP{192, 168, 0, 1}
			swepIp := "192.168.0.1/32"
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       cnet.IP{IP: wepIp},
				Hostname: cNodeName,
				HandleID: &handle,
			})
			Expect(err).NotTo(HaveOccurred())

			wep := api.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "caliconodename-k8s-mypod-mywep",
					Namespace: "default",
				},
				Spec: api.WorkloadEndpointSpec{
					InterfaceName: "eth0",
					Pod:           "mypod",
					Endpoint:      "mywep",
					IPNetworks: []string{
						swepIp,
					},
					Node:         cNodeName,
					Orchestrator: "k8s",
					Workload:     "default.fakepod",
				},
			}
			_, err = calicoClient.WorkloadEndpoints().Create(context.Background(), &wep, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			bgppeer := api.BGPPeer{
				Spec: api.BGPPeerSpec{
					Node: cNodeName,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "bgppeer1",
				},
			}
			_, err = calicoClient.BGPPeers().Create(context.Background(), &bgppeer, options.SetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			nodeConfigName := fmt.Sprintf("node.%s", cNodeName)
			pTrue := true
			felixConf := api.FelixConfiguration{
				Spec: api.FelixConfigurationSpec{
					IgnoreLooseRPF: &pTrue,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeConfigName,
				},
			}
			_, err = calicoClient.FelixConfigurations().Create(context.Background(), &felixConf, options.SetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			bgpConf := api.BGPConfiguration{
				Spec: api.BGPConfigurationSpec{
					LogSeverityScreen: "Error",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeConfigName,
				},
			}
			_, err = calicoClient.BGPConfigurations().Create(context.Background(), &bgpConf, options.SetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			// Delete the node.
			err = k8sClient.CoreV1().Nodes().Delete(kNodeName, &metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Check that the node is removed from Calico
			Eventually(func() *api.Node {
				node, _ := calicoClient.Nodes().Get(context.Background(), cNodeName, options.GetOptions{})
				return node
			}, time.Second*2, 500*time.Millisecond).Should(BeNil())

			// Check that all other node-specific data was also removed
			// starting with the wep.
			w, _ := calicoClient.WorkloadEndpoints().Get(context.Background(), "default", "calicoodename-k8s-mypod-mywep", options.GetOptions{})
			Expect(w).To(BeNil())

			// Check that the wep's IP was released
			ips, _ := calicoClient.IPAM().IPsByHandle(context.Background(), handle)
			Expect(ips).Should(BeNil())

			// Check that the host affinity was released.
			be := testutils.GetBackendClient(etcd.IP)
			list, err := be.List(
				context.Background(),
				model.BlockAffinityListOptions{
					Host: cNodeName,
				},
				"",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(list.KVPairs).To(HaveLen(0))

		})
	})

	Context("Namespace Profile FV tests", func() {
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
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeNil())
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

	Context("ServiceAccount Profile FV tests", func() {
		var profName string
		BeforeEach(func() {
			saName := "peanutbutter"
			nsName := "default"
			profName = "ksa." + nsName + "." + saName
			sa := &v1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      saName,
					Namespace: nsName,
					Labels: map[string]string{
						"peanut": "butter",
					},
				},
			}
			_, err := k8sClient.CoreV1().ServiceAccounts(nsName).Create(sa)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() *api.Profile {
				profile, _ := calicoClient.Profiles().Get(context.Background(), profName, options.GetOptions{})
				return profile
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeNil())
		})

		It("should write new profiles in etcd to match service account in k8s ", func() {
			// Delete profile and then check if it is re-created.
			_, err := calicoClient.Profiles().Delete(context.Background(), profName, options.DeleteOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Eventually(func() error {
				_, err := calicoClient.Profiles().Get(context.Background(), profName, options.GetOptions{})
				return err
			}, time.Second*15, 500*time.Millisecond).ShouldNot(HaveOccurred())
		})

		It("should update existing profiles in etcd to match service account in k8s", func() {
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

	Context("NetworkPolicy FV tests", func() {
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

			np := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:        policyName,
					Namespace:   policyNamespace,
					Annotations: policyAnnotations,
					Labels:      policyLabels,
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"fools": "gold",
						},
					},
				},
			}
			err := k8sClient.NetworkingV1().RESTClient().
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
				err := k8sClient.NetworkingV1().RESTClient().
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

	Context("NetworkPolicy egress FV tests", func() {
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
			var np *networkingv1.NetworkPolicy
			np = &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
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

			err := k8sClient.NetworkingV1().RESTClient().
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

	Context("Pod FV tests", func() {
		It("should not overwrite a workload endpoint's container ID", func() {
			// Create a Pod
			podName := fmt.Sprintf("pod-fv-container-id-%s", uuid.NewV4())
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
				Eventually(func() error {
					_, err := k8sClient.CoreV1().Pods("default").Create(&pod)
					return err
				}, "20s", "2s").ShouldNot(HaveOccurred())
			})

			By("updating the pod's status to be running", func() {
				pod.Status.PodIP = "192.168.1.1"
				pod.Status.Phase = v1.PodRunning
				_, err := k8sClient.CoreV1().Pods("default").UpdateStatus(&pod)
				Expect(err).NotTo(HaveOccurred())
			})

			// Mock the job of the CNI plugin by creating the wep in etcd, providing a container ID.
			wepIDs := names.WorkloadEndpointIdentifiers{
				Node:         pod.Spec.NodeName,
				Orchestrator: "k8s",
				Endpoint:     "eth0",
				Pod:          pod.Name,
			}
			wepName, err := wepIDs.CalculateWorkloadEndpointName(false)
			Expect(err).NotTo(HaveOccurred())
			wep := api.NewWorkloadEndpoint()
			wep.Name = wepName
			wep.Namespace = podNamespace
			wep.Labels = map[string]string{
				"foo": "label1",
				"projectcalico.org/namespace":    podNamespace,
				"projectcalico.org/orchestrator": api.OrchestratorKubernetes,
			}
			wep.Spec = api.WorkloadEndpointSpec{
				ContainerID:   "container-id-1",
				Orchestrator:  "k8s",
				Pod:           podName,
				Node:          nodeName,
				Endpoint:      "eth0",
				IPNetworks:    []string{"192.168.1.1/32"},
				InterfaceName: "testInterface",
			}

			By("creating a corresponding workload endpoint", func() {
				_, err := calicoClient.WorkloadEndpoints().Create(context.Background(), wep, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			By("updating the pod's labels to trigger a cache update", func() {
				// Definitively trigger a pod controller cache update by updating the pod's labels
				// in the Kubernetes API. This ensures the controller has the cached WEP with container-id-1.
				podNow, err := k8sClient.CoreV1().Pods("default").Get(podName, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				pod = *podNow
				pod.Labels["foo"] = "label2"
				_, err = k8sClient.CoreV1().Pods("default").Update(&pod)
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
				}, 15*time.Second).ShouldNot(HaveOccurred())
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

					gwep.Spec.ContainerID = "container-id-2"
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
				podNow, err := k8sClient.CoreV1().Pods("default").Get(podName, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				pod = *podNow
				pod.Labels["foo"] = "label3"
				_, err = k8sClient.CoreV1().Pods(podNamespace).Update(&pod)
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
				Expect(w.Spec.ContainerID).To(Equal("container-id-2"))
			})
		})
	})

	It("should not create a workload endpoint when one does not already exist", func() {
		// Create a Pod
		podName := fmt.Sprintf("pod-fv-no-create-wep-%s", uuid.NewV4())
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
			Eventually(func() error {
				_, err := k8sClient.CoreV1().Pods("default").Create(&pod)
				return err
			}, "20s", "2s").ShouldNot(HaveOccurred())
		})

		By("updating that pod's labels", func() {
			podNow, err := k8sClient.CoreV1().Pods("default").Get(podName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			pod = *podNow
			pod.Labels["foo"] = "label2"
			_, err = k8sClient.CoreV1().Pods("default").Update(&pod)
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
