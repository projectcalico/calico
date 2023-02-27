// Copyright (c) 2017-2022 Tigera, Inc. All rights reserved.
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

package pod_test

import (
	"context"
	"fmt"
	"os"
	"time"

	uuid "github.com/satori/go.uuid"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("Calico pod controller FV tests (etcd mode)", func() {
	var (
		etcd              *containers.Container
		policyController  *containers.Container
		apiserver         *containers.Container
		calicoClient      client.Interface
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		calicoClient = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		kconfigfile, err := os.CreateTemp("", "ginkgo-policycontroller")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(kconfigfile.Name())
		data := testutils.BuildKubeconfig(apiserver.IP)
		_, err = kconfigfile.Write([]byte(data))
		Expect(err).NotTo(HaveOccurred())

		// Make the kubeconfig readable by the container.
		Expect(kconfigfile.Chmod(os.ModePerm)).NotTo(HaveOccurred())

		// Run the controller.
		policyController = testutils.RunPolicyController(apiconfig.EtcdV3, etcd.IP, kconfigfile.Name(), "")

		k8sClient, err = testutils.GetK8sClient(kconfigfile.Name())
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		// Run controller manager.  Empirically it can take around 10s until the
		// controller manager is ready to create default service accounts, even
		// when the k8s image has already been downloaded to run the API
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
					{
						Name:    "container1",
						Image:   "busybox",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}

		By("creating a Pod in the k8s API", func() {
			Eventually(func() error {
				_, err := k8sClient.CoreV1().Pods("default").Create(context.Background(),
					&pod, metav1.CreateOptions{})
				return err
			}, "20s", "2s").ShouldNot(HaveOccurred())
		})

		By("updating the pod's status to be running", func() {
			pod.Status.PodIP = "192.168.1.1"
			pod.Status.Phase = v1.PodRunning
			_, err := k8sClient.CoreV1().Pods("default").UpdateStatus(context.Background(),
				&pod, metav1.UpdateOptions{})
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
		wep := libapi.NewWorkloadEndpoint()
		wep.Name = wepName
		wep.Namespace = podNamespace
		wep.Labels = map[string]string{
			"foo":                            "label1",
			"projectcalico.org/namespace":    podNamespace,
			"projectcalico.org/orchestrator": api.OrchestratorKubernetes,
		}
		wep.Spec = libapi.WorkloadEndpointSpec{
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
			podNow, err := k8sClient.CoreV1().Pods("default").Get(context.Background(), podName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			pod = *podNow
			pod.Labels["foo"] = "label2"
			_, err = k8sClient.CoreV1().Pods("default").Update(context.Background(),
				&pod, metav1.UpdateOptions{})
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
			var gwep *libapi.WorkloadEndpoint
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
			podNow, err := k8sClient.CoreV1().Pods("default").Get(context.Background(),
				podName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			pod = *podNow
			pod.Labels["foo"] = "label3"
			_, err = k8sClient.CoreV1().Pods(podNamespace).Update(context.Background(),
				&pod, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		var w *libapi.WorkloadEndpoint
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

	It("should update serviceaccount appropriately", func() {
		longName := "long-service-account-name-that-exceeds-the-character-limit-for-kubernetes-labels"
		podNamespace := "default"

		// Create serviceaccount.
		sa := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      longName,
				Namespace: podNamespace,
			},
		}
		Eventually(func() error {
			_, err := k8sClient.CoreV1().ServiceAccounts(podNamespace).Create(
				context.Background(),
				sa,
				metav1.CreateOptions{},
			)
			return err
		}, time.Second*10, 500*time.Millisecond).ShouldNot(HaveOccurred())

		// Create a Pod
		podName := fmt.Sprintf("pod-fv-container-id-%s", uuid.NewV4())
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
				NodeName:           nodeName,
				ServiceAccountName: longName,
				Containers: []v1.Container{
					{
						Name:    "container1",
						Image:   "busybox",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}

		By("creating a Pod in the k8s API", func() {
			Eventually(func() error {
				_, err := k8sClient.CoreV1().Pods("default").Create(context.Background(),
					&pod, metav1.CreateOptions{})
				return err
			}, "20s", "2s").ShouldNot(HaveOccurred())
		})

		By("updating the pod's status to be running", func() {
			pod.Status.PodIP = "192.168.1.1"
			pod.Status.Phase = v1.PodRunning
			_, err := k8sClient.CoreV1().Pods("default").UpdateStatus(context.Background(),
				&pod, metav1.UpdateOptions{})
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
		wep := libapi.NewWorkloadEndpoint()
		wep.Name = wepName
		wep.Namespace = podNamespace
		wep.Labels = map[string]string{
			"foo":                            "label1",
			"projectcalico.org/namespace":    podNamespace,
			"projectcalico.org/orchestrator": api.OrchestratorKubernetes,
		}
		wep.Spec = libapi.WorkloadEndpointSpec{
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
			podNow, err := k8sClient.CoreV1().Pods("default").Get(context.Background(), podName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			pod = *podNow
			pod.Labels["foo"] = "label2"
			_, err = k8sClient.CoreV1().Pods("default").Update(context.Background(),
				&pod, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("waiting for the new servcieaccount to appear on the WEP", func() {
			Eventually(func() error {
				w, err := calicoClient.WorkloadEndpoints().Get(context.Background(), wep.Namespace, wep.Name, options.GetOptions{})
				if err != nil {
					return err
				}

				if w.Spec.ServiceAccountName != longName {
					return fmt.Errorf("ServiceAccountName not updated. Current value: %s", w.Spec.ServiceAccountName)
				}
				return nil
			}, 15*time.Second).ShouldNot(HaveOccurred())
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
					{
						Name:    "container1",
						Image:   "busybox",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}

		By("creating a Pod in the k8s API", func() {
			Eventually(func() error {
				_, err := k8sClient.CoreV1().Pods("default").Create(context.Background(),
					&pod, metav1.CreateOptions{})
				return err
			}, "20s", "2s").ShouldNot(HaveOccurred())
		})

		By("updating that pod's labels", func() {
			podNow, err := k8sClient.CoreV1().Pods("default").Get(context.Background(), podName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			pod = *podNow
			pod.Labels["foo"] = "label2"
			_, err = k8sClient.CoreV1().Pods("default").Update(context.Background(), &pod, metav1.UpdateOptions{})
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
