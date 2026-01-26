// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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

package node_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	backend "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var (
	// Configure timeoutes for the tests. We expedite leak detection in order to speed up the tests.
	leakGracePeriod = 1 * time.Second

	// We don't want consistently blocks to take too long - but they need to wait at least a few
	// grace periods to do their job.
	consistentlyTimeout  = 3 * leakGracePeriod
	consistentlyInterval = consistentlyTimeout / 10

	retryInterval = 100 * time.Millisecond
)

var _ = Describe("IPAM garbage collection FV tests with short leak grace period", func() {
	var (
		etcd              *containers.Container
		controller        *containers.Container
		apiserver         *containers.Container
		calicoClient      client.Interface
		bc                backend.Client
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
		nodeA             string
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		var err error
		kconfigfile, cancel := testutils.BuildKubeconfig(apiserver.IP)
		defer cancel()

		k8sClient, err = testutils.GetK8sClient(kconfigfile)
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, retryInterval).Should(BeNil())

		// Apply the necessary CRDs. There can sometimes be a delay between starting
		// the API server and when CRDs are apply-able, so retry here.
		testutils.ApplyCRDs(apiserver)

		// Make a Calico client and backend client.
		type accessor interface {
			Backend() backend.Client
		}
		calicoClient = testutils.GetCalicoClient(apiconfig.Kubernetes, "", kconfigfile)
		bc = calicoClient.(accessor).Backend()

		// Create an IP pool with room for 4 blocks.
		By("creating an IP pool for the test", func() {
			p := api.NewIPPool()
			p.Name = "test-ipam-gc-ippool"
			p.Spec.CIDR = "192.168.0.0/24"
			p.Spec.BlockSize = 26
			p.Spec.NodeSelector = "all()"
			p.Spec.Disabled = false
			_, err = calicoClient.IPPools().Create(context.Background(), p, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		// Set the leak grace period to a short duration to speed up the test.
		By("shortening the leak grace period for the test", func() {
			kcc := api.NewKubeControllersConfiguration()
			kcc.Name = "default"
			kcc.Spec.Controllers.Node = &api.NodeControllerConfig{LeakGracePeriod: &metav1.Duration{Duration: leakGracePeriod}}
			_, err = calicoClient.KubeControllersConfiguration().Create(context.Background(), kcc, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())
		})

		By("creating a node for the test", func() {
			nodeA = "node-a"
			_, err = k8sClient.CoreV1().Nodes().Create(context.Background(),
				&v1.Node{
					TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: nodeA},
					Spec:       v1.NodeSpec{},
				},
				metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("creating a serviceaccount for the test", func() {
			sa := &v1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: "default",
				},
			}
			Eventually(func() error {
				_, err := k8sClient.CoreV1().ServiceAccounts("default").Create(
					context.Background(),
					sa,
					metav1.CreateOptions{},
				)
				return err
			}, time.Second*10, retryInterval).ShouldNot(HaveOccurred())
		})

		// Start the controller.
		controller = testutils.RunKubeControllers(apiconfig.Kubernetes, "", kconfigfile, "node")

		// Run controller manager.
		controllerManager = testutils.RunK8sControllerManager(apiserver.IP)
	})

	AfterEach(func() {
		// Delete the IP pool.
		_, err := calicoClient.IPPools().Delete(context.Background(), "test-ipam-gc-ippool", options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		_ = calicoClient.Close()
		controllerManager.Stop()
		controller.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	It("should NOT clean up tunnel IP allocations", func() {
		var err error

		// Allocate all kinds of tunnel IPs to the node.
		handleAIPIP := "handleAIPIP"
		handleAVXLAN := "handleAVXLAN"
		handleAWG := "handleAWireguard"
		By("allocating tunnel addresses to the node", func() {
			// Allocate an IPIP, VXLAN and WG address to NodeA as well.
			// These only get cleaned up if the node is deleted, so for this test should never be GC'd.
			attrs := map[string]string{"node": nodeA, "type": "ipipTunnelAddress"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.10"), HandleID: &handleAIPIP, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())

			attrs = map[string]string{"node": nodeA, "type": "vxlanTunnelAddress"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.11"), HandleID: &handleAVXLAN, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())

			attrs = map[string]string{"node": nodeA, "type": "wireguardTunnelAddress"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.12"), HandleID: &handleAWG, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		// Expect the correct blocks to exist as a result of the IPAM allocations above.
		blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(blocks.KVPairs)).To(Equal(1))
		affs, err := bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeA, AffinityType: string(ipam.AffinityTypeHost)}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(affs.KVPairs)).To(Equal(1))

		// Expect the tunnel IPs to not have been cleaned up.
		Consistently(func() error {
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleAIPIP, 1); err != nil {
				return err
			}
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleAVXLAN, 1); err != nil {
				return err
			}
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleAWG, 1); err != nil {
				return err
			}
			if err := assertNumBlocks(bc, 1); err != nil {
				return err
			}
			return nil
		}, consistentlyTimeout, consistentlyInterval).Should(BeNil())
	})

	It("should clean up empty blocks after the grace period", func() {
		// Allocate and then release an IP to create an empty block.
		handle := "block-gc-test-handle"
		By("allocating an IP address to create a valid block", func() {
			attrs := map[string]string{"node": nodeA}
			err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.1"), HandleID: &handle, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		handle2 := "block-gc-test-handle-2"
		By("allocating an IP address to create a second valid block", func() {
			attrs := map[string]string{"node": nodeA}
			err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.65"), HandleID: &handle2, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		// Expect two blocks, both affine to node A.
		blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(blocks.KVPairs)).To(Equal(2))
		affs, err := bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeA, AffinityType: string(ipam.AffinityTypeHost)}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(affs.KVPairs)).To(Equal(2))

		By("releasing the second IP address to create an empty affine block", func() {
			unalloc, _, err := calicoClient.IPAM().ReleaseIPs(context.Background(), ipam.ReleaseOptions{Address: "192.168.0.65", Handle: handle2})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(unalloc)).To(Equal(0))
		})

		// Expect the block to be cleaned up by the GC, eventually.
		Eventually(func() error {
			return assertNumBlocks(bc, 1)
		}, 15*time.Second, retryInterval).Should(BeNil())
	})

	It("should NOT clean up allocations that are not Kubernetes pods", func() {
		var err error
		handleNonKubernetes := "handle-not-kubernetes"
		By("allocate an IP address that does not belong to a k8s pod", func() {
			// This is not a k8s pod, so doesn't get the pod or namespace attributes.
			attrs := map[string]string{"node": "non-kubernetes-node"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.1"), HandleID: &handleNonKubernetes, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		// Expect the correct blocks to exist as a result of the IPAM allocations above.
		blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(blocks.KVPairs)).To(Equal(1))
		affs, err := bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeA, AffinityType: string(ipam.AffinityTypeHost)}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(affs.KVPairs)).To(Equal(1))

		// The allocation should not be cleaned up.
		Consistently(func() error {
			// Pod doesn't exist.
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleNonKubernetes, 1); err != nil {
				return err
			}
			if err := assertNumBlocks(bc, 1); err != nil {
				return err
			}
			return nil
		}, consistentlyTimeout, consistentlyInterval).Should(BeNil())
	})

	It("should clean up an IP with no corresponding pod", func() {
		var err error
		handleMissingPod := "handle-missing-pod"
		By("allocation an IP address to simulate a leak", func() {
			// Allocate a pod IP address and thus a block and affinity to NodeA.
			// We won't create a corresponding pod API object, thus simulating an IP address leak.
			attrs := map[string]string{"node": nodeA, "pod": "missing-pod", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.1"), HandleID: &handleMissingPod, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		// Expect the correct blocks to exist as a result of the IPAM allocations above.
		blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(blocks.KVPairs)).To(Equal(1))
		affs, err := bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeA, AffinityType: string(ipam.AffinityTypeHost)}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(affs.KVPairs)).To(Equal(1))

		// Eventually, garbage collection will notice that "missing-pod" does not exist, and the IP address
		// will be deleted. The GC takes some time, so wait up to a full minute.
		Eventually(func() error {
			// Pod doesn't exist.
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleMissingPod, 0); err != nil {
				return err
			}
			if err := assertNumBlocks(bc, 1); err != nil {
				return err
			}
			return nil
		}, time.Minute, retryInterval).Should(BeNil())
	})

	It("should NOT garbage collect a valid IP address (status.PodIP)", func() {
		var err error
		handleValidIP := "handle-valid-ip"
		By("allocating an IP address to simulate a valid IP allocation", func() {
			// We will create a pod API object for this IP, simulating a valid IP that is NOT a leak.
			// We do not expect this IP address to be GC'd.
			attrs := map[string]string{"node": nodeA, "pod": "pod-with-valid-ip", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.2"), HandleID: &handleValidIP, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		var pod *v1.Pod
		By("creating a Pod for the valid IP address", func() {
			pod = &v1.Pod{
				TypeMeta:   metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "pod-with-valid-ip", Namespace: "default"},
				Spec: v1.PodSpec{
					NodeName: nodeA,
					Containers: []v1.Container{
						{
							Name:    "container1",
							Image:   "busybox",
							Command: []string{"sleep", "3600"},
						},
					},
				},
			}
			pod, err = k8sClient.CoreV1().Pods("default").Create(context.Background(), pod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("updating the Pod to be running", func() {
			pod.Status.PodIP = "192.168.0.2"
			pod.Status.Phase = v1.PodRunning
			_, err = k8sClient.CoreV1().Pods("default").UpdateStatus(context.Background(), pod, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		// Expect the correct blocks to exist as a result of the IPAM allocations above.
		blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(blocks.KVPairs)).To(Equal(1))
		affs, err := bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeA, AffinityType: string(ipam.AffinityTypeHost)}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(affs.KVPairs)).To(Equal(1))

		// The valid IP should not be cleaned up.
		Consistently(func() error {
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleValidIP, 1); err != nil {
				return err
			}
			if err := assertNumBlocks(bc, 1); err != nil {
				return err
			}
			return nil
		}, consistentlyTimeout, consistentlyInterval).Should(BeNil())
	})

	It("should NOT garbage collect a valid IP address (status.PodIPs)", func() {
		var err error
		handleValidIP := "handle-valid-ip"
		By("allocating an IP address to simulate a valid IP allocation", func() {
			// We will create a pod API object for this IP, simulating a valid IP that is NOT a leak.
			// We do not expect this IP address to be GC'd.
			attrs := map[string]string{"node": nodeA, "pod": "pod-with-valid-ip", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.2"), HandleID: &handleValidIP, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		var pod *v1.Pod
		By("creating a Pod for the valid IP address", func() {
			pod = &v1.Pod{
				TypeMeta:   metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "pod-with-valid-ip", Namespace: "default"},
				Spec: v1.PodSpec{
					NodeName: nodeA,
					Containers: []v1.Container{
						{
							Name:    "container1",
							Image:   "busybox",
							Command: []string{"sleep", "3600"},
						},
					},
				},
			}
			pod, err = k8sClient.CoreV1().Pods("default").Create(context.Background(), pod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("updating the Pod to be running", func() {
			pod.Status.PodIPs = []v1.PodIP{
				{IP: "fe80::00"},
				{IP: "192.168.0.2"},
			}
			pod.Status.Phase = v1.PodRunning
			_, err = k8sClient.CoreV1().Pods("default").UpdateStatus(context.Background(), pod, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		// Expect the correct blocks to exist as a result of the IPAM allocations above.
		blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(blocks.KVPairs)).To(Equal(1))
		affs, err := bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeA, AffinityType: string(ipam.AffinityTypeHost)}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(affs.KVPairs)).To(Equal(1))

		// The valid IP should not be cleaned up.
		Consistently(func() error {
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleValidIP, 1); err != nil {
				return err
			}
			if err := assertNumBlocks(bc, 1); err != nil {
				return err
			}
			return nil
		}, consistentlyTimeout, consistentlyInterval).Should(BeNil())
	})

	It("should NOT clean up an IP if the matching pod does not yet have an address in the API", func() {
		var err error
		handleValidNotYetReported := "handle-valid-ip-not-in-api"
		By("allocating an IP address to simulate a valid IP allocation", func() {
			// We will create a pod API object for this IP, but we will not update the status,
			// simulating a valid IP that is NOT a leak but has yet to be reported to the k8s API.
			// We do not expect this IP address to be GC'd.
			attrs := map[string]string{"node": nodeA, "pod": "pod-with-valid-ip-not-in-api", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.3"), HandleID: &handleValidNotYetReported, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		// Create a pod, but don't give it an address yet.
		var pod *v1.Pod
		By("creating a Pod for the valid IP address", func() {
			pod = &v1.Pod{
				TypeMeta:   metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "pod-with-valid-ip-not-in-api", Namespace: "default"},
				Spec: v1.PodSpec{
					NodeName: nodeA,
					Containers: []v1.Container{
						{
							Name:    "container1",
							Image:   "busybox",
							Command: []string{"sleep", "3600"},
						},
					},
				},
			}
			pod, err = k8sClient.CoreV1().Pods("default").Create(context.Background(), pod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		// Expect the correct blocks to exist as a result of the IPAM allocations above.
		blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(blocks.KVPairs)).To(Equal(1))
		affs, err := bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeA, AffinityType: string(ipam.AffinityTypeHost)}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(affs.KVPairs)).To(Equal(1))

		// Expect the address not to be cleaned up.
		Eventually(func() error {
			// Pod doesn't exist.
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleValidNotYetReported, 1); err != nil {
				return err
			}

			if err := assertNumBlocks(bc, 1); err != nil {
				return err
			}
			return nil
		}, 30*time.Second, retryInterval).Should(BeNil())
	})

	It("should GC IP allocations if they do not match the pod's IP", func() {
		var err error
		handleMismatchedIP := "handle-ip-not-match"
		By("allocating an IP address to simulate a second leaked IP allocation", func() {
			// We will create a pod API object for this IP, but the pod will have a different IP reported.
			// This simulates the scenario where the IP address for the pod has changed.
			attrs := map[string]string{"node": nodeA, "pod": "pod-mismatched-ip", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.4"), HandleID: &handleMismatchedIP, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		var pod *v1.Pod
		By("creating a Pod for the mismatched test case", func() {
			pod = &v1.Pod{
				TypeMeta:   metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "pod-mismatched-ip", Namespace: "default"},
				Spec: v1.PodSpec{
					NodeName: nodeA,
					Containers: []v1.Container{
						{
							Name:    "container1",
							Image:   "busybox",
							Command: []string{"sleep", "3600"},
						},
					},
				},
			}
			pod, err = k8sClient.CoreV1().Pods("default").Create(context.Background(), pod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("updating the Pod to be running, with the wrong IP", func() {
			pod.Status.PodIP = "192.168.30.5"
			pod.Status.Phase = v1.PodRunning
			_, err = k8sClient.CoreV1().Pods("default").UpdateStatus(context.Background(), pod, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		// Expect the correct blocks to exist as a result of the IPAM allocations above.
		blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(blocks.KVPairs)).To(Equal(1))
		affs, err := bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeA, AffinityType: string(ipam.AffinityTypeHost)}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(affs.KVPairs)).To(Equal(1))

		// Eventually the IP will be GC'd
		Eventually(func() error {
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleMismatchedIP, 0); err != nil {
				return err
			}
			if err := assertNumBlocks(bc, 1); err != nil {
				return err
			}
			return nil
		}, time.Minute, retryInterval).Should(BeNil())
	})
})

var _ = Describe("IPAM garbage collection FV tests with long leak grace period", func() {
	var (
		etcd              *containers.Container
		controller        *containers.Container
		apiserver         *containers.Container
		calicoClient      client.Interface
		bc                backend.Client
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
		kconfigfile       string
		nodeA             string
		removeKubeconfig  func()
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		var err error
		kconfigfile, removeKubeconfig = testutils.BuildKubeconfig(apiserver.IP)

		k8sClient, err = testutils.GetK8sClient(kconfigfile)
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, retryInterval).Should(BeNil())

		// Apply the necessary CRDs. There can sometimes be a delay between starting
		// the API server and when CRDs are apply-able, so retry here.
		testutils.ApplyCRDs(apiserver)

		// Make a Calico client and backend client.
		type accessor interface {
			Backend() backend.Client
		}
		calicoClient = testutils.GetCalicoClient(apiconfig.Kubernetes, "", kconfigfile)
		bc = calicoClient.(accessor).Backend()

		// Create an IP pool with room for 4 blocks.
		By("creating an IP pool for the test", func() {
			p := api.NewIPPool()
			p.Name = "test-ipam-gc-ippool"
			p.Spec.CIDR = "192.168.0.0/24"
			p.Spec.BlockSize = 26
			p.Spec.NodeSelector = "all()"
			p.Spec.Disabled = false
			_, err = calicoClient.IPPools().Create(context.Background(), p, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		// Set a long grace period. The tests in this suite verify behavior of the controller before the
		// grace period has been hit.
		By("lengthening the leak grace period for the test", func() {
			kcc := api.NewKubeControllersConfiguration()
			kcc.Name = "default"
			kcc.Spec.Controllers.Node = &api.NodeControllerConfig{LeakGracePeriod: &metav1.Duration{Duration: 5 * time.Minute}}
			_, err = calicoClient.KubeControllersConfiguration().Create(context.Background(), kcc, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())
		})

		By("creating a node for the test", func() {
			nodeA = "node-a"
			_, err = k8sClient.CoreV1().Nodes().Create(context.Background(),
				&v1.Node{
					TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: nodeA},
					Spec:       v1.NodeSpec{},
				},
				metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("creating a serviceaccount for the test", func() {
			sa := &v1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: "default",
				},
			}
			Eventually(func() error {
				_, err := k8sClient.CoreV1().ServiceAccounts("default").Create(
					context.Background(),
					sa,
					metav1.CreateOptions{},
				)
				return err
			}, time.Second*10, retryInterval).ShouldNot(HaveOccurred())
		})

		// Start the controller.
		controller = testutils.RunKubeControllers(apiconfig.Kubernetes, "", kconfigfile, "node")

		// Run controller manager.
		controllerManager = testutils.RunK8sControllerManager(apiserver.IP)
	})

	AfterEach(func() {
		// Delete the IP pool.
		_, err := calicoClient.IPPools().Delete(context.Background(), "test-ipam-gc-ippool", options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		_ = calicoClient.Close()
		controllerManager.Stop()
		controller.Stop()
		apiserver.Stop()
		etcd.Stop()
		removeKubeconfig()
	})

	It("should NOT clean up empty blocks within the grace period", func() {
		// Allocate and then release an IP to create an empty block.
		handle := "block-gc-test-handle"
		By("allocating an IP address to create a valid block", func() {
			attrs := map[string]string{"node": nodeA}
			err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.1"), HandleID: &handle, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		handle2 := "block-gc-test-handle-2"
		By("allocating an IP address to create a second valid block", func() {
			attrs := map[string]string{"node": nodeA}
			err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.65"), HandleID: &handle2, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		// Expect two blocks, both affine to node A.
		blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(blocks.KVPairs)).To(Equal(2))
		affs, err := bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeA, AffinityType: string(ipam.AffinityTypeHost)}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(affs.KVPairs)).To(Equal(2))

		By("releasing the second IP address to create an empty affine block", func() {
			unalloc, _, err := calicoClient.IPAM().ReleaseIPs(context.Background(), ipam.ReleaseOptions{Address: "192.168.0.65", Handle: handle2})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(unalloc)).To(Equal(0))
		})

		// Expect that the block is not removed immediately.
		Consistently(func() error {
			return assertNumBlocks(bc, 2)
		}, consistentlyTimeout, consistentlyInterval).Should(BeNil())
	})
})
