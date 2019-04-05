// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
	"os/exec"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/kube-controllers/tests/testutils"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	backend "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
)

var _ = Describe("kube-controllers FV tests (KDD mode)", func() {
	var (
		etcd              *containers.Container
		policyController  *containers.Container
		apiserver         *containers.Container
		calicoClient      client.Interface
		bc                backend.Client
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
	)

	const kNodeName = "k8snodename"
	const cNodeName = "caliconodename"

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		kconfigfile, err := ioutil.TempFile("", "ginkgo-policycontroller")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(kconfigfile.Name())
		data := fmt.Sprintf(testutils.KubeconfigTemplate, apiserver.IP)
		kconfigfile.Write([]byte(data))

		k8sClient, err = testutils.GetK8sClient(kconfigfile.Name())
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		// Apply the necessary CRDs.
		out, err := apiserver.ExecOutput("kubectl", "apply", "-f", "crds.yaml")
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to apply CRDs: %s", out))

		// Make a Calico client and backend client.
		type accessor interface {
			Backend() backend.Client
		}
		calicoClient = testutils.GetCalicoClient(apiconfig.Kubernetes, "", kconfigfile.Name())
		bc = calicoClient.(accessor).Backend()

		// In KDD mode, we only support the node controller right now.
		policyController = testutils.RunPolicyController(apiconfig.Kubernetes, "", kconfigfile.Name(), "node")

		// Run controller manager.
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
		Expect(info.Spec.ClusterType).To(Equal("k8s,kdd"))
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
	})

	Context("Mainline FV tests", func() {
		BeforeEach(func() {
			// Create an IP pool with room for 4 blocks.
			p := api.NewIPPool()
			p.Name = "test-ippool"
			p.Spec.CIDR = "192.168.0.0/24"
			p.Spec.BlockSize = 26
			p.Spec.NodeSelector = "all()"
			p.Spec.Disabled = false
			_, err := calicoClient.IPPools().Create(context.Background(), p, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			// Delete the IP pool.
			_, err := calicoClient.IPPools().Delete(context.Background(), "test-ippool", options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should clean up IPAM data for missing nodes", func() {
			// This test creates three nodes and creates IPAM allocations for each.
			// The IPPool in the test has room for 4 blocks which will be affine to
			// the different nodes like so:
			// - NodeA: 192.168.0.0/26
			// - NodeB: 192.168.0.64/26
			// - None:  192.168.0.128/26
			// - None:  192.168.0.192/26
			// NodeC will not have an affine block itself, but will have borrowed addresses
			// from NodeB's block, as well as one of the blocks with no affinity.
			nodeA := "node-a"
			nodeB := "node-b"
			nodeC := "node-c"

			// Create the nodes in the Kubernetes API.
			_, err := k8sClient.CoreV1().Nodes().Create(&v1.Node{
				TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: nodeA},
				Spec:       v1.NodeSpec{},
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = k8sClient.CoreV1().Nodes().Create(&v1.Node{
				TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: nodeB},
				Spec:       v1.NodeSpec{},
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = k8sClient.CoreV1().Nodes().Create(&v1.Node{
				TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: nodeC},
				Spec:       v1.NodeSpec{},
			})
			Expect(err).NotTo(HaveOccurred())

			// Allocate a pod IP address and thus a block and affinity to NodeA.
			handleA := "handleA"
			attrs := map[string]string{"node": nodeA, "pod": "pod-a", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.1"), HandleID: &handleA, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())

			// Allocate an IPIP and VXLAN address to NodeA as well.
			handleAIPIP := "handleAIPIP"
			attrs = map[string]string{"node": nodeA, "type": "ipipTunnelAddress"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.2"), HandleID: &handleAIPIP, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())

			handleAVXLAN := "handleAVXLAN"
			attrs = map[string]string{"node": nodeA, "type": "vxlanTunnelAddress"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.3"), HandleID: &handleAVXLAN, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())

			// Allocate a pod IP address and thus a block and affinity to NodeB.
			handleB := "handleB"
			attrs = map[string]string{"node": nodeB, "pod": "pod-b", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.65"), HandleID: &handleB, Attrs: attrs, Hostname: nodeB,
			})
			Expect(err).NotTo(HaveOccurred())

			// Allocate a pod IP address and thus a block and affinity to NodeC.
			handleC := "handleC"
			attrs = map[string]string{"node": nodeC, "pod": "pod-c", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.129"), HandleID: &handleC, Attrs: attrs, Hostname: nodeC,
			})
			Expect(err).NotTo(HaveOccurred())

			// Release the affinity for the block, creating the desired state - an IP address in a non-affine block.
			err = calicoClient.IPAM().ReleaseHostAffinities(context.Background(), nodeC, false)
			Expect(err).NotTo(HaveOccurred())

			// Also allocate an IP address on NodeC within NodeB's block, to simulate a "borrowed" address.
			handleC2 := "handleC2"
			attrs = map[string]string{"node": nodeC, "pod": "pod-c2", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: net.MustParseIP("192.168.0.66"), HandleID: &handleC2, Attrs: attrs, Hostname: nodeC,
			})
			Expect(err).NotTo(HaveOccurred())

			// Expect the correct blocks to exist as a result of the IPAM allocations above.
			blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(blocks.KVPairs)).To(Equal(3))
			affs, err := bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeA}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(affs.KVPairs)).To(Equal(1))
			affs, err = bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeB}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(affs.KVPairs)).To(Equal(1))
			affs, err = bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeC}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(affs.KVPairs)).To(Equal(0))

			// Deleting NodeB should clean up the allocations associated with the node, as well as the
			// affinity, but should leave the block intact since there are still allocations from another
			// node.
			err = k8sClient.CoreV1().Nodes().Delete(nodeB, nil)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() error {
				if err := assertIPsWithHandle(calicoClient.IPAM(), handleA, 1); err != nil {
					return err
				}
				if err := assertIPsWithHandle(calicoClient.IPAM(), handleAIPIP, 1); err != nil {
					return err
				}
				if err := assertIPsWithHandle(calicoClient.IPAM(), handleB, 0); err != nil {
					return err
				}
				if err := assertIPsWithHandle(calicoClient.IPAM(), handleC, 1); err != nil {
					return err
				}

				if err := assertNumBlocks(bc, 3); err != nil {
					return err
				}
				return nil
			}, time.Second*10, 500*time.Millisecond).Should(BeNil())

			// Deleting NodeC should clean up the second and third blocks since both node B and C
			// are now gone.
			err = k8sClient.CoreV1().Nodes().Delete(nodeC, nil)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() error {
				if err := assertIPsWithHandle(calicoClient.IPAM(), handleC, 0); err != nil {
					return err
				}
				if err := assertIPsWithHandle(calicoClient.IPAM(), handleC2, 0); err != nil {
					return err
				}
				if err := assertNumBlocks(bc, 1); err != nil {
					return err
				}
				return nil
			}, time.Second*10, 500*time.Millisecond).Should(BeNil())

			// Deleting NodeA should clean up the final block and the remaining allocations within.
			err = k8sClient.CoreV1().Nodes().Delete(nodeA, nil)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() error {
				if err := assertIPsWithHandle(calicoClient.IPAM(), handleA, 0); err != nil {
					return err
				}
				if err := assertIPsWithHandle(calicoClient.IPAM(), handleAIPIP, 0); err != nil {
					return err
				}
				if err := assertNumBlocks(bc, 0); err != nil {
					return err
				}
				return nil
			}, time.Second*10, 500*time.Millisecond).Should(BeNil())

			// Assert all IPAM data is removed now.
			kvps, err := bc.List(context.Background(), model.BlockListOptions{}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(kvps.KVPairs)).To(Equal(0))
			kvps, err = bc.List(context.Background(), model.BlockAffinityListOptions{}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(kvps.KVPairs)).To(Equal(0))
			kvps, err = bc.List(context.Background(), model.IPAMHandleListOptions{}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(kvps.KVPairs)).To(Equal(0))
		})
	})
})

func assertNumBlocks(bc backend.Client, num int) error {
	blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
	if err != nil {
		return fmt.Errorf("error querying blocks: %s", err)
	}
	if len(blocks.KVPairs) != num {
		return fmt.Errorf("Expected 0 blocks, found %d. Blocks: %#v", len(blocks.KVPairs), blocks)
	}
	return nil
}

func assertIPsWithHandle(c ipam.Interface, handle string, num int) error {
	ips, err := c.IPsByHandle(context.Background(), handle)
	if err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			return fmt.Errorf("error querying ips for handle %s: %s", handle, err)
		}
	}
	if len(ips) != num {
		return fmt.Errorf("Expected %d IPs with handle %s, found %d", len(ips), handle, ips)
	}
	return nil
}
