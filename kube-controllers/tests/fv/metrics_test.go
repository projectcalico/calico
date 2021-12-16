// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
	"net/http"
	"os"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

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

var _ = Describe("kube-controllers metrics tests", func() {
	var (
		etcd              *containers.Container
		kubeControllers   *containers.Container
		apiserver         *containers.Container
		calicoClient      client.Interface
		bc                backend.Client
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		kconfigfile, err := ioutil.TempFile("", "ginkgo-policycontroller")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(kconfigfile.Name())
		data := testutils.BuildKubeconfig(apiserver.IP)
		_, err = kconfigfile.Write([]byte(data))
		Expect(err).NotTo(HaveOccurred())

		// Make the kubeconfig readable by the container.
		Expect(kconfigfile.Chmod(os.ModePerm)).NotTo(HaveOccurred())

		k8sClient, err = testutils.GetK8sClient(kconfigfile.Name())
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		// Apply the necessary CRDs. There can sometimes be a delay between starting
		// the API server and when CRDs are apply-able, so retry here.
		apply := func() error {
			out, err := apiserver.ExecOutput("kubectl", "apply", "-f", "/crds/")
			if err != nil {
				return fmt.Errorf("%s: %s", err, out)
			}
			return nil
		}
		Eventually(apply, 10*time.Second).ShouldNot(HaveOccurred())

		// Make a Calico client and backend client.
		type accessor interface {
			Backend() backend.Client
		}
		calicoClient = testutils.GetCalicoClient(apiconfig.Kubernetes, "", kconfigfile.Name())
		bc = calicoClient.(accessor).Backend()

		// Run the node controller, which exports the metrics under test.
		kubeControllers = testutils.RunPolicyController(apiconfig.Kubernetes, "", kconfigfile.Name(), "node")

		// Run controller manager.
		controllerManager = testutils.RunK8sControllerManager(apiserver.IP)

		// Create an IP pool with room for 4 blocks.
		p := api.NewIPPool()
		p.Name = "test-ippool"
		p.Spec.CIDR = "192.168.0.0/24"
		p.Spec.BlockSize = 26
		p.Spec.NodeSelector = "all()"
		p.Spec.Disabled = false
		_, err = calicoClient.IPPools().Create(context.Background(), p, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		controllerManager.Stop()
		kubeControllers.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	It("should export metrics for IPAM state", func() {
		// Create nodes in the Kubernetes API.
		nodeA := "node-a"
		nodeB := "node-b"
		nodeC := "node-c"
		_, err := k8sClient.CoreV1().Nodes().Create(context.Background(),
			&v1.Node{
				TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: nodeA},
				Spec:       v1.NodeSpec{},
			},
			metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = k8sClient.CoreV1().Nodes().Create(context.Background(),
			&v1.Node{
				TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: nodeB},
				Spec:       v1.NodeSpec{},
			},
			metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = k8sClient.CoreV1().Nodes().Create(context.Background(),
			&v1.Node{
				TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: nodeC},
				Spec:       v1.NodeSpec{},
			},
			metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Assert no IPAM metrics reported yet.
		var out string
		Eventually(func() error {
			out, err = getMetrics(fmt.Sprintf("http://%s:9094/metrics", kubeControllers.IP))
			return err
		}, 10*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
		Expect(out).NotTo(ContainSubstring("ipam_"))

		// Allocate a pod IP address and thus a block and affinity to NodeA.
		handleA := "handleA"
		attrs := map[string]string{"node": nodeA, "pod": "pod-a", "namespace": "default"}
		err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
			IP: net.MustParseIP("192.168.0.1"), HandleID: &handleA, Attrs: attrs, Hostname: nodeA,
		})
		Expect(err).NotTo(HaveOccurred())

		// Allocate an IPIP, VXLAN and WG address to NodeA as well.
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

		handleAWG := "handleAWireguard"
		attrs = map[string]string{"node": nodeA, "type": "wireguardTunnelAddress"}
		err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
			IP: net.MustParseIP("192.168.0.4"), HandleID: &handleAWG, Attrs: attrs, Hostname: nodeA,
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

		// Assert that IPAM metrics have been updated to include the blocks and allocations from above.
		expectedMetrics := []string{
			`ipam_allocations_per_node{node="node-a"} 4`,
			`ipam_allocations_per_node{node="node-b"} 1`,
			`ipam_blocks_per_node{node="node-a"} 1`,
			`ipam_blocks_per_node{node="node-b"} 1`,
			`ipam_blocks_per_node{node="node-c"} 1`,
		}
		Eventually(func() error {
			out, err = getMetrics(fmt.Sprintf("http://%s:9094/metrics", kubeControllers.IP))
			Expect(err).NotTo(HaveOccurred())
			for _, s := range expectedMetrics {
				if !strings.Contains(out, s) {
					return fmt.Errorf("Expected:\n%s\nTo contain metric:\n  %s\n", out, s)
				}
			}
			return nil
		}, 5*time.Second).ShouldNot(HaveOccurred())

		// Release the affinity for node-C's block, creating an IP address in a non-affine block.
		err = calicoClient.IPAM().ReleaseHostAffinities(context.Background(), nodeC, false)
		Expect(err).NotTo(HaveOccurred())

		// Assert that IPAM metrics have been updated. It should now show a block with no affinity,
		// and an IP address that is "borrowed" from the empty block on node C.
		expectedMetrics = []string{
			`ipam_allocations_per_node{node="node-a"} 4`,
			`ipam_allocations_per_node{node="node-b"} 1`,
			`ipam_allocations_per_node{node="node-c"} 1`,
			`ipam_blocks_per_node{node="node-a"} 1`,
			`ipam_blocks_per_node{node="node-b"} 1`,
			`ipam_blocks_per_node{node="no_affinity"} 1`,
			`ipam_allocations_borrowed_per_node{node="node-c"} 1`,
		}
		Eventually(func() error {
			out, err = getMetrics(fmt.Sprintf("http://%s:9094/metrics", kubeControllers.IP))
			Expect(err).NotTo(HaveOccurred())
			for _, s := range expectedMetrics {
				if !strings.Contains(out, s) {
					return fmt.Errorf("Expected:\n%s\nTo contain metric:\n  %s\n", out, s)
				}
			}
			return nil
		}, 5*time.Second).ShouldNot(HaveOccurred())

		// Also allocate an IP address on NodeC within NodeB's block, to simulate a "borrowed" address.
		handleC2 := "handleC2"
		attrs = map[string]string{"node": nodeC, "pod": "pod-c2", "namespace": "default"}
		err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
			IP: net.MustParseIP("192.168.0.66"), HandleID: &handleC2, Attrs: attrs, Hostname: nodeC,
		})
		Expect(err).NotTo(HaveOccurred())

		// Assert that IPAM metrics for node-c have been updated.
		expectedMetrics = []string{
			`ipam_allocations_per_node{node="node-c"} 2`,
			`ipam_allocations_borrowed_per_node{node="node-c"} 2`,
		}
		Eventually(func() error {
			out, err = getMetrics(fmt.Sprintf("http://%s:9094/metrics", kubeControllers.IP))
			Expect(err).NotTo(HaveOccurred())
			for _, s := range expectedMetrics {
				if !strings.Contains(out, s) {
					return fmt.Errorf("Expected:\n%s\nTo contain metric:\n  %s\n", out, s)
				}
			}
			return nil
		}, 5*time.Second).ShouldNot(HaveOccurred())

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
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), nodeB, metav1.DeleteOptions{})
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

		// Assert that IPAM metrics have been updated. We should no longer have any allocations on NodeB, however
		// the block should still exist. Since we don't release affinity until the block is empty, the block should
		// still be affine to node-b.
		notExpectedMetrics := []string{
			`ipam_allocations_per_node{node="node-b"}`,
			`ipam_blocks_per_node{node="node-c"}`,
		}
		expectedMetrics = []string{
			`ipam_allocations_per_node{node="node-a"} 4`,
			`ipam_allocations_per_node{node="node-c"} 2`,
			`ipam_blocks_per_node{node="node-a"} 1`,
			`ipam_blocks_per_node{node="node-b"} 1`,
			`ipam_blocks_per_node{node="no_affinity"} 1`,
			`ipam_allocations_borrowed_per_node{node="node-c"} 2`,
		}
		Eventually(func() error {
			out, err = getMetrics(fmt.Sprintf("http://%s:9094/metrics", kubeControllers.IP))
			Expect(err).NotTo(HaveOccurred())
			for _, s := range expectedMetrics {
				if !strings.Contains(out, s) {
					return fmt.Errorf("Expected:\n%s\nTo contain metric:\n  %s\n", out, s)
				}
			}
			for _, s := range notExpectedMetrics {
				if strings.Contains(out, s) {
					return fmt.Errorf("Expected:\n%s\nNOT to contain metric:\n  %s\n", out, s)
				}
			}
			return nil
		}, 5*time.Second).ShouldNot(HaveOccurred())

		// Deleting NodeC should clean up the second and third blocks since both node B and C
		// are now gone.
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), nodeC, metav1.DeleteOptions{})
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

		// Assert that IPAM metrics have been updated. Both blocks should now be released, and all that should be
		// left is the block and allocations for node A.
		notExpectedMetrics = []string{
			`ipam_allocations_per_node{node="node-c"}`,
			`ipam_allocations_per_node{node="node-b"}`,
			`ipam_blocks_per_node{node="node-b"}`,
			`ipam_blocks_per_node{node="node-c"}`,
			`ipam_blocks_per_node{node="no_affinity"}`,
			`ipam_allocations_borrowed_per_node{node="node-c"}`,
		}
		expectedMetrics = []string{
			`ipam_allocations_per_node{node="node-a"} 4`,
			`ipam_blocks_per_node{node="node-a"} 1`,
		}
		Eventually(func() error {
			out, err = getMetrics(fmt.Sprintf("http://%s:9094/metrics", kubeControllers.IP))
			Expect(err).NotTo(HaveOccurred())
			for _, s := range expectedMetrics {
				if !strings.Contains(out, s) {
					return fmt.Errorf("Expected:\n%s\nTo contain metric:\n  %s\n", out, s)
				}
			}
			for _, s := range notExpectedMetrics {
				if strings.Contains(out, s) {
					return fmt.Errorf("Expected:\n%s\nNOT to contain metric:\n  %s\n", out, s)
				}
			}
			return nil
		}, 5*time.Second).ShouldNot(HaveOccurred())

		// Deleting NodeA should clean up the final block and the remaining allocations within.
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), nodeA, metav1.DeleteOptions{})
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

		Eventually(func() error {
			// Assert all IPAM data is removed now.
			kvps, err := bc.List(context.Background(), model.BlockListOptions{}, "")
			if err != nil {
				return err
			} else if len(kvps.KVPairs) != 0 {
				return fmt.Errorf("Expected no blocks but there are some")
			}
			kvps, err = bc.List(context.Background(), model.BlockAffinityListOptions{}, "")
			if err != nil {
				return err
			} else if len(kvps.KVPairs) != 0 {
				return fmt.Errorf("Expected no affinities but there are some")
			}
			kvps, err = bc.List(context.Background(), model.IPAMHandleListOptions{}, "")
			if err != nil {
				return err
			} else if len(kvps.KVPairs) != 0 {
				return fmt.Errorf("Expected no handles but there are some")
			}
			return nil
		}, time.Second*10, 500*time.Millisecond).Should(BeNil())
	})
})

// getMetrics hits the provided prometheus metrics URL and returns the response body
// for use in asserting accurate metrics reporting.
func getMetrics(metricsURL string) (string, error) {
	resp, err := http.Get(metricsURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
