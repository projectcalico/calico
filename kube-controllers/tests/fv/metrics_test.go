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

		// Ensure the metrics endpoint is online.
		Eventually(func() (string, error) {
			return getMetrics(fmt.Sprintf("http://%s:9094/metrics", kubeControllers.IP))
		}, 10*time.Second, 1*time.Second).ShouldNot(BeNil())
	})

	AfterEach(func() {
		controllerManager.Stop()
		kubeControllers.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	It("should export metrics for IPAM state", func() {
		// Create an IP pool with room for 4 blocks.
		createIPPool("test-ippool", "192.168.0.0/24", calicoClient)
		createIPPool("test-ippool-2", "172.16.0.0/16", calicoClient)
		createIPPool("test-ippool-3", "10.16.0.0/24", calicoClient)

		// Create nodes in the Kubernetes API.
		nodeA := "node-a"
		nodeB := "node-b"
		nodeC := "node-c"
		createNode(nodeA, k8sClient)
		createNode(nodeB, k8sClient)
		createNode(nodeC, k8sClient)

		// Assert only pool size IPAM metrics are reported at this point.
		validateExpectedAndUnexpectedMetrics(
			[]string{
				`ipam_pool_size{ippool="test-ippool"} 256`,
				`ipam_pool_size{ippool="test-ippool-2"} 65536`,
				`ipam_pool_size{ippool="test-ippool-3"} 256`,
			},
			[]string{
				`ipam_allocations_`,
				`ipam_blocks_`,
			},
			kubeControllers.IP,
			10*time.Second, 1*time.Second,
		)

		// Allocate pod IP addresses from pool 1 and 2, and thus blocks and affinities to NodeA.
		handleA := "handleA"
		handleA2 := "handleA2"
		allocatePodIpWithHandle("192.168.0.1", handleA, nodeA, "pod-a", calicoClient)
		allocatePodIpWithHandle("172.16.0.1", handleA2, nodeA, "pod-a2", calicoClient)

		// Allocate an IPIP, VXLAN and WG address to NodeA as well.
		handleAIPIP := "handleAIPIP"
		handleAVXLAN := "handleAVXLAN"
		handleAWG := "handleAWireguard"
		allocateInterfaceIpWithHandle("192.168.0.2", handleAIPIP, nodeA, "ipipTunnelAddress", calicoClient)
		allocateInterfaceIpWithHandle("192.168.0.3", handleAVXLAN, nodeA, "vxlanTunnelAddress", calicoClient)
		allocateInterfaceIpWithHandle("192.168.0.4", handleAWG, nodeA, "wireguardTunnelAddress", calicoClient)

		// Allocate pod IP addresses from pool 1 and 3, and thus blocks and affinities to NodeB.
		handleB := "handleB"
		handleB2 := "handleB2"
		allocatePodIpWithHandle("192.168.0.65", handleB, nodeB, "pod-b", calicoClient)
		allocatePodIpWithHandle("10.16.0.1", handleB2, nodeB, "pod-b2", calicoClient)

		// Allocate a pod IP address from pool 1 and thus a block and affinity to NodeC.
		handleC := "handleC"
		allocatePodIpWithHandle("192.168.0.129", handleC, nodeC, "pod-c", calicoClient)

		// Assert that IPAM metrics have been updated to include the blocks and allocations from above.
		// Assert that IPAM metrics have been updated to include the blocks and allocations from above.
		validateExpectedAndUnexpectedMetrics(
			[]string{
				`ipam_allocations_in_use{ippool="test-ippool",node="node-a"} 4`,
				`ipam_allocations_in_use{ippool="test-ippool-2",node="node-a"} 1`,
				`ipam_allocations_in_use{ippool="test-ippool",node="node-b"} 1`,
				`ipam_allocations_in_use{ippool="test-ippool-3",node="node-b"} 1`,
				`ipam_allocations_in_use{ippool="test-ippool",node="node-c"} 1`,
				`ipam_allocations_per_node{node="node-a"} 5`,
				`ipam_allocations_per_node{node="node-b"} 2`,
				`ipam_allocations_per_node{node="node-c"} 1`,
				`ipam_blocks{ippool="test-ippool",node="node-a"} 1`,
				`ipam_blocks{ippool="test-ippool-2",node="node-a"} 1`,
				`ipam_blocks{ippool="test-ippool",node="node-b"} 1`,
				`ipam_blocks{ippool="test-ippool-3",node="node-b"} 1`,
				`ipam_blocks{ippool="test-ippool",node="node-c"} 1`,
				`ipam_blocks_per_node{node="node-a"} 2`,
				`ipam_blocks_per_node{node="node-b"} 2`,
				`ipam_blocks_per_node{node="node-c"} 1`,
			},
			[]string{},
			kubeControllers.IP,
			5*time.Second,
		)

		// Release the affinity for node-C's block, creating an IP address in a non-affine block.
		err := calicoClient.IPAM().ReleaseHostAffinities(context.Background(), nodeC, false)
		Expect(err).NotTo(HaveOccurred())

		// Assert that IPAM metrics have been updated. It should now show a block with no affinity,
		// and an IP address that is "borrowed" from the empty block on node C.
		validateExpectedAndUnexpectedMetrics(
			[]string{
				`ipam_allocations_in_use{ippool="test-ippool",node="node-a"} 4`,
				`ipam_allocations_in_use{ippool="test-ippool-2",node="node-a"} 1`,
				`ipam_allocations_in_use{ippool="test-ippool",node="node-b"} 1`,
				`ipam_allocations_in_use{ippool="test-ippool-3",node="node-b"} 1`,
				`ipam_allocations_in_use{ippool="test-ippool",node="node-c"} 1`,
				`ipam_allocations_per_node{node="node-a"} 5`,
				`ipam_allocations_per_node{node="node-b"} 2`,
				`ipam_allocations_per_node{node="node-c"} 1`,
				`ipam_blocks{ippool="test-ippool",node="node-a"} 1`,
				`ipam_blocks{ippool="test-ippool-2",node="node-a"} 1`,
				`ipam_blocks{ippool="test-ippool",node="node-b"} 1`,
				`ipam_blocks{ippool="test-ippool-3",node="node-b"} 1`,
				`ipam_blocks{ippool="test-ippool",node="no_affinity"} 1`,
				`ipam_blocks_per_node{node="node-a"} 2`,
				`ipam_blocks_per_node{node="node-b"} 2`,
				`ipam_blocks_per_node{node="no_affinity"} 1`,
				`ipam_allocations_borrowed{ippool="test-ippool",node="node-c"} 1`,
				`ipam_allocations_borrowed_per_node{node="node-c"} 1`,
			}, []string{
				`ipam_blocks{ippool="test-ippool",node="node-c"}`,
				`ipam_blocks_per_node{node="node-c"}`,
			},
			kubeControllers.IP,
			5*time.Second,
		)

		// Also allocate an IP address on NodeC within NodeB's block, to simulate a "borrowed" address.
		handleC2 := "handleC2"
		allocatePodIpWithHandle("192.168.0.66", handleC2, nodeC, "pod-c2", calicoClient)

		// Assert that IPAM metrics for node-c have been updated.
		validateExpectedAndUnexpectedMetrics(
			[]string{
				`ipam_allocations_in_use{ippool="test-ippool",node="node-c"} 2`,
				`ipam_allocations_per_node{node="node-c"} 2`,
				`ipam_allocations_borrowed{ippool="test-ippool",node="node-c"} 2`,
				`ipam_allocations_borrowed_per_node{node="node-c"} 2`,
			},
			[]string{},
			kubeControllers.IP,
			5*time.Second,
		)

		// Expect the correct blocks to exist as a result of the IPAM allocations above.
		blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(blocks.KVPairs)).To(Equal(5))
		affs, err := bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeA}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(affs.KVPairs)).To(Equal(2))
		affs, err = bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeB}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(affs.KVPairs)).To(Equal(2))
		affs, err = bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeC}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(affs.KVPairs)).To(Equal(0))

		// Delete Pools 2 and 3 to trigger the change of pool associations
		_, err = calicoClient.IPPools().Delete(context.Background(), "test-ippool-2", options.DeleteOptions{})
		Expect(err).ToNot(HaveOccurred())
		_, err = calicoClient.IPPools().Delete(context.Background(), "test-ippool-3", options.DeleteOptions{})
		Expect(err).ToNot(HaveOccurred())

		// Assert that associated pools are labelled as no_pool, and block affinities as no_affinity.
		// Blocks lose affinity when their pool is deleted.
		validateExpectedAndUnexpectedMetrics(
			[]string{
				`ipam_pool_size{ippool="test-ippool"} 256`,
				`ipam_allocations_in_use{ippool="test-ippool",node="node-a"} 4`,
				`ipam_allocations_in_use{ippool="no_pool",node="node-a"} 1`,
				`ipam_allocations_in_use{ippool="test-ippool",node="node-b"} 1`,
				`ipam_allocations_in_use{ippool="no_pool",node="node-b"} 1`,
				`ipam_allocations_in_use{ippool="test-ippool",node="node-c"} 2`,
				`ipam_allocations_per_node{node="node-a"} 5`,
				`ipam_allocations_per_node{node="node-b"} 2`,
				`ipam_allocations_per_node{node="node-c"} 2`,
				`ipam_blocks{ippool="test-ippool",node="node-a"} 1`,
				`ipam_blocks{ippool="test-ippool",node="node-b"} 1`,
				`ipam_blocks{ippool="no_pool",node="no_affinity"} 2`, // Blocks from pools 2 and 3 lose affinity and pool.
				`ipam_blocks{ippool="test-ippool",node="no_affinity"} 1`,
				`ipam_blocks_per_node{node="node-a"} 1`,
				`ipam_blocks_per_node{node="node-b"} 1`,
				`ipam_blocks_per_node{node="no_affinity"} 3`,
				`ipam_allocations_borrowed{ippool="test-ippool",node="node-c"} 2`,
				`ipam_allocations_borrowed_per_node{node="node-c"} 2`,
			},
			[]string{
				`ipam_pool_size{ippool="test-ippool-2"}`,
				`ipam_pool_size{ippool="test-ippool-3"}`,
				`ipam_allocations_in_use{ippool="test-ippool-2",node="node-a"}`,
				`ipam_allocations_in_use{ippool="test-ippool-3",node="node-b"}`,
				`ipam_blocks{ippool="test-ippool-2",node="node-a"}`,
				`ipam_blocks{ippool="test-ippool-3",node="node-b"}`,
			},
			kubeControllers.IP,
			5*time.Second,
		)

		// Deleting NodeB should clean up the allocations associated with the node, as well as the
		// affinity, but should leave the block intact since there are still allocations from another
		// node.
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), nodeB, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() error {
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleA, 1); err != nil {
				return err
			}
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleA2, 1); err != nil {
				return err
			}
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleAIPIP, 1); err != nil {
				return err
			}
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleB, 0); err != nil {
				return err
			}
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleB2, 0); err != nil {
				return err
			}
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleC, 1); err != nil {
				return err
			}

			if err := assertNumBlocks(bc, 4); err != nil {
				return err
			}
			return nil
		}, time.Second*10, 500*time.Millisecond).Should(BeNil())

		// Assert that IPAM metrics have been updated. We should no longer have any allocations on NodeB, however
		// the block should still exist. Since we don't release affinity until the block is empty, the block should
		// still be affine to node-b.
		validateExpectedAndUnexpectedMetrics(
			[]string{
				`ipam_allocations_in_use{ippool="test-ippool",node="node-a"} 4`,
				`ipam_allocations_in_use{ippool="no_pool",node="node-a"} 1`,
				`ipam_allocations_in_use{ippool="test-ippool",node="node-c"} 2`,
				`ipam_allocations_per_node{node="node-a"} 5`,
				`ipam_allocations_per_node{node="node-c"} 2`,
				`ipam_blocks{ippool="test-ippool",node="node-a"} 1`,
				`ipam_blocks{ippool="test-ippool",node="node-b"} 1`,
				`ipam_blocks{ippool="no_pool",node="no_affinity"} 1`,
				`ipam_blocks{ippool="test-ippool",node="no_affinity"} 1`,
				`ipam_blocks_per_node{node="node-a"} 1`,
				`ipam_blocks_per_node{node="node-b"} 1`,
				`ipam_blocks_per_node{node="no_affinity"} 2`,
				`ipam_allocations_borrowed{ippool="test-ippool",node="node-c"} 2`,
				`ipam_allocations_borrowed_per_node{node="node-c"} 2`,
			},
			[]string{
				`ipam_allocations_in_use{ippool="test-ippool",node="node-b"}`,
				`ipam_allocations_in_use{ippool="no_pool",node="node-b"}`,
				`ipam_allocations_per_node{node="node-b"}`,
			},
			kubeControllers.IP,
			5*time.Second,
		)

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
			if err := assertNumBlocks(bc, 2); err != nil {
				return err
			}
			return nil
		}, time.Second*10, 500*time.Millisecond).Should(BeNil())

		// Assert that IPAM metrics have been updated. Both blocks should now be released, and all that should be
		// left is the block and allocations for node A.
		validateExpectedAndUnexpectedMetrics(
			[]string{
				`ipam_allocations_in_use{ippool="test-ippool",node="node-a"} 4`,
				`ipam_allocations_in_use{ippool="no_pool",node="node-a"} 1`,
				`ipam_allocations_per_node{node="node-a"} 5`,
				`ipam_blocks{ippool="test-ippool",node="node-a"} 1`,
				`ipam_blocks{ippool="no_pool",node="no_affinity"} 1`,
				`ipam_blocks_per_node{node="node-a"} 1`,
				`ipam_blocks_per_node{node="no_affinity"} 1`,
			},
			[]string{
				`ipam_allocations_in_use{ippool="test-ippool",node="node-c"}`,
				`ipam_allocations_per_node{node="node-c"}`,
				`ipam_blocks{ippool="test-ippool",node="node-b"}`,
				`ipam_blocks{ippool="test-ippool",node="no_affinity"}`,
				`ipam_blocks_per_node{node="node-b"}`,
				`ipam_allocations_borrowed{ippool="test-ippool",node="node-c"}`,
				`ipam_allocations_borrowed_per_node{node="node-c"}`,
			},
			kubeControllers.IP,
			5*time.Second,
		)

		// Create an IP Pool that is analogous to the deleted pool 2.
		createIPPool("test-ippool-2-analogue", "172.16.0.0/16", calicoClient)

		// Validate that blocks and allocations are labelled with the analogue.
		// Pool labels represent the pool occupied by the block and allocations.
		validateExpectedAndUnexpectedMetrics(
			[]string{
				`ipam_allocations_in_use{ippool="test-ippool",node="node-a"} 4`,
				`ipam_allocations_in_use{ippool="test-ippool-2-analogue",node="node-a"} 1`,
				`ipam_allocations_per_node{node="node-a"} 5`,
				`ipam_blocks{ippool="test-ippool",node="node-a"} 1`,
				`ipam_blocks{ippool="test-ippool-2-analogue",node="no_affinity"} 1`,
				`ipam_blocks_per_node{node="node-a"} 1`,
				`ipam_blocks_per_node{node="no_affinity"} 1`,
			},
			[]string{
				`ipam_allocations_in_use{ippool="no_pool",node="node-a"} 1`,
				`ipam_blocks{ippool="no_pool",node="no_affinity"} 1`,
			},
			kubeControllers.IP,
			5*time.Second,
		)

		// Deleting NodeA should clean up the final block and the remaining allocations within.
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), nodeA, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		validateExpectedAndUnexpectedMetrics(
			[]string{},
			[]string{
				`ipam_allocations_in_use{ippool="test-ippool",node="node-a"}`,
				`ipam_allocations_in_use{ippool="test-ippool-2-analogue",node="node-a"}`,
				`ipam_allocations_per_node{node="node-a"}`,
				`ipam_blocks{ippool="test-ippool",node="node-a"}`,
				`ipam_blocks{ippool="test-ippool-2-analogue",node="no_affinity"}`,
				`ipam_blocks_per_node{node="node-a"}`,
				`ipam_blocks_per_node{node="no_affinity"}`,
			},
			kubeControllers.IP,
			5*time.Second,
		)

		Eventually(func() error {
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleA, 0); err != nil {
				return err
			}
			if err := assertIPsWithHandle(calicoClient.IPAM(), handleA2, 0); err != nil {
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

func createNode(node string, k8sClient *kubernetes.Clientset) {
	_, err := k8sClient.CoreV1().Nodes().Create(context.Background(),
		&v1.Node{
			TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: node},
			Spec:       v1.NodeSpec{},
		},
		metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func createIPPool(name string, cidr string, calicoClient client.Interface) {
	p := api.NewIPPool()
	p.Name = name
	p.Spec.CIDR = cidr
	p.Spec.BlockSize = 26
	p.Spec.NodeSelector = "all()"
	p.Spec.Disabled = false
	_, err := calicoClient.IPPools().Create(context.Background(), p, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func allocatePodIpWithHandle(ip string, handle string, node string, pod string, calicoClient client.Interface) {
	attrs := map[string]string{"node": node, "pod": pod, "namespace": "default"}
	err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
		IP: net.MustParseIP(ip), HandleID: &handle, Attrs: attrs, Hostname: node,
	})
	Expect(err).NotTo(HaveOccurred())
}

func allocateInterfaceIpWithHandle(ip string, handle string, node string, itype string, calicoClient client.Interface) {
	attrs := map[string]string{"node": node, "type": itype}
	err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
		IP: net.MustParseIP(ip), HandleID: &handle, Attrs: attrs, Hostname: node,
	})
	Expect(err).NotTo(HaveOccurred())
}

func validateExpectedAndUnexpectedMetrics(expectedMetrics []string, notExpectedMetrics []string, host string, intervals ...interface{}) {
	Eventually(func() error {
		out, err := getMetrics(fmt.Sprintf("http://%s:9094/metrics", host))
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
	}, intervals...).ShouldNot(HaveOccurred())
}
