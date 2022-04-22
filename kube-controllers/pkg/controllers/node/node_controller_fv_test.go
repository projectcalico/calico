// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	backend "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("Calico node controller FV tests (KDD mode)", func() {
	var (
		etcd              *containers.Container
		policyController  *containers.Container
		apiserver         *containers.Container
		calicoClient      client.Interface
		bc                backend.Client
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
		kconfigfile       *os.File
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		var err error
		kconfigfile, err = ioutil.TempFile("", "ginkgo-policycontroller")
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
		Consistently(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 10*time.Second, 1*time.Second).Should(BeNil())

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

			// Allocate a pod IP address and thus a block and affinity to NodeA.
			handleA := "handleA"
			attrs := map[string]string{"node": nodeA, "pod": "pod-a", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: cnet.MustParseIP("192.168.0.1"), HandleID: &handleA, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())

			// Allocate an IPIP, VXLAN and WG address to NodeA as well.
			handleAIPIP := "handleAIPIP"
			attrs = map[string]string{"node": nodeA, "type": "ipipTunnelAddress"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: cnet.MustParseIP("192.168.0.2"), HandleID: &handleAIPIP, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())

			handleAVXLAN := "handleAVXLAN"
			attrs = map[string]string{"node": nodeA, "type": "vxlanTunnelAddress"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: cnet.MustParseIP("192.168.0.3"), HandleID: &handleAVXLAN, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())

			handleAWG := "handleAWireguard"
			attrs = map[string]string{"node": nodeA, "type": "wireguardTunnelAddress"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: cnet.MustParseIP("192.168.0.4"), HandleID: &handleAWG, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())

			// Allocate a pod IP address and thus a block and affinity to NodeB.
			handleB := "handleB"
			attrs = map[string]string{"node": nodeB, "pod": "pod-b", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: cnet.MustParseIP("192.168.0.65"), HandleID: &handleB, Attrs: attrs, Hostname: nodeB,
			})
			Expect(err).NotTo(HaveOccurred())

			// Allocate a pod IP address and thus a block and affinity to NodeC.
			handleC := "handleC"
			attrs = map[string]string{"node": nodeC, "pod": "pod-c", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: cnet.MustParseIP("192.168.0.129"), HandleID: &handleC, Attrs: attrs, Hostname: nodeC,
			})
			Expect(err).NotTo(HaveOccurred())

			// Release the affinity for the block, creating the desired state - an IP address in a non-affine block.
			err = calicoClient.IPAM().ReleaseHostAffinities(context.Background(), nodeC, false)
			Expect(err).NotTo(HaveOccurred())

			// Also allocate an IP address on NodeC within NodeB's block, to simulate a "borrowed" address.
			handleC2 := "handleC2"
			attrs = map[string]string{"node": nodeC, "pod": "pod-c2", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: cnet.MustParseIP("192.168.0.66"), HandleID: &handleC2, Attrs: attrs, Hostname: nodeC,
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

		// This is a test for a specific bug which was fixed by https://github.com/projectcalico/libcalico-go/pull/1345
		It("should handle improperly formatted handle IDs", func() {
			nodeA := "node-a"

			// Create the nodes in the Kubernetes API.
			_, err := k8sClient.CoreV1().Nodes().Create(context.Background(),
				&v1.Node{
					TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: nodeA},
					Spec:       v1.NodeSpec{},
				},
				metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Allocate a pod IP address and thus a block and affinity to NodeA.
			handleA := "handleA"
			attrs := map[string]string{"node": nodeA, "pod": "pod-a", "namespace": "default"}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP: cnet.MustParseIP("192.168.0.1"), HandleID: &handleA, Attrs: attrs, Hostname: nodeA,
			})
			Expect(err).NotTo(HaveOccurred())

			// Expect the correct blocks to exist as a result of the IPAM allocation above.
			blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(blocks.KVPairs)).To(Equal(1))
			affs, err := bc.List(context.Background(), model.BlockAffinityListOptions{Host: nodeA}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(affs.KVPairs)).To(Equal(1))

			// Now, modify the allocation so that the data is malformed, matching the issue under test.
			// See https://github.com/projectcalico/libcalico-go/pull/1345
			kvp := blocks.KVPairs[0]
			b := kvp.Value.(*model.AllocationBlock)
			malformedHandle := fmt.Sprintf("%s\r\neth0", *b.Attributes[0].AttrPrimary)
			blocks.KVPairs[0].Value.(*model.AllocationBlock).Attributes[0].AttrPrimary = &malformedHandle
			_, err = bc.Update(context.Background(), blocks.KVPairs[0])
			Expect(err).NotTo(HaveOccurred())

			// Deleting NodeA should clean up all IPAM data.
			err = k8sClient.CoreV1().Nodes().Delete(context.Background(), nodeA, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() error {
				if err := assertIPsWithHandle(calicoClient.IPAM(), handleA, 0); err != nil {
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
})

var _ = Describe("Calico node controller FV tests (etcd mode)", func() {
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
		calicoClient = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

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

	Context("Node FV tests", func() {
		It("should be removed in response to a k8s node delete", func() {
			kn := &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: kNodeName,
				},
			}
			_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			cn := libapi.NewNode()
			cn.Name = cNodeName
			cn.Spec = libapi.NodeSpec{
				OrchRefs: []libapi.OrchRef{
					{
						NodeName:     kNodeName,
						Orchestrator: "k8s",
					},
				},
			}

			_, err = calicoClient.Nodes().Create(context.Background(), cn, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kNodeName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() *libapi.Node {
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
			_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			cn := &libapi.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: cNodeName,
				},
				Spec: libapi.NodeSpec{
					OrchRefs: []libapi.OrchRef{
						{
							NodeName:     kNodeName,
							Orchestrator: "mesos",
						},
					},
				},
			}
			_, err = calicoClient.Nodes().Create(context.Background(), cn, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kNodeName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			Consistently(func() *libapi.Node {
				node, _ := calicoClient.Nodes().Get(context.Background(), cNodeName, options.GetOptions{})
				return node
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeNil())

			node, _ := calicoClient.Nodes().Get(context.Background(), cNodeName, options.GetOptions{})
			Expect(len(node.Spec.OrchRefs)).Should(Equal(1))
			Expect(node.Spec.OrchRefs[0].Orchestrator).Should(Equal("mesos"))
		})

		It("should not be removed if orchrefs are nil.", func() {
			cn := &libapi.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: cNodeName,
				},
				Spec: libapi.NodeSpec{},
			}
			_, err := calicoClient.Nodes().Create(context.Background(), cn, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			Consistently(func() *libapi.Node {
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
			_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Create the node object in Calico's datastore.
			cn := &libapi.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: cNodeName,
				},
				Spec: libapi.NodeSpec{
					OrchRefs: []libapi.OrchRef{
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

			// Allocate an address within the block, which will be assigned to a WEP.
			// We don't specify metadata in the attrs fields (e.g., pod name, namespace, node), since those fields
			// weren't added until Calico v3.6 so some allocations won't have them. For these allocations, we NEED
			// the workload endpoint in order to garbage collect them.
			handle := "myhandle"
			wepIp := net.IP{192, 168, 0, 1}
			swepIp := "192.168.0.1/32"
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       cnet.IP{IP: wepIp},
				Hostname: cNodeName,
				HandleID: &handle,
			})
			Expect(err).NotTo(HaveOccurred())

			// Create the WEP, using the address.
			wep := libapi.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "caliconodename-k8s-mypod-mywep",
					Namespace: "default",
				},
				Spec: libapi.WorkloadEndpointSpec{
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

			// Allocate another address within the block, which will NOT be assigned to a WEP. This make sure
			// we handle cleanup of addresses which may have lost association with a running workload. This allocation
			// includes metadata attributes introduced in Calico v3.6, which allows us to garbage collect it even though
			// there is no corresponding workload endpoint.
			handle2 := "myhandle2"
			wepIp = net.IP{192, 168, 0, 2}
			attrs := map[string]string{
				ipam.AttributeNode:      cNodeName,
				ipam.AttributePod:       "podname2",
				ipam.AttributeNamespace: "podnamespace2",
			}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       cnet.IP{IP: wepIp},
				Hostname: cNodeName,
				HandleID: &handle2,
				Attrs:    attrs,
			})
			Expect(err).NotTo(HaveOccurred())

			// Allocate another address within another block, and then release the affinity of that block from the node.
			// This tests yet another possible scenario - that we clean up addresses in blocks that may no longer be tied to
			// the node itself via an affinity (e.g., if the IP pool was deleted). Allocating the IP address claims the block
			// so we need to explicitly release the affinity to get it into the right state.
			handle3 := "myhandle3"
			wepIp = net.IP{192, 168, 1, 1}
			attrs = map[string]string{
				ipam.AttributeNode:      cNodeName,
				ipam.AttributePod:       "podname3",
				ipam.AttributeNamespace: "podnamespace3",
			}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       cnet.IP{IP: wepIp},
				Hostname: cNodeName,
				HandleID: &handle3,
				Attrs:    attrs,
			})
			Expect(err).NotTo(HaveOccurred())

			affBlock := cnet.IPNet{IPNet: net.IPNet{
				IP:   net.IP{192, 168, 1, 0},
				Mask: net.IPMask{255, 255, 255, 0},
			}}
			err = calicoClient.IPAM().ReleaseAffinity(context.Background(), affBlock, cNodeName, false)
			Expect(err).NotTo(HaveOccurred())

			// Allocate an address in a block that is affine to another host, simulating a "borrowed" IP.
			// We expect that this will also get cleaned up. (The block will also get cleaned up since "someothernode"
			// doesn't actually exist, but that is dependent on releasing the IP first).
			handle4 := "myhandle4"
			wepIp = net.IP{192, 168, 2, 1}
			attrs = map[string]string{
				ipam.AttributeNode:      "someothernode",
				ipam.AttributePod:       "podname4",
				ipam.AttributeNamespace: "podnamespace4",
			}
			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       cnet.IP{IP: wepIp},
				Hostname: cNodeName,
				HandleID: &handle4,
				Attrs:    attrs,
			})
			Expect(err).NotTo(HaveOccurred())

			// Create a per-node BGP peer.
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

			// Create a per-node FelixConfiguration.
			nodeConfigName := fmt.Sprintf("node.%s", cNodeName)
			felixConf := api.FelixConfiguration{
				Spec: api.FelixConfigurationSpec{},
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeConfigName,
				},
			}
			_, err = calicoClient.FelixConfigurations().Create(context.Background(), &felixConf, options.SetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			// Create a per-node BGPConfiguration.
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

			// Delete the node. This is expected to trigger removal of all the above resources.
			err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kNodeName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Check that the node is removed from Calico
			Eventually(func() *libapi.Node {
				node, _ := calicoClient.Nodes().Get(context.Background(), cNodeName, options.GetOptions{})
				return node
			}, time.Second*2, 500*time.Millisecond).Should(BeNil())

			// Check that all other node-specific data was also removed
			// starting with the wep.
			w, _ := calicoClient.WorkloadEndpoints().Get(context.Background(), "default", "calicoodename-k8s-mypod-mywep", options.GetOptions{})
			Expect(w).To(BeNil())

			// Check that the wep's IP was released
			Eventually(func() error {
				ips, err := calicoClient.IPAM().IPsByHandle(context.Background(), handle)
				if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok && err != nil {
					return err
				}
				if len(ips) != 0 {
					return fmt.Errorf("IP not GC'd: %s", ips)
				}
				return nil
			}, 5*time.Second).ShouldNot(HaveOccurred())

			// Check that the orphaned IP was released
			Eventually(func() error {
				ips, err := calicoClient.IPAM().IPsByHandle(context.Background(), handle2)
				if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok && err != nil {
					return err
				}
				if len(ips) != 0 {
					return fmt.Errorf("IP not GC'd: %s", ips)
				}
				return nil
			}, 5*time.Second).ShouldNot(HaveOccurred())

			// Check that the IP in the orphaned block was released.
			Eventually(func() error {
				ips, err := calicoClient.IPAM().IPsByHandle(context.Background(), handle3)
				if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok && err != nil {
					return err
				}
				if len(ips) != 0 {
					return fmt.Errorf("IP not GC'd: %s", ips)
				}
				return nil
			}, 5*time.Second).ShouldNot(HaveOccurred())

			// Check that the borrowed address was released.
			Eventually(func() error {
				ips, err := calicoClient.IPAM().IPsByHandle(context.Background(), handle4)
				if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok && err != nil {
					return err
				}
				if len(ips) != 0 {
					return fmt.Errorf("IP not GC'd: %s", ips)
				}
				return nil
			}, 5*time.Second).ShouldNot(HaveOccurred())

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

			// Check that the two blocks were deleted.
			blocks, err := be.List(context.Background(), model.BlockListOptions{}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(blocks.KVPairs).To(HaveLen(0))
		})

		It("should sync labels from k8s -> calico", func() {
			// Create a kubernetes node with some labels.
			kn := &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: kNodeName,
					Labels: map[string]string{
						"label1": "value1",
					},
				},
			}
			_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Create a Calico node with a reference to it.
			cn := libapi.NewNode()
			cn.Name = cNodeName
			cn.Labels = map[string]string{"calico-label": "calico-value", "label1": "badvalue"}
			cn.Spec = libapi.NodeSpec{
				OrchRefs: []libapi.OrchRef{
					{
						NodeName:     kNodeName,
						Orchestrator: "k8s",
					},
				},
			}
			_, err = calicoClient.Nodes().Create(context.Background(), cn, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Expect the node label to sync.
			expected := map[string]string{"label1": "value1", "calico-label": "calico-value"}
			Eventually(func() error { return expectLabels(calicoClient, expected, cNodeName) },
				time.Second*15, 500*time.Millisecond).Should(BeNil())

			// Update the Kubernetes node labels.
			Expect(testutils.UpdateK8sNode(k8sClient, kn.Name, func(kn *v1.Node) {
				kn.Labels["label1"] = "value2"
			})).NotTo(HaveOccurred())

			// Expect the node label to sync.
			expected = map[string]string{"label1": "value2", "calico-label": "calico-value"}
			Eventually(func() error { return expectLabels(calicoClient, expected, cNodeName) },
				time.Second*15, 500*time.Millisecond).Should(BeNil())

			// Delete the label, add a different one.
			Expect(testutils.UpdateK8sNode(k8sClient, kn.Name, func(kn *v1.Node) {
				kn.Labels = map[string]string{"label2": "value1"}
			})).NotTo(HaveOccurred())

			// Expect the node labels to sync.
			expected = map[string]string{"label2": "value1", "calico-label": "calico-value"}
			Eventually(func() error { return expectLabels(calicoClient, expected, cNodeName) },
				time.Second*15, 500*time.Millisecond).Should(BeNil())

			// Delete the Kubernetes node.
			err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kNodeName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() *libapi.Node {
				node, _ := calicoClient.Nodes().Get(context.Background(), cNodeName, options.GetOptions{})
				return node
			}, time.Second*2, 500*time.Millisecond).Should(BeNil())
		})
	})
})

func expectLabels(c client.Interface, labels map[string]string, node string) error {
	cn, err := c.Nodes().Get(context.Background(), node, options.GetOptions{})
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(cn.Labels, labels) {
		s := fmt.Sprintf("Labels do not match.\n\nExpected: %#v\n  Actual: %#v\n", labels, cn.Labels)
		logrus.Warn(s)
		return fmt.Errorf(s)
	}
	return nil
}

func assertNumBlocks(bc backend.Client, num int) error {
	blocks, err := bc.List(context.Background(), model.BlockListOptions{}, "")
	if err != nil {
		return fmt.Errorf("error querying blocks: %s", err)
	}
	if len(blocks.KVPairs) != num {
		return fmt.Errorf("Expected %d blocks, found %d. Blocks: %#v", num, len(blocks.KVPairs), blocks)
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
		return fmt.Errorf("Expected %d IPs with handle %s, found %d (%v)", num, handle, len(ips), ips)
	}
	return nil
}
