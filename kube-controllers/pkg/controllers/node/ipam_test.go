// Copyright (c) 2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package node

import (
	"context"
	"fmt"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	kubevirtv1 "kubevirt.io/api/core/v1"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/converter"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const (
	// Shorten the grace period of the controller to speed up tests. With a grace period
	// of 1 second, we expect periodically triggered sync's every 500ms, and that IPs will
	// move from candidate -> confirmed leak after one second.
	gracePeriod = 1 * time.Second

	// Asserting on GC output should allow for three grace periods to occur.
	// This ensures we don't hit race conditions with the internal GC loop.
	assertionTimeout = 3 * gracePeriod
)

// assertConsistentState performs checks on the provided IPAM controller's internal
// caches to ensure that they are consistent with each other. Useful for ensuring that
// at any arbitrary point in time, we're not in an unknown state.
func assertConsistentState(c *IPAMController) {
	// Stop the world so we can inspect it.
	done := c.pause()
	defer done()

	// Make sure that allBlocks contains all of the blocks.
	for cidr := range c.emptyBlocks {
		_, ok := c.allBlocks[cidr]
		Expect(ok).To(BeTrue(), fmt.Sprintf("Block %s not present in allBlocks", cidr))
	}
	for _, blocks := range c.blocksByNode {
		for cidr := range blocks {
			_, ok := c.allBlocks[cidr]
			Expect(ok).To(BeTrue(), fmt.Sprintf("Block %s not present in allBlocks", cidr))
		}
	}
	for cidr := range c.allocationsByBlock {
		_, ok := c.allBlocks[cidr]
		Expect(ok).To(BeTrue(), fmt.Sprintf("Block %s not present in allBlocks, but is present in allocationsByBlock", cidr))
	}

	// Make sure blocksByNode and nodesByBlock are consistent.
	for n, blocks := range c.blocksByNode {
		for cidr := range blocks {
			ExpectWithOffset(1, c.nodesByBlock[cidr]).To(Equal(n), fmt.Sprintf("Block %s on wrong node", cidr))
		}
	}
	for cidr, n := range c.nodesByBlock {
		ExpectWithOffset(1, c.blocksByNode[n][cidr]).To(BeTrue(), fmt.Sprintf("Block %s not present in blocksByNode", cidr))
	}

	// Make sure every allocation within the allocationState is present in the other maps.
	for node, allocations := range c.allocationState.allocationsByNode {
		for id, a := range allocations {
			ExpectWithOffset(1, c.allocationsByBlock[a.block][id]).To(Equal(a), fmt.Sprintf("Allocation %s not present in allocationsByBlock", id))
		}
		ExpectWithOffset(1, c.blocksByNode).To(HaveKey(node), fmt.Sprintf("Node %s not present in blocksByNode", node))
	}
}

// createPod is a helper to create Pod objects that ensures we execute the transformer functionality as part of UTs.
func createPod(ctx context.Context, cs kubernetes.Interface, p *v1.Pod) (*v1.Pod, error) {
	t := converter.PodTransformer(true)
	a, err := t(p)
	if err != nil {
		return nil, err
	}
	transformed := a.(*v1.Pod)
	return cs.CoreV1().Pods(transformed.Namespace).Create(ctx, transformed, metav1.CreateOptions{})
}

var _ = Describe("IPAM controller UTs", func() {
	var c *IPAMController
	var cli client.Interface
	var cs kubernetes.Interface
	var vmIndexer cache.Indexer
	var vmiIndexer cache.Indexer
	var stopChan chan struct{}
	var pods chan *v1.Pod
	var nodes chan *v1.Node

	BeforeEach(func() {
		// Create a fake clientset with nothing in it.
		cs = fake.NewSimpleClientset()

		// Create a fake Calico client.
		cli = NewFakeCalicoClient()

		vmIndexer = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
		vmiIndexer = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})

		// Create a node indexer with the fake clientset
		factory := informers.NewSharedInformerFactory(cs, 0)
		podInformer := factory.Core().V1().Pods().Informer()
		nodeInformer := factory.Core().V1().Nodes().Informer()

		// Config for the test.
		cfg := config.NodeControllerConfig{
			LeakGracePeriod: &metav1.Duration{Duration: gracePeriod},
		}

		// stopChan is used in AfterEach to stop the controller in each test.
		stopChan = make(chan struct{})

		pods = make(chan *v1.Pod, 1)
		_, err := podInformer.AddEventHandler(&cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				pod := obj.(*v1.Pod)
				pods <- pod
			},
			DeleteFunc: func(obj any) {
				pod := obj.(*v1.Pod)
				pods <- pod
			},
		})
		Expect(err).NotTo(HaveOccurred())
		nodes = make(chan *v1.Node, 1)
		_, err = nodeInformer.AddEventHandler(&cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				node := obj.(*v1.Node)
				nodes <- node
			},
			DeleteFunc: func(obj any) {
				node := obj.(*v1.Node)
				nodes <- node
			},
		})
		Expect(err).NotTo(HaveOccurred())

		factory.Start(stopChan)
		cache.WaitForCacheSync(stopChan, podInformer.HasSynced)
		cache.WaitForCacheSync(stopChan, nodeInformer.HasSynced)

		// Create a new controller. We don't register with a data feed,
		// as the tests themselves will drive the controller.
		c = NewIPAMController(cfg, cli, cs, podInformer.GetIndexer(), nodeInformer.GetIndexer(), vmIndexer, vmiIndexer)

		// For testing, speed up update batching.
		c.consolidationWindow = 1 * time.Millisecond
	})

	AfterEach(func() {
		// Assert test leaves the controller with a consistent internal state.
		assertConsistentState(c)

		// Stop the controller.
		close(stopChan)
	})

	Describe("VMI allocation validation", func() {
		makeVMIAllocation := func(ns, vmName string) *allocation {
			return &allocation{
				ip:     "10.0.0.1",
				handle: "vmi-handle",
				attrs: map[string]string{
					ipam.AttributeNamespace: ns,
					ipam.AttributeVMIName:   vmName,
				},
			}
		}

		It("should treat matching VM allocation as valid", func() {
			c.Start(stopChan)
			resume := c.pause()
			defer resume()

			namespace := "default"
			vmName := "test-vm"
			vmUID := "vm-uid"
			runStrategy := kubevirtv1.RunStrategyAlways
			vm := &kubevirtv1.VirtualMachine{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vmName,
					Namespace: namespace,
					UID:       types.UID(vmUID),
				},
				Spec: kubevirtv1.VirtualMachineSpec{
					RunStrategy: &runStrategy,
				},
			}

			Expect(vmIndexer.Add(vm)).NotTo(HaveOccurred())

			allocation := makeVMIAllocation(namespace, vmName)
			Expect(c.isVMAllocationValid(allocation)).To(BeTrue())
		})

		It("should treat allocation as invalid if VM not found", func() {
			c.Start(stopChan)
			namespace := "default"

			allocation := makeVMIAllocation(namespace, "invalid-vm-name")
			Expect(c.isVMAllocationValid(allocation)).To(BeFalse())
		})

		It("should treat allocation as valid if VM not found but Standalone VMI exist", func() {
			c.Start(stopChan)
			namespace := "default"
			vmiName := "test-vm"
			vmiUID := "vmi-uid"

			vmi := &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vmiName,
					Namespace: namespace,
					UID:       types.UID(vmiUID),
				},
			}
			Expect(vmiIndexer.Add(vmi)).NotTo(HaveOccurred())

			allocation := makeVMIAllocation(namespace, vmiName)
			Expect(c.isVMAllocationValid(allocation)).To(BeTrue())
		})

		It("should treat allocation as invalid if VMI exists but is owned by a deleted VM", func() {
			c.Start(stopChan)
			namespace := "default"
			vmiName := "test-vm"
			vmiUID := "vmi-uid"
			isController := true

			// VMI with a VM ownerReference — but the VM is not in the cache.
			vmi := &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vmiName,
					Namespace: namespace,
					UID:       types.UID(vmiUID),
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "kubevirt.io/v1",
							Kind:       "VirtualMachine",
							Name:       vmiName,
							Controller: &isController,
						},
					},
				},
			}
			Expect(vmiIndexer.Add(vmi)).NotTo(HaveOccurred())

			allocation := makeVMIAllocation(namespace, vmiName)
			Expect(c.isVMAllocationValid(allocation)).To(BeFalse())
		})

		It("should treat allocation as valid if namespace or vmName attributes are missing", func() {
			c.Start(stopChan)

			allocation := makeVMIAllocation("", "")
			Expect(c.isVMAllocationValid(allocation)).To(BeTrue())
		})

		It("should treat allocation as valid if KubeVirt indexers are nil (KubeVirt not installed)", func() {
			c.vmIndexer = nil
			c.vmiIndexer = nil
			c.Start(stopChan)

			allocation := makeVMIAllocation("default", "some-vm")
			Expect(c.isVMAllocationValid(allocation)).To(BeTrue())
		})
	})

	Describe("VM allocation GC through checkAllocations", func() {
		var handle string
		var blockCIDR string

		// setupVMAllocation creates a Calico node, Kubernetes node, and a VM-type
		// IPAM allocation block. The allocation has both Pod and VMIName attributes
		// to match real KubeVirt allocations.
		setupVMAllocation := func() {
			n := internalapi.Node{}
			n.Name = "cnode"
			n.Spec.OrchRefs = []internalapi.OrchRef{{NodeName: "kname", Orchestrator: apiv3.OrchestratorKubernetes}}
			_, err := cli.Nodes().Create(context.TODO(), &n, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			kn := v1.Node{}
			kn.Name = "kname"
			_, err = cs.CoreV1().Nodes().Create(context.TODO(), &kn, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			var node *v1.Node
			Eventually(nodes).WithTimeout(time.Second).Should(Receive(&node))

			handle = "vmi-handle"
			idx := 0
			cidr := net.MustParseCIDR("10.0.0.0/30")
			aff := "host:cnode"
			key := model.BlockKey{CIDR: cidr}
			b := model.AllocationBlock{
				CIDR:        cidr,
				Affinity:    &aff,
				Allocations: []*int{&idx, nil, nil, nil},
				Unallocated: []int{1, 2, 3},
				Attributes: []model.AllocationAttribute{
					{
						HandleID: &handle,
						ActiveOwnerAttrs: map[string]string{
							ipam.AttributeNode:      "cnode",
							ipam.AttributePod:       "virt-launcher-test-vm-xxxxx",
							ipam.AttributeNamespace: "default",
							ipam.AttributeVMIName:   "test-vm",
						},
					},
				},
			}
			kvp := model.KVPair{Key: key, Value: &b}
			blockCIDR = kvp.Key.(model.BlockKey).CIDR.String()
			update := bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
			c.onUpdate(update)
		}

		It("should GC VM allocation after grace period when VM is missing", func() {
			// Use a short grace period for testing.
			c.vmRecreationGracePeriod = gracePeriod

			c.Start(stopChan)
			setupVMAllocation()

			// Wait for internal caches to update.
			Eventually(func() bool {
				done := c.pause()
				defer done()
				_, ok := c.allBlocks[blockCIDR]
				return ok
			}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

			c.onStatusUpdate(bapi.InSync)

			// VM does not exist in virtClient, so the allocation should eventually be GC'd
			// after the grace period.
			fakeClient := cli.IPAM().(*fakeIPAMClient)
			Eventually(func() bool {
				return fakeClient.handlesReleased[handle]
			}, assertionTimeout, 100*time.Millisecond).Should(BeTrue())
		})

		It("should not GC VM allocation within grace period", func() {
			// Use a very long grace period so it never expires during the test.
			c.vmRecreationGracePeriod = 1 * time.Hour

			c.Start(stopChan)
			setupVMAllocation()

			// Wait for internal caches to update.
			Eventually(func() bool {
				done := c.pause()
				defer done()
				_, ok := c.allBlocks[blockCIDR]
				return ok
			}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

			c.onStatusUpdate(bapi.InSync)

			// VM does not exist, but grace period is long.
			// The allocation should be a candidate leak but NOT confirmed.
			fakeClient := cli.IPAM().(*fakeIPAMClient)

			// Wait for at least one GC cycle to run so the allocation is marked as a candidate.
			allocID := fmt.Sprintf("%s/%s", handle, "10.0.0.0")
			Eventually(func() bool {
				done := c.pause()
				defer done()
				a := c.allocationState.allocationsByNode["cnode"][allocID]
				return a != nil && a.leakedAt != nil
			}, assertionTimeout, 100*time.Millisecond).Should(BeTrue(), "allocation should be a candidate leak")

			// The handle should NOT be released (grace period not expired).
			Consistently(func() bool {
				return fakeClient.handlesReleased[handle]
			}, assertionTimeout, 100*time.Millisecond).Should(BeFalse())
		})

		It("should stop GC when VM reappears during grace period", func() {
			// Use a very long grace period so it never expires during the test.
			c.vmRecreationGracePeriod = 1 * time.Hour

			c.Start(stopChan)
			setupVMAllocation()

			// Wait for internal caches to update.
			Eventually(func() bool {
				done := c.pause()
				defer done()
				_, ok := c.allBlocks[blockCIDR]
				return ok
			}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

			c.onStatusUpdate(bapi.InSync)

			// Wait for the allocation to become a candidate leak.
			allocID := fmt.Sprintf("%s/%s", handle, "10.0.0.0")
			Eventually(func() bool {
				done := c.pause()
				defer done()
				a := c.allocationState.allocationsByNode["cnode"][allocID]
				return a != nil && a.leakedAt != nil
			}, assertionTimeout, 100*time.Millisecond).Should(BeTrue(), "allocation should be a candidate leak")

			// Now create the VM so it exists.
			runStrategy := kubevirtv1.RunStrategyAlways
			vm := &kubevirtv1.VirtualMachine{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-vm",
					Namespace: "default",
					UID:       "vm-uid",
				},
				Spec: kubevirtv1.VirtualMachineSpec{
					RunStrategy: &runStrategy,
				},
			}
			Expect(vmIndexer.Add(vm)).NotTo(HaveOccurred())

			// The allocation should be marked valid and leakedAt cleared.
			Eventually(func() bool {
				done := c.pause()
				defer done()
				a := c.allocationState.allocationsByNode["cnode"][allocID]
				return a != nil && a.leakedAt == nil && !a.confirmedLeak
			}, assertionTimeout, 100*time.Millisecond).Should(BeTrue(), "allocation should be marked valid after VM reappears")
		})
	})

	It("should handle node updates and maintain its node cache", func() {
		// Start the controller.
		c.Start(stopChan)

		calicoNodeName := "cname"
		key := model.ResourceKey{Name: calicoNodeName, Kind: internalapi.KindNode}
		n := internalapi.Node{}
		n.Name = calicoNodeName
		n.Spec.OrchRefs = []internalapi.OrchRef{
			{NodeName: "kname", Orchestrator: apiv3.OrchestratorKubernetes},
		}
		kvp := model.KVPair{
			Key:   key,
			Value: &n,
		}
		update := bapi.Update{
			KVPair:     kvp,
			UpdateType: bapi.UpdateTypeKVNew,
		}

		// Send a new Node update.
		c.onUpdate(update)

		// Check internal state is updated. Because the main loop is
		// in a different goroutine, this might take a short period of time.
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.kubernetesNodesByCalicoName[n.Name]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal("kname"), "Cache not updated after ADD")

		// Send an update that changes the Kubernetes node name.
		// This should be rare, or maybe never happen, but we should handle it anyway.
		n.Spec.OrchRefs[0].NodeName = "kname2"
		update.UpdateType = bapi.UpdateTypeKVUpdated
		c.onUpdate(update)

		// Expect the cache to be updated.
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.kubernetesNodesByCalicoName[n.Name]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal("kname2"), "Cache not updated after UPDATE")

		// Send a delete for the node, which should remove the entry from the cache.
		update.Value = nil
		c.onUpdate(update)
		Eventually(func() map[string]string {
			done := c.pause()
			defer done()
			return c.kubernetesNodesByCalicoName
		}, 1*time.Second, 100*time.Millisecond).ShouldNot(HaveKey(n.Name), "Cache not updated after DELETE")

		// Recreate the Calico node as a non-Kubernetes node.
		n.Spec.OrchRefs[0].Orchestrator = apiv3.OrchestratorOpenStack
		update.Value = &n
		update.UpdateType = bapi.UpdateTypeKVNew
		c.onUpdate(update)

		// Expect the cache to be updated, mapping the Calico name to "".
		Eventually(func() bool {
			done := c.pause()
			defer done()
			kname, ok := c.kubernetesNodesByCalicoName[n.Name]
			return ok && kname == ""
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue(), "Cache not updated as expected after ADD of non-k8s node")

		// Send a delete for the non-Kubernetes node, which should remove the entry from the cache.
		update.Value = nil
		c.onUpdate(update)
		Eventually(func() map[string]string {
			done := c.pause()
			defer done()
			return c.kubernetesNodesByCalicoName
		}, 1*time.Second, 100*time.Millisecond).ShouldNot(HaveKey(n.Name), "Cache not updated after DELETE")
	})

	It("should handle adding and deleting blocks", func() {
		// Start the controller.
		c.Start(stopChan)

		// Add a new block with no allocations.
		cidr := net.MustParseCIDR("10.0.0.0/30")
		aff := "host:cnode"
		key := model.BlockKey{CIDR: cidr}
		b := model.AllocationBlock{
			CIDR:        cidr,
			Affinity:    &aff,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 1, 2, 3},
			Attributes:  []model.AllocationAttribute{},
		}
		kvp := model.KVPair{
			Key:   key,
			Value: &b,
		}
		blockCIDR := kvp.Key.(model.BlockKey).CIDR.String()
		update := bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(update)

		// Expect new entries in the internal maps.
		Eventually(func() model.KVPair {
			done := c.pause()
			defer done()
			return c.allBlocks[blockCIDR]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(kvp))
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.nodesByBlock["10.0.0.0/30"]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal("cnode"))
		Eventually(func() map[string]*allocation {
			done := c.pause()
			defer done()
			return c.allocationState.allocationsByNode["cnode"]
		}, 1*time.Second, 100*time.Millisecond).Should(BeNil())

		// Now, allocate an address in the block and send it in as an update.
		idx := 0
		handle := "test-handle"
		b.Allocations[0] = &idx
		b.Unallocated = []int{1, 2, 3}
		b.Attributes = append(b.Attributes, model.AllocationAttribute{
			HandleID: &handle,
			ActiveOwnerAttrs: map[string]string{
				ipam.AttributeNode:      "cnode",
				ipam.AttributePod:       "test-pod",
				ipam.AttributeNamespace: "test-namespace",
			},
		})
		c.onUpdate(update)

		expectedAllocation := &allocation{
			ip:     "10.0.0.0",
			handle: handle,
			attrs:  b.Attributes[0].ActiveOwnerAttrs,
			block:  "10.0.0.0/30",
		}

		// Unique ID we expect for this allocation.
		id := fmt.Sprintf("%s/%s", handle, "10.0.0.0")

		// Expect new entries in the internal maps.
		Eventually(func() model.KVPair {
			done := c.pause()
			defer done()
			return c.allBlocks[blockCIDR]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(kvp))
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.nodesByBlock["10.0.0.0/30"]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal("cnode"))
		Eventually(func() map[string]*allocation {
			done := c.pause()
			defer done()
			return c.allocationState.allocationsByNode["cnode"]
		}, 1*time.Second, 100*time.Millisecond).ShouldNot(BeNil())
		Eventually(func() *allocation {
			done := c.pause()
			defer done()
			return c.allocationsByBlock[blockCIDR][id]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(expectedAllocation))
		Eventually(func() *allocation {
			done := c.pause()
			defer done()
			return c.allocationState.allocationsByNode["cnode"][id]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(expectedAllocation))

		// Release the address from above and expect original state to be restored.
		b.Allocations[0] = nil
		b.Unallocated = []int{1, 2, 3, 0}
		b.Attributes = []model.AllocationAttribute{}
		c.onUpdate(update)
		Eventually(func() model.KVPair {
			done := c.pause()
			defer done()
			return c.allBlocks[blockCIDR]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(kvp))
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.nodesByBlock["10.0.0.0/30"]
		}, assertionTimeout, time.Second).Should(Equal("cnode"))
		Eventually(func() map[string]*allocation {
			done := c.pause()
			defer done()
			return c.allocationState.allocationsByNode["cnode"]
		}, 1*time.Second, 100*time.Millisecond).Should(BeNil())
		Eventually(func() *allocation {
			done := c.pause()
			defer done()
			return c.allocationsByBlock[blockCIDR][id]
		}, 1*time.Second, 100*time.Millisecond).Should(BeNil())

		Eventually(func() *allocation {
			done := c.pause()
			defer done()
			return c.allocationState.allocationsByNode["cnode"][id]
		}, 1*time.Second, 100*time.Millisecond).Should(BeNil())

		// Delete the block and expect everything to be cleaned up.
		update.Value = nil
		c.onUpdate(update)
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allBlocks[blockCIDR]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeFalse())
		Eventually(func() map[string]*allocation {
			done := c.pause()
			defer done()
			return c.allocationState.allocationsByNode["cnode"]
		}, 1*time.Second, 100*time.Millisecond).Should(BeNil())
		Eventually(func() map[string]*allocation {
			done := c.pause()
			defer done()
			return c.allocationsByBlock[blockCIDR]
		}, 1*time.Second, 100*time.Millisecond).Should(BeNil())
	})

	It("should maintain pool and block mappings", func() {
		// Start the controller.
		c.Start(stopChan)

		// Add first block with no pools established.
		firstBlockCIDR := net.MustParseCIDR("192.168.0.0/30")
		firstBlockAff := "host:cnode"
		firstBlockKey := model.BlockKey{CIDR: firstBlockCIDR}
		firstBlock := model.AllocationBlock{
			CIDR:        firstBlockCIDR,
			Affinity:    &firstBlockAff,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 1, 2, 3},
			Attributes:  []model.AllocationAttribute{},
		}
		firstBlockKVP := model.KVPair{
			Key:   firstBlockKey,
			Value: &firstBlock,
		}
		firstBlockUpdate := bapi.Update{KVPair: firstBlockKVP, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(firstBlockUpdate)

		// Expect new entries in the pool manager maps under unknown pool.
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.poolManager.poolsByBlock[firstBlockCIDR.String()]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(unknownPoolLabel))
		Eventually(func() map[string]bool {
			done := c.pause()
			defer done()
			return c.poolManager.blocksByPool[unknownPoolLabel]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(map[string]bool{firstBlockCIDR.String(): true}))
		Eventually(func() map[string]*apiv3.IPPool {
			done := c.pause()
			defer done()
			return c.poolManager.allPools
		}, 1*time.Second, 100*time.Millisecond).Should(BeEmpty())

		// Establish first pool for the first block.
		firstIPPoolName := "ippool-1"
		firstIPPoolKey := model.ResourceKey{Name: firstIPPoolName, Kind: apiv3.KindIPPool}
		firstIPPool := apiv3.IPPool{}
		firstIPPool.Name = firstIPPoolName
		firstIPPool.Spec.CIDR = "192.168.0.0/24"
		firstIPPool.Spec.BlockSize = 30
		firstIPPool.Spec.NodeSelector = "all()"
		firstIPPool.Spec.Disabled = false
		firstPoolKVP := model.KVPair{
			Key:   firstIPPoolKey,
			Value: &firstIPPool,
		}
		firstPoolUpdate := bapi.Update{
			KVPair:     firstPoolKVP,
			UpdateType: bapi.UpdateTypeKVNew,
		}
		c.onUpdate(firstPoolUpdate)

		// Expect first block to be associated with first pool.
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.poolManager.poolsByBlock[firstBlockCIDR.String()]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(firstIPPoolName))
		Eventually(func() map[string]bool {
			done := c.pause()
			defer done()
			return c.poolManager.blocksByPool[firstIPPoolName]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(map[string]bool{firstBlockCIDR.String(): true}))
		Eventually(func() *apiv3.IPPool {
			done := c.pause()
			defer done()
			return c.poolManager.allPools[firstIPPoolName]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(&firstIPPool))

		// Create a second pool and a second block immediately associated to it.
		secondIPPoolName := "ippool-2"
		secondIPPoolKey := model.ResourceKey{Name: secondIPPoolName, Kind: apiv3.KindIPPool}
		secondIPPool := apiv3.IPPool{}
		secondIPPool.Name = secondIPPoolName
		secondIPPool.Spec.CIDR = "10.16.0.0/24"
		secondIPPool.Spec.BlockSize = 30
		secondIPPool.Spec.NodeSelector = "all()"
		secondIPPool.Spec.Disabled = false
		secondIPPoolKVP := model.KVPair{
			Key:   secondIPPoolKey,
			Value: &secondIPPool,
		}
		secondPoolUpdate := bapi.Update{
			KVPair:     secondIPPoolKVP,
			UpdateType: bapi.UpdateTypeKVNew,
		}
		c.onUpdate(secondPoolUpdate)

		secondBlockCIDR := net.MustParseCIDR("10.16.0.0/30")
		secondBlockAff := "host:cnode"
		secondBlockKey := model.BlockKey{CIDR: secondBlockCIDR}
		secondBlock := model.AllocationBlock{
			CIDR:        secondBlockCIDR,
			Affinity:    &secondBlockAff,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 1, 2, 3},
			Attributes:  []model.AllocationAttribute{},
		}
		secondBlockKVP := model.KVPair{
			Key:   secondBlockKey,
			Value: &secondBlock,
		}
		secondBlockUpdate := bapi.Update{KVPair: secondBlockKVP, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(secondBlockUpdate)

		// Expect second block to be associated with second pool.
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.poolManager.poolsByBlock[secondBlockCIDR.String()]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(secondIPPoolName))
		Eventually(func() map[string]bool {
			done := c.pause()
			defer done()
			return c.poolManager.blocksByPool[secondIPPoolName]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(map[string]bool{secondBlockCIDR.String(): true}))
		Eventually(func() *apiv3.IPPool {
			done := c.pause()
			defer done()
			return c.poolManager.allPools[secondIPPoolName]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(&secondIPPool))

		// Delete second block (associated with second pool). Expect block to be removed from pool maps.
		secondBlockUpdate.Value = nil
		c.onUpdate(secondBlockUpdate)
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.poolManager.poolsByBlock[secondBlockCIDR.String()]
		}, 1*time.Second, 100*time.Millisecond).Should(BeEmpty())
		Eventually(func() map[string]bool {
			done := c.pause()
			defer done()
			return c.poolManager.blocksByPool[secondIPPoolName]
		}, 1*time.Second, 100*time.Millisecond).Should(BeEmpty())

		// Delete first pool. Expect first block to be associated with unknown pool, and pool removed from pool cache.
		firstPoolUpdate.Value = nil
		c.onUpdate(firstPoolUpdate)
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.poolManager.poolsByBlock[firstBlockCIDR.String()]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(unknownPoolLabel))
		Eventually(func() map[string]bool {
			done := c.pause()
			defer done()
			return c.poolManager.blocksByPool[unknownPoolLabel]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(map[string]bool{firstBlockCIDR.String(): true}))
		Eventually(func() *apiv3.IPPool {
			done := c.pause()
			defer done()
			return c.poolManager.allPools[firstIPPoolName]
		}, 1*time.Second, 100*time.Millisecond).Should(BeNil())

		// Delete first block (unassociated with a pool). Expect block to be removed from pool maps.
		firstBlockUpdate.Value = nil
		c.onUpdate(firstBlockUpdate)
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.poolManager.poolsByBlock[firstBlockCIDR.String()]
		}, 1*time.Second, 100*time.Millisecond).Should(BeEmpty())
		Eventually(func() map[string]bool {
			done := c.pause()
			defer done()
			return c.poolManager.blocksByPool[firstIPPoolName]
		}, 1*time.Second, 100*time.Millisecond).Should(BeEmpty())

		// The unknown pool has no more blocks, it should be removed from the blocksByPool map.
		// The second pool has no more blocks, it should remain from the blocksByPool map since it is an active pool.
		Eventually(func() map[string]map[string]bool {
			done := c.pause()
			defer done()
			return c.poolManager.blocksByPool
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(map[string]map[string]bool{"ippool-2": {}}))
	})

	It("should handle node deletion properly", func() {
		// Start the controller.
		c.Start(stopChan)

		// Add a new block with one allocation.
		idx := 0
		handle := "test-handle"
		cidr := net.MustParseCIDR("10.0.0.0/30")
		aff := "host:cnode"
		key := model.BlockKey{CIDR: cidr}
		b := model.AllocationBlock{
			CIDR:        cidr,
			Affinity:    &aff,
			Allocations: []*int{&idx, nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{
					HandleID: &handle,
					ActiveOwnerAttrs: map[string]string{
						ipam.AttributeNode:      "cnode",
						ipam.AttributePod:       "test-pod",
						ipam.AttributeNamespace: "test-namespace",
					},
				},
			},
		}
		kvp := model.KVPair{
			Key:   key,
			Value: &b,
		}
		blockCIDR := kvp.Key.(model.BlockKey).CIDR.String()
		update := bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(update)

		// Wait for internal caches to update.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allBlocks[blockCIDR]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// Mark the syncer as InSync so that the GC will be enabled.
		c.onStatusUpdate(bapi.InSync)

		// Trigger a node deletion. The node referenced in the allocation above
		// never existed in the k8s API and neither does the pod, so this should result in a GC.
		c.OnKubernetesNodeDeleted(&v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "kname"}})

		// Confirm the IP and block affinity were released.
		fakeClient := cli.IPAM().(*fakeIPAMClient)
		Eventually(func() bool {
			return fakeClient.handlesReleased[handle]
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue())
		Eventually(func() bool {
			return fakeClient.affinityReleased("cnode")
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue())
	})

	It("should handle clusterinformation updates and maintain its clusterinformation datastoreReady cache", func() {
		// Start the controller.
		c.Start(stopChan)

		calicoNodeName := "cname"
		isReady := false

		key := model.ResourceKey{Name: calicoNodeName, Kind: apiv3.KindClusterInformation}
		ci := apiv3.ClusterInformation{}
		ci.Name = calicoNodeName
		ci.Spec.DatastoreReady = &isReady
		kvp := model.KVPair{
			Key:   key,
			Value: &ci,
		}
		update := bapi.Update{
			KVPair:     kvp,
			UpdateType: bapi.UpdateTypeKVNew,
		}

		// Send a new ClusterInformation update.
		c.onUpdate(update)

		Eventually(func() bool {
			done := c.pause()
			defer done()
			return c.datastoreReady
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(false), "Cache not updated after UPDATE")

		isReady = true
		c.onUpdate(update)
		Eventually(func() bool {
			done := c.pause()
			defer done()
			return c.datastoreReady
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(true), "Cache not updated after ADD")

		update.Value = nil
		c.onUpdate(update)
		Eventually(func() bool {
			done := c.pause()
			defer done()
			return c.datastoreReady
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(false), "Cache not updated after DELETE")
	})

	It("should clean up leaked IP addresses", func() {
		// Add a new block with one allocation - on a valid node but no corresponding pod.
		n := internalapi.Node{}
		n.Name = "cnode"
		n.Spec.OrchRefs = []internalapi.OrchRef{{NodeName: "kname", Orchestrator: apiv3.OrchestratorKubernetes}}
		_, err := cli.Nodes().Create(context.TODO(), &n, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Add the matching Kubernetes node.
		kn := v1.Node{}
		kn.Name = "kname"
		_, err = cs.CoreV1().Nodes().Create(context.TODO(), &kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		var node *v1.Node
		Eventually(nodes).WithTimeout(time.Second).Should(Receive(&node))

		// Start the controller.
		c.Start(stopChan)

		idx := 0
		handle := "test-handle"
		cidr := net.MustParseCIDR("10.0.0.0/30")
		aff := "host:cnode"
		key := model.BlockKey{CIDR: cidr}
		b := model.AllocationBlock{
			CIDR:        cidr,
			Affinity:    &aff,
			Allocations: []*int{&idx, nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{
					HandleID: &handle,
					ActiveOwnerAttrs: map[string]string{
						ipam.AttributeNode:      "cnode",
						ipam.AttributePod:       "test-pod",
						ipam.AttributeNamespace: "test-namespace",
					},
				},
			},
		}
		kvp := model.KVPair{
			Key:   key,
			Value: &b,
		}
		blockCIDR := kvp.Key.(model.BlockKey).CIDR.String()
		update := bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(update)

		// Wait for internal caches to update.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allBlocks[blockCIDR]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// Mark the syncer as InSync so that the GC will be triggered.
		c.onStatusUpdate(bapi.InSync)

		// Confirm the IP was released. We start the controller with a 5s reconcile period,
		// so this should take at most 15s.
		fakeClient := cli.IPAM().(*fakeIPAMClient)
		Eventually(func() bool {
			return fakeClient.handlesReleased[handle]
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue())

		// The block should remain.
		Consistently(func() bool {
			return fakeClient.affinityReleased("cnode")
		}, assertionTimeout, 100*time.Millisecond).Should(BeFalse())
	})

	It("should handle blocks losing their affinity", func() {
		// Create Calico and k8s nodes for the test.
		n := internalapi.Node{}
		n.Name = "cnode"
		n.Spec.OrchRefs = []internalapi.OrchRef{{NodeName: "kname", Orchestrator: apiv3.OrchestratorKubernetes}}
		_, err := cli.Nodes().Create(context.TODO(), &n, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		kn := v1.Node{}
		kn.Name = "kname"
		_, err = cs.CoreV1().Nodes().Create(context.TODO(), &kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		var node *v1.Node
		Eventually(nodes).WithTimeout(time.Second).Should(Receive(&node))

		// Create a pod for the allocation so that it doesn't get GC'd.
		pod := v1.Pod{}
		pod.Name = "test-pod"
		pod.Namespace = "test-namespace"
		pod.Spec.NodeName = "kname"
		_, err = createPod(context.TODO(), cs, &pod)
		Expect(err).NotTo(HaveOccurred())
		var gotPod *v1.Pod
		Eventually(pods).WithTimeout(time.Second).Should(Receive(&gotPod))

		// Start the controller.
		c.Start(stopChan)

		// Add a new block with one allocation, affine to cnode.
		idx := 0
		handle := "test-handle"
		cidr := net.MustParseCIDR("10.0.0.0/30")
		aff := "host:cnode"
		key := model.BlockKey{CIDR: cidr}
		b := model.AllocationBlock{
			CIDR:        cidr,
			Affinity:    &aff,
			Allocations: []*int{&idx, nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{
					HandleID: &handle,
					ActiveOwnerAttrs: map[string]string{
						ipam.AttributeNode:      "cnode",
						ipam.AttributePod:       pod.Name,
						ipam.AttributeNamespace: pod.Namespace,
					},
				},
			},
		}
		kvp := model.KVPair{
			Key:   key,
			Value: &b,
		}
		blockCIDR := kvp.Key.(model.BlockKey).CIDR.String()
		update := bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(update)

		// Wait for controller state to update. The block
		// should appear in allBlocks.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allBlocks[blockCIDR]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// And, the allocationsByNode map should receive an entry.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allocationState.allocationsByNode["cnode"]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// Now release the block's affinity with no other changes.
		b2 := model.AllocationBlock{
			CIDR:        cidr,
			Affinity:    nil,
			Allocations: []*int{&idx, nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{
					HandleID: &handle,
					ActiveOwnerAttrs: map[string]string{
						ipam.AttributeNode:      "cnode",
						ipam.AttributePod:       pod.Name,
						ipam.AttributeNamespace: pod.Namespace,
					},
				},
			},
		}
		kvp2 := model.KVPair{
			Key:   key,
			Value: &b2,
		}
		update2 := bapi.Update{KVPair: kvp2, UpdateType: bapi.UpdateTypeKVUpdated}
		c.onUpdate(update2)

		// Block still exists.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allBlocks[blockCIDR]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// cnode still has an allocation from the block, even though it is not affine.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allocationState.allocationsByNode["cnode"]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// However, the block is no longer assigned to cnode.
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.nodesByBlock["10.0.0.0/30"]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(""))

		// Finally, release the IP in the now orphaned block. Removing the IP should
		// result in the remaining state being cleaned up.
		By("releasing the IP address", func() {
			b3 := model.AllocationBlock{
				CIDR:        cidr,
				Affinity:    nil,
				Allocations: []*int{nil, nil, nil, nil},
				Unallocated: []int{1, 2, 3, 0},
				Attributes:  []model.AllocationAttribute{},
			}
			kvp3 := model.KVPair{
				Key:   key,
				Value: &b3,
			}
			update3 := bapi.Update{KVPair: kvp3, UpdateType: bapi.UpdateTypeKVUpdated}
			c.onUpdate(update3)
		})

		// Block still exists, but is empty. Note: In a real system,
		// this would trigger deletion of the block.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allBlocks[blockCIDR]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// cnode no longer has any allocations
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allocationState.allocationsByNode["cnode"]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeFalse())

		// The block still has no affinity.
		Eventually(func() string {
			done := c.pause()
			defer done()
			return c.nodesByBlock["10.0.0.0/30"]
		}, 1*time.Second, 100*time.Millisecond).Should(Equal(""))
	})

	It("should NOT clean up IPs if another valid IP shares the handle", func() {
		// Create Calico and k8s nodes for the test.
		n := internalapi.Node{}
		n.Name = "cnode"
		n.Spec.OrchRefs = []internalapi.OrchRef{{NodeName: "kname", Orchestrator: apiv3.OrchestratorKubernetes}}
		_, err := cli.Nodes().Create(context.TODO(), &n, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		kn := v1.Node{}
		kn.Name = "kname"
		_, err = cs.CoreV1().Nodes().Create(context.TODO(), &kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		var node *v1.Node
		Eventually(nodes).WithTimeout(time.Second).Should(Receive(&node))

		// Create a pod for the allocation - the pod will have a single IP in its status, but there will be
		// two IPs allocated which belong to the pod's handle - one "leaked" and one valid. This simulates
		// a scenario where dual-stack is enabled in Calico, but not in Kubernetes, so two IPs will be allocated
		// per-pod, but only one IP will show up in the k8s API.
		pod := v1.Pod{}
		pod.Name = "test-pod"
		pod.Namespace = "test-namespace"
		pod.Spec.NodeName = "kname"
		pod.Status.PodIP = "10.0.0.0"
		pod.Status.PodIPs = []v1.PodIP{{IP: "10.0.0.0"}}
		_, err = createPod(context.TODO(), cs, &pod)
		Expect(err).NotTo(HaveOccurred())
		var gotPod *v1.Pod
		Eventually(pods).WithTimeout(time.Second).Should(Receive(&gotPod))

		// Add a new block with the IPv4 address.
		idx := 0
		handle := "test-handle"
		cidr := net.MustParseCIDR("10.0.0.0/30")
		aff := "host:cnode"
		key := model.BlockKey{CIDR: cidr}
		b := model.AllocationBlock{
			CIDR:        cidr,
			Affinity:    &aff,
			Allocations: []*int{&idx, nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{
					HandleID: &handle,
					ActiveOwnerAttrs: map[string]string{
						ipam.AttributeNode:      "cnode",
						ipam.AttributePod:       pod.Name,
						ipam.AttributeNamespace: pod.Namespace,
					},
				},
			},
		}
		kvp := model.KVPair{
			Key:   key,
			Value: &b,
		}
		update := bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(update)

		// Allocate an IPv6 address to the pod as well.
		cidrv6 := net.MustParseCIDR("fe80::00/126")
		key2 := model.BlockKey{CIDR: cidrv6}
		b2 := model.AllocationBlock{
			CIDR:        cidrv6,
			Affinity:    &aff,
			Allocations: []*int{&idx, nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{
					HandleID: &handle,
					ActiveOwnerAttrs: map[string]string{
						ipam.AttributeNode:      "cnode",
						ipam.AttributePod:       pod.Name,
						ipam.AttributeNamespace: pod.Namespace,
					},
				},
			},
		}
		kvpV6 := model.KVPair{
			Key:   key2,
			Value: &b2,
		}
		updateV6 := bapi.Update{KVPair: kvpV6, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(updateV6)

		// Start the controller.
		c.Start(stopChan)

		By("Waiting for internal caches to sync", func() {
			Eventually(func() bool {
				// v6 block is present.
				blockCIDR := kvpV6.Key.(model.BlockKey).CIDR.String()
				done := c.pause()
				defer done()
				_, ok := c.allBlocks[blockCIDR]
				return ok
			}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

			Eventually(func() bool {
				// v4 block is present.
				blockCIDR := kvp.Key.(model.BlockKey).CIDR.String()
				done := c.pause()
				defer done()
				_, ok := c.allBlocks[blockCIDR]
				return ok
			}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

			Eventually(func() int {
				// Should have two allocations.
				done := c.pause()
				defer done()
				return len(c.allocationState.allocationsByNode["cnode"])
			}, 1*time.Second, 100*time.Millisecond).Should(Equal(2))
		})

		By("Marking the syncer in-sync", func() {
			c.onStatusUpdate(bapi.InSync)
		})

		fakeClient := cli.IPAM().(*fakeIPAMClient)
		By("Verifying initial state", func() {
			// The IPv4 IP should not be marked as a leak.
			Consistently(func() bool {
				done := c.pause()
				defer done()
				a := c.allocationState.allocationsByNode["cnode"]["test-handle/10.0.0.0"]
				return a.isConfirmedLeak()
			}, assertionTimeout, 100*time.Millisecond).Should(BeFalse())

			// The IPv6 IP should be marked as a leak.
			Eventually(func() bool {
				done := c.pause()
				defer done()
				a := c.allocationState.allocationsByNode["cnode"]["test-handle/fe80::"]
				return a.isConfirmedLeak()
			}, assertionTimeout, 1*time.Second).Should(BeTrue())

			// The handle used for the allocation should not be considered a leak because the IPv4 address
			// is still valid.
			Eventually(func() bool {
				done := c.pause()
				defer done()
				return c.handleTracker.isConfirmedLeak(handle)
			}, assertionTimeout, 1*time.Second).Should(BeFalse())

			// Confirm the IPs were NOT released.
			Eventually(func() bool {
				return fakeClient.handlesReleased[handle]
			}, assertionTimeout, 500*time.Millisecond).Should(BeFalse())
		})

		By("Deleting the pod", func() {
			// Deleting the pod should invalidate the IPv4 address, and result in both IPs being GC'd.
			err = cs.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Verifying final state", func() {
			// The handle should now be marked as a leak. This may take some time, as the IPv4 address needs to go
			// through the grace period.
			Eventually(func() bool {
				done := c.pause()
				defer done()
				return c.handleTracker.isConfirmedLeak(handle)
			}, assertionTimeout, 1*time.Second).Should(BeTrue())

			// Confirm the IPs were released.
			Eventually(func() bool {
				return fakeClient.handlesReleased[handle]
			}, assertionTimeout, 100*time.Millisecond).Should(BeTrue())
		})
	})

	It("should not clean up leaked addresses if no grace period set", func() {
		// Set the controller's grace period to 0.
		c.config.LeakGracePeriod = &metav1.Duration{Duration: 0 * time.Second}

		// Add a new block with one allocation - on a valid node but no corresponding pod.
		n := internalapi.Node{}
		n.Name = "cnode"
		n.Spec.OrchRefs = []internalapi.OrchRef{{NodeName: "kname", Orchestrator: apiv3.OrchestratorKubernetes}}
		_, err := cli.Nodes().Create(context.TODO(), &n, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Add the matching Kubernetes node.
		kn := v1.Node{}
		kn.Name = "kname"
		_, err = cs.CoreV1().Nodes().Create(context.TODO(), &kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		var node *v1.Node
		Eventually(nodes).WithTimeout(time.Second).Should(Receive(&node))

		// Start the controller.
		c.Start(stopChan)

		idx := 0
		handle := "test-handle"
		cidr := net.MustParseCIDR("10.0.0.0/30")
		aff := "host:cnode"
		key := model.BlockKey{CIDR: cidr}
		b := model.AllocationBlock{
			CIDR:        cidr,
			Affinity:    &aff,
			Allocations: []*int{&idx, nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{
					HandleID: &handle,
					ActiveOwnerAttrs: map[string]string{
						ipam.AttributeNode:      "cnode",
						ipam.AttributePod:       "test-pod",
						ipam.AttributeNamespace: "test-namespace",
					},
				},
			},
		}
		kvp := model.KVPair{
			Key:   key,
			Value: &b,
		}
		blockCIDR := kvp.Key.(model.BlockKey).CIDR.String()
		update := bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(update)

		// Wait for internal caches to update.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allBlocks[blockCIDR]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// Mark the syncer as InSync so that the GC will be triggered.
		c.onStatusUpdate(bapi.InSync)

		// Confirm the IP was NOT released. We start the controller with a 5s reconcile period,
		// so this should take at most 15s.
		fakeClient := cli.IPAM().(*fakeIPAMClient)
		Eventually(func() bool {
			return fakeClient.handlesReleased[handle]
		}, assertionTimeout, 100*time.Millisecond).Should(BeFalse())

		// The block should remain.
		Consistently(func() bool {
			return fakeClient.affinityReleased("cnode")
		}, assertionTimeout, 100*time.Millisecond).Should(BeFalse())
	})

	It("should clean up empty blocks", func() {
		// Create Calico and k8s nodes for the test.
		n := internalapi.Node{}
		n.Name = "cnode"
		n.Spec.OrchRefs = []internalapi.OrchRef{{NodeName: "kname", Orchestrator: apiv3.OrchestratorKubernetes}}
		_, err := cli.Nodes().Create(context.TODO(), &n, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		kn := v1.Node{}
		kn.Name = "kname"
		_, err = cs.CoreV1().Nodes().Create(context.TODO(), &kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		var node *v1.Node
		Eventually(nodes).WithTimeout(time.Second).Should(Receive(&node))

		// Create a pod for the allocation so that it doesn't get GC'd.
		pod := v1.Pod{}
		pod.Name = "test-pod"
		pod.Namespace = "test-namespace"
		pod.Spec.NodeName = "kname"
		_, err = createPod(context.TODO(), cs, &pod)
		Expect(err).NotTo(HaveOccurred())
		var gotPod *v1.Pod
		Eventually(pods).WithTimeout(time.Second).Should(Receive(&gotPod))

		// Start the controller.
		c.Start(stopChan)

		// Add a new block with one allocation, affine to cnode.
		idx := 0
		handle := "test-handle"
		cidr := net.MustParseCIDR("10.0.0.0/30")
		aff := "host:cnode"
		key := model.BlockKey{CIDR: cidr}
		b := model.AllocationBlock{
			CIDR:        cidr,
			Affinity:    &aff,
			Allocations: []*int{&idx, nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{
					HandleID: &handle,
					ActiveOwnerAttrs: map[string]string{
						ipam.AttributeNode:      "cnode",
						ipam.AttributePod:       pod.Name,
						ipam.AttributeNamespace: pod.Namespace,
					},
				},
			},
		}
		kvp := model.KVPair{
			Key:   key,
			Value: &b,
		}
		blockCIDR := kvp.Key.(model.BlockKey).CIDR.String()
		update := bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(update)

		// Wait for controller state to update. The block
		// should appear in allBlocks.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allBlocks[blockCIDR]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// And, the allocationsByNode map should receive an entry.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allocationState.allocationsByNode["cnode"]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// Add a new block with no allocations.
		cidr2 := net.MustParseCIDR("10.0.0.4/30")
		key2 := model.BlockKey{CIDR: cidr2}
		b2 := model.AllocationBlock{
			CIDR:        cidr2,
			Affinity:    &aff,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 1, 2, 3},
		}
		kvp2 := model.KVPair{
			Key:   key2,
			Value: &b2,
		}
		blockCIDR2 := kvp2.Key.(model.BlockKey).CIDR.String()
		update2 := bapi.Update{KVPair: kvp2, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(update2)

		// The controller should now recognize an empty block.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.emptyBlocks[blockCIDR2]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// Mark the syncer as InSync so that the GC will be enabled.
		c.onStatusUpdate(bapi.InSync)

		// The empty block should be released.
		fakeClient := cli.IPAM().(*fakeIPAMClient)
		Eventually(func() bool {
			return fakeClient.affinityReleased(fmt.Sprintf("%s/%s", blockCIDR2, "cnode"))
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue())
	})

	It("should clean up empty blocks even if the node is full", func() {
		// Create Calico and k8s nodes for the test.
		n := internalapi.Node{}
		n.Name = "cnode"
		n.Spec.OrchRefs = []internalapi.OrchRef{{NodeName: "kname", Orchestrator: apiv3.OrchestratorKubernetes}}
		_, err := cli.Nodes().Create(context.TODO(), &n, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		kn := v1.Node{}
		kn.Name = "kname"
		_, err = cs.CoreV1().Nodes().Create(context.TODO(), &kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		var node *v1.Node
		Eventually(nodes).WithTimeout(time.Second).Should(Receive(&node))

		// Create a pod for the allocation so that it doesn't get GC'd.
		pod := v1.Pod{}
		pod.Name = "test-pod"
		pod.Namespace = "test-namespace"
		pod.Spec.NodeName = "kname"
		_, err = createPod(context.TODO(), cs, &pod)
		Expect(err).NotTo(HaveOccurred())
		var gotPod *v1.Pod
		Eventually(pods).WithTimeout(time.Second).Should(Receive(&gotPod))

		// Start the controller.
		c.Start(stopChan)

		// Add a new block that is full.
		idx := 0
		handle := "test-handle"
		cidr := net.MustParseCIDR("10.0.0.0/30")
		aff := "host:cnode"
		key := model.BlockKey{CIDR: cidr}
		b := model.AllocationBlock{
			CIDR:        cidr,
			Affinity:    &aff,
			Allocations: []*int{&idx, &idx, &idx, &idx},
			Unallocated: []int{},
			Attributes: []model.AllocationAttribute{
				{
					HandleID: &handle,
					ActiveOwnerAttrs: map[string]string{
						ipam.AttributeNode:      "cnode",
						ipam.AttributePod:       pod.Name,
						ipam.AttributeNamespace: pod.Namespace,
					},
				},
			},
		}
		kvp := model.KVPair{
			Key:   key,
			Value: &b,
		}
		blockCIDR := kvp.Key.(model.BlockKey).CIDR.String()
		update := bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(update)

		// Wait for controller state to update. The block
		// should appear in allBlocks.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allBlocks[blockCIDR]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// And, the allocationsByNode map should receive an entry.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allocationState.allocationsByNode["cnode"]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// Add a new block with no allocations.
		cidr2 := net.MustParseCIDR("10.0.0.4/30")
		key2 := model.BlockKey{CIDR: cidr2}
		b2 := model.AllocationBlock{
			CIDR:        cidr2,
			Affinity:    &aff,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 1, 2, 3},
		}
		kvp2 := model.KVPair{
			Key:   key2,
			Value: &b2,
		}
		blockCIDR2 := kvp2.Key.(model.BlockKey).CIDR.String()
		update2 := bapi.Update{KVPair: kvp2, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(update2)

		// The controller should now recognize an empty block.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.emptyBlocks[blockCIDR2]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// Mark the syncer as InSync so that the GC will be enabled.
		c.onStatusUpdate(bapi.InSync)

		// The empty block should be released after the grace period.
		fakeClient := cli.IPAM().(*fakeIPAMClient)
		Eventually(func() bool {
			return fakeClient.affinityReleased(fmt.Sprintf("%s/%s", blockCIDR2, "cnode"))
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue())
		Consistently(func() bool {
			return fakeClient.affinityReleased(fmt.Sprintf("%s/%s", blockCIDR2, "cnode"))
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue())
	})

	It("should NOT clean up all blocks assigned to a node", func() {
		// Create Calico and k8s nodes for the test.
		n := internalapi.Node{}
		n.Name = "cnode"
		n.Spec.OrchRefs = []internalapi.OrchRef{{NodeName: "kname", Orchestrator: apiv3.OrchestratorKubernetes}}
		_, err := cli.Nodes().Create(context.TODO(), &n, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		kn := v1.Node{}
		kn.Name = "kname"
		_, err = cs.CoreV1().Nodes().Create(context.TODO(), &kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		var node *v1.Node
		Eventually(nodes).WithTimeout(time.Second).Should(Receive(&node))

		// Create a pod for the allocation so that it doesn't get GC'd.
		pod := v1.Pod{}
		pod.Name = "test-pod"
		pod.Namespace = "test-namespace"
		pod.Spec.NodeName = "kname"
		_, err = createPod(context.TODO(), cs, &pod)
		Expect(err).NotTo(HaveOccurred())
		var gotPod *v1.Pod
		Eventually(pods).WithTimeout(time.Second).Should(Receive(&gotPod))

		// Start the controller.
		c.Start(stopChan)

		// Add 5 empty blocks to the node.
		for i := range 5 {
			unallocated := make([]int, 64)
			for i := range unallocated {
				unallocated[i] = i
			}
			cidr := net.MustParseCIDR(fmt.Sprintf("10.0.%d.0/24", i))
			aff := "host:cnode"
			key := model.BlockKey{CIDR: cidr}
			b := model.AllocationBlock{
				CIDR:        cidr,
				Affinity:    &aff,
				Allocations: make([]*int, 64),
				Unallocated: unallocated,
				Attributes:  []model.AllocationAttribute{},
			}
			kvp := model.KVPair{
				Key:   key,
				Value: &b,
			}
			update := bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
			c.onUpdate(update)
		}

		// Wait for controller state to update with all blocks.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			return len(c.allBlocks) == 5
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// The controller should recognize them as empty.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			return len(c.emptyBlocks) == 5
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// Mark the syncer as InSync so that the GC will be enabled.
		c.onStatusUpdate(bapi.InSync)

		// 4 out of the 5 empty blocks should be released, but not all.
		numBlocks := func() int {
			done := c.pause()
			defer done()
			return len(c.blocksByNode["cnode"])
		}
		Eventually(numBlocks, assertionTimeout, 100*time.Millisecond).Should(Equal(1))
		Consistently(numBlocks, assertionTimeout, 100*time.Millisecond).Should(Equal(1))
		numBlocks = func() int {
			done := c.pause()
			defer done()
			return len(c.emptyBlocks)
		}
		Eventually(numBlocks, 1*time.Second, 100*time.Millisecond).Should(Equal(1))
		Consistently(numBlocks, assertionTimeout, 100*time.Millisecond).Should(Equal(1))
	})

	// This test verifies that the GC cleans up blocks even if the total number of free addresses on the node
	// is small.
	// Reference: https://github.com/projectcalico/calico/issues/7987
	It("should clean up small IPAM blocks", func() {
		// Create Calico and k8s nodes for the test.
		n := internalapi.Node{}
		n.Name = "cnode"
		n.Spec.OrchRefs = []internalapi.OrchRef{{NodeName: "kname", Orchestrator: apiv3.OrchestratorKubernetes}}
		_, err := cli.Nodes().Create(context.TODO(), &n, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		kn := v1.Node{}
		kn.Name = "kname"
		_, err = cs.CoreV1().Nodes().Create(context.TODO(), &kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		var node *v1.Node
		Eventually(nodes).WithTimeout(time.Second).Should(Receive(&node))

		// Start the controller.
		c.Start(stopChan)

		// Add small, empty blocks to the node.
		// Use a block size of 31, resulting in 2 allocations per block.
		for i := range 5 {
			unallocated := make([]int, 64)
			for i := range unallocated {
				unallocated[i] = i
			}
			cidr := net.MustParseCIDR(fmt.Sprintf("10.0.%d.0/31", i))
			aff := "host:cnode"
			key := model.BlockKey{CIDR: cidr}
			b := model.AllocationBlock{
				CIDR:        cidr,
				Affinity:    &aff,
				Allocations: make([]*int, 64),
				Unallocated: unallocated,
				Attributes:  []model.AllocationAttribute{},
			}
			kvp := model.KVPair{
				Key:   key,
				Value: &b,
			}
			update := bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
			c.onUpdate(update)
		}

		// Wait for controller state to update with all blocks.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			return len(c.allBlocks) == 5
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// The controller should recognize them all as empty.
		Eventually(func() bool {
			done := c.pause()
			defer done()
			return len(c.emptyBlocks) == 5
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// Mark the syncer as InSync so that the GC will be enabled.
		c.onStatusUpdate(bapi.InSync)

		// 4 out of the 5 empty blocks should be released, but not all.
		numBlocks := func() int {
			done := c.pause()
			defer done()
			return len(c.blocksByNode["cnode"])
		}
		Eventually(numBlocks, assertionTimeout, 100*time.Millisecond).Should(Equal(1))
		Consistently(numBlocks, assertionTimeout, 100*time.Millisecond).Should(Equal(1))
		numBlocks = func() int {
			done := c.pause()
			defer done()
			return len(c.emptyBlocks)
		}
		Eventually(numBlocks, 1*time.Second, 100*time.Millisecond).Should(Equal(1))
		Consistently(numBlocks, assertionTimeout, 100*time.Millisecond).Should(Equal(1))
	})

	It("should delete empty IPAM blocks when the node no longer exists", func() {
		// This testcase handles an edge case in our code, to make sure we spot node affinities that
		// must be released even when there are no allocations in the block. Since much of the GC controller logic
		// is based on allocations, it's important to have an explicit test for this case.

		// Create an empty block with an affinity to a node that doesn't exist. Then, trigger a full GC cycle. The controller
		// should spot the empty block and release it.
		c.onUpdate(createBlock(nil, "dead-node", "10.0.0.0/26"))

		// Start the controller.
		c.Start(stopChan)

		// Mark the syncer as InSync so that the GC will be enabled.
		c.fullScanNextSync("forced by test")
		c.onStatusUpdate(bapi.InSync)

		// Expect the block to be released.
		fakeClient := cli.IPAM().(*fakeIPAMClient)
		Eventually(func() bool {
			return fakeClient.affinityReleased("dead-node")
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue(), "Affinity for dead-node should be released")
	})

	Context("with a 1hr grace period", func() {
		ns := "test-namespace"
		podsNode1 := []v1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1-1", Namespace: ns},
				Spec:       v1.PodSpec{NodeName: "node1"},
				Status:     v1.PodStatus{PodIP: "10.0.1.1", PodIPs: []v1.PodIP{{IP: "10.0.1.1"}}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1-2", Namespace: ns},
				Spec:       v1.PodSpec{NodeName: "node1"},
				Status:     v1.PodStatus{PodIP: "10.0.1.2", PodIPs: []v1.PodIP{{IP: "10.0.1.2"}}},
			},
		}
		podsNode2 := []v1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod2-1", Namespace: ns},
				Spec:       v1.PodSpec{NodeName: "node2"},
				Status:     v1.PodStatus{PodIP: "10.0.2.1", PodIPs: []v1.PodIP{{IP: "10.0.2.1"}}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod2-2", Namespace: ns},
				Spec:       v1.PodSpec{NodeName: "node2"},
				Status:     v1.PodStatus{PodIP: "10.0.2.2", PodIPs: []v1.PodIP{{IP: "10.0.2.2"}}},
			},
		}

		BeforeEach(func() {
			// Set the controller's grace period to a large value, to take the periodic GC out of the equation.
			// This suite of tests is focused on response to events, not periodic GC.
			c.config.LeakGracePeriod = &metav1.Duration{Duration: 1 * time.Hour}

			// Create Calico and k8s nodes for the test.
			for _, name := range []string{"node1", "node2"} {
				n := internalapi.Node{}
				n.Name = name
				n.Spec.OrchRefs = []internalapi.OrchRef{{NodeName: name, Orchestrator: apiv3.OrchestratorKubernetes}}
				_, err := cli.Nodes().Create(context.TODO(), &n, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				kn := v1.Node{}
				kn.Name = name
				_, err = cs.CoreV1().Nodes().Create(context.TODO(), &kn, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				var node *v1.Node
				Eventually(nodes).WithTimeout(time.Second).Should(Receive(&node))
			}

			// Create some pods in the API, across two different nodes.
			for _, p := range append(podsNode1, podsNode2...) {
				_, err := createPod(context.TODO(), cs, &p)
				Expect(err).NotTo(HaveOccurred())
				var gotPod *v1.Pod
				Eventually(pods).WithTimeout(time.Second).Should(Receive(&gotPod))
			}

			// Create some IPAM blocks, assigning IPs to the pods.
			c.onUpdate(createBlock(podsNode1, "node1", "10.0.1.0/24"))
			c.onUpdate(createBlock(podsNode2, "node2", "10.0.2.0/24"))

			// Mark the syncer as InSync so that the GC will be enabled.
			c.onStatusUpdate(bapi.InSync)

			// Start the controller.
			c.Start(stopChan)
		})

		It("should handle node deletion events", func() {
			// Delete node1.
			Expect(cs.CoreV1().Nodes().Delete(context.TODO(), "node1", metav1.DeleteOptions{})).NotTo(HaveOccurred())
			c.OnKubernetesNodeDeleted(&v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}})
			Eventually(nodes).WithTimeout(time.Second).Should(Receive())

			// The allocations won't be marked as leaked yet, since the controller is confused about the node's status (deleted,
			// but still has pods).
			Eventually(func() error {
				done := c.pause()
				defer done()
				if _, ok := c.allocationState.allocationsByNode["node1"]; !ok {
					return fmt.Errorf("node1 not found")
				}
				if _, ok := c.allocationState.allocationsByNode["node1"]["pod1-1/10.0.1.1"]; !ok {
					return fmt.Errorf("allocation not found")
				}
				if c.allocationState.allocationsByNode["node1"]["pod1-1/10.0.1.1"].leakedAt != nil {
					return fmt.Errorf("allocation was marked as leaked")
				}
				return nil
			}, 15*time.Second, 100*time.Millisecond).ShouldNot(HaveOccurred())

			// Delete the pods too.
			Expect(cs.CoreV1().Pods(ns).Delete(context.TODO(), podsNode1[0].Name, metav1.DeleteOptions{})).NotTo(HaveOccurred())
			Expect(cs.CoreV1().Pods(ns).Delete(context.TODO(), podsNode1[1].Name, metav1.DeleteOptions{})).NotTo(HaveOccurred())

			// Trigger another sync.
			c.OnKubernetesNodeDeleted(&v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}})

			// All state should be cleaned up now.
			fakeClient := cli.IPAM().(*fakeIPAMClient)
			Eventually(func() error {
				done := c.pause()
				defer done()
				if _, ok := c.allocationState.allocationsByNode["node1"]; ok {
					return fmt.Errorf("node1 still being tracked")
				}
				if !fakeClient.affinityReleased("node1") {
					return fmt.Errorf("node1 affinity not released")
				}
				if len(fakeClient.handlesReleased) != 2 {
					return fmt.Errorf("expected 2 handles to be released, got %d", len(fakeClient.handlesReleased))
				}
				return nil
			}, 15*time.Second, 100*time.Millisecond).ShouldNot(HaveOccurred())
		})
	})

	Context("with a large number of nodes and allocations", func() {
		// This is a sort of stress test to see how well the controller handles a large number of nodes and allocations.
		numNodes := 1000
		podsPerNode := 5

		var allPods []v1.Pod
		var allBlocks []bapi.Update

		// We need a separate fake clientset with a large watcher buffer for bulk creation,
		// and direct access to the informer store for fast pod population.
		var scaleCS kubernetes.Interface
		var scalePodIndexer cache.Indexer
		var scaleNodeIndexer cache.Indexer

		BeforeEach(func() {
			// Create a new fake clientset for the scale test. We'll populate the informer
			// caches directly to avoid the slow create→watch→inform round-trip.
			scaleCS = fake.NewSimpleClientset()

			scaleFactory := informers.NewSharedInformerFactory(scaleCS, 0)
			scalePodInformer := scaleFactory.Core().V1().Pods().Informer()
			scaleNodeInformer := scaleFactory.Core().V1().Nodes().Informer()
			scaleFactory.Start(stopChan)
			cache.WaitForCacheSync(stopChan, scalePodInformer.HasSynced, scaleNodeInformer.HasSynced)

			scalePodIndexer = scalePodInformer.GetIndexer()
			scaleNodeIndexer = scaleNodeInformer.GetIndexer()

			// Recreate the controller with the scale-specific indexers and clientset.
			cfg := config.NodeControllerConfig{
				LeakGracePeriod: &metav1.Duration{Duration: 1 * time.Hour},
			}
			c = NewIPAMController(cfg, cli, scaleCS, scalePodIndexer, scaleNodeIndexer, vmIndexer, vmiIndexer)
			c.consolidationWindow = 1 * time.Second

			// Start the controller.
			c.Start(stopChan)

			// Create Calico nodes via the fake Calico client, and add K8s nodes
			// directly to the informer cache to avoid watch channel overflow.
			for i := range numNodes {
				n := internalapi.Node{}
				n.Name = fmt.Sprintf("node%d", i)
				n.Spec.OrchRefs = []internalapi.OrchRef{{NodeName: n.Name, Orchestrator: apiv3.OrchestratorKubernetes}}
				_, err := cli.Nodes().Create(context.TODO(), &n, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				kn := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: n.Name}}
				Expect(scaleNodeIndexer.Add(kn)).NotTo(HaveOccurred())
			}

			// Build pods and blocks in memory, then add pods directly to the indexer.
			// This bypasses the fake K8s client entirely for bulk creation, avoiding
			// the serial create→watch→inform bottleneck that previously took ~60s.
			t := converter.PodTransformer(true)
			for nodeNum := range numNodes {
				baseIPInt := big.NewInt(int64(0x0a000000 + nodeNum*64))
				baseIP := net.BigIntToIP(baseIPInt, false)
				blockCIDR := fmt.Sprintf("%s/26", baseIP.String())

				podIP := baseIP
				nodeName := fmt.Sprintf("node%d", nodeNum)
				nodePods := []v1.Pod{}
				for podNum := range podsPerNode {
					p := v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      fmt.Sprintf("pod%d-%d", nodeNum, podNum),
							Namespace: "test-namespace",
						},
						Spec: v1.PodSpec{NodeName: nodeName},
						Status: v1.PodStatus{
							PodIP:  podIP.String(),
							PodIPs: []v1.PodIP{{IP: podIP.String()}},
						},
					}
					allPods = append(allPods, p)
					nodePods = append(nodePods, p)
					podIP = net.IncrementIP(podIP, big.NewInt(1))
				}
				allBlocks = append(allBlocks, createBlock(nodePods, nodeName, blockCIDR))
			}

			// Add all pods to the indexer. Apply the same transformer used by production code.
			for i := range allPods {
				transformed, err := t(&allPods[i])
				Expect(err).NotTo(HaveOccurred())
				Expect(scalePodIndexer.Add(transformed)).NotTo(HaveOccurred())
			}

			By("Sending updates for all blocks")
			for _, u := range allBlocks {
				c.onUpdate(u)
			}
			c.onStatusUpdate(bapi.InSync)

			By("Waiting for controller to be in sync")
			Eventually(func() bool {
				done := c.pause()
				defer done()
				return len(c.allBlocks) == numNodes
			}, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
			Eventually(func() bool {
				done := c.pause()
				defer done()
				return len(c.allocationState.dirtyNodes) == 0
			}, 10*time.Second, 100*time.Millisecond).Should(BeTrue(), "Controller did not process all blocks")
			Eventually(func() bool {
				done := c.pause()
				defer done()
				return c.fullSyncRequired
			}, 5*time.Second, 100*time.Millisecond).Should(BeFalse())
		})

		It("should detect a leaked IP reasonably quickly", func() {
			By("Deleting a pod to trigger a leak")

			// Delete one of the pods to trigger a leak, and check that the controller detects it.
			// Remove it from the indexer (so the pod lister can't find it) and notify the controller.
			pod := allPods[numNodes-1]
			Expect(scalePodIndexer.Delete(&pod)).NotTo(HaveOccurred())
			c.OnKubernetesPodDeleted(&pod)

			// Delete a pod on node 0 but don't inform the controller. This should not trigger a leak,
			// since the controller is not aware of the pod deletion.
			pod2 := allPods[0]
			Expect(scalePodIndexer.Delete(&pod2)).NotTo(HaveOccurred())

			// Wait for the controller to detect the leak. This should happen quickly, since the controller
			// will only need to process a single block.
			Eventually(func() bool {
				done := c.pause()
				defer done()
				a := c.allocationState.allocationsByNode[pod.Spec.NodeName][fmt.Sprintf("%s/%s", pod.Name, pod.Status.PodIP)]
				return a.leakedAt != nil
			}, 3*time.Second, 100*time.Millisecond).Should(BeTrue(), "IP was not marked as leaked")
			Consistently(func() bool {
				// While it would not be WRONG to mark the other pod as leaked, we know that the controller won't do so
				// because we haven't told it the pod was deleted. This verifies that the controller is doing work incrementally based
				// on the events it receives, rather than brute force syncing.
				done := c.pause()
				defer done()
				a := c.allocationState.allocationsByNode[pod2.Spec.NodeName][fmt.Sprintf("%s/%s", pod2.Name, pod2.Status.PodIP)]
				return a.leakedAt == nil
			}, assertionTimeout, 100*time.Millisecond).Should(BeTrue(), "IP was unexpected marked as leaked")

			By("Triggering a full IPAM scan")
			// Now do a brute force full scan to ensure that the controller eventually catches up.
			c.fullScanNextSync("forced by test")
			c.onStatusUpdate(bapi.InSync)
			Eventually(func() bool {
				done := c.pause()
				defer done()
				a := c.allocationState.allocationsByNode[pod2.Spec.NodeName][fmt.Sprintf("%s/%s", pod2.Name, pod2.Status.PodIP)]
				return a.leakedAt != nil
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue(), "IP was not marked as leaked")
		})
	})

	It("should clean up node with tunnel IPs in a single sync pass", func() {
		// Start the controller.
		c.Start(stopChan)

		// Create a block with a tunnel address allocation for a node that doesn't exist.
		tunnelHandle := "vxlan-tunnel-addr-dead-node"
		cidr := net.MustParseCIDR("10.0.0.0/30")
		aff := "host:dead-node"
		idx := 0
		key := model.BlockKey{CIDR: cidr}
		b := model.AllocationBlock{
			CIDR:        cidr,
			Affinity:    &aff,
			Allocations: []*int{&idx, nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{
					HandleID: &tunnelHandle,
					ActiveOwnerAttrs: map[string]string{
						ipam.AttributeNode: "dead-node",
						ipam.AttributeType: ipam.AttributeTypeVXLAN,
					},
				},
			},
		}
		kvp := model.KVPair{Key: key, Value: &b}
		update := bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
		c.onUpdate(update)

		// Wait for internal caches to update.
		blockCIDR := kvp.Key.(model.BlockKey).CIDR.String()
		Eventually(func() bool {
			done := c.pause()
			defer done()
			_, ok := c.allBlocks[blockCIDR]
			return ok
		}, 1*time.Second, 100*time.Millisecond).Should(BeTrue())

		// Mark the syncer as InSync and trigger a full scan.
		c.fullScanNextSync("forced by test")
		c.onStatusUpdate(bapi.InSync)

		// Both the tunnel IP GC and the node affinity release should eventually complete.
		fakeClient := cli.IPAM().(*fakeIPAMClient)
		Eventually(func() bool {
			return fakeClient.handlesReleased[tunnelHandle]
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue(), "Tunnel IP handle should be released via GC")

		Eventually(func() bool {
			return fakeClient.affinityReleased("dead-node")
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue(), "Node affinity should be released")
	})

	// Regression test for https://github.com/projectcalico/calico/issues/8643
	//
	// Scenario: When nodes are rapidly scaled down, the IPAM GC controller can get
	// stuck in an infinite retry loop. The root cause is that if
	// ReleaseHostAffinities(mustBeEmpty=true) fails (e.g., because blocks still have
	// allocations due to a race between IP release and block update propagation),
	// dirty nodes accumulated and each subsequent sync processed more and more
	// nodes, increasing contention and making recovery impossible.
	//
	// The fix uses incremental dirty-node tracking: each node is individually marked
	// clean as it is successfully processed or released. Failed nodes simply remain
	// dirty and are retried on the next pass.
	//
	// This test creates three deleted nodes, injects cleanup errors for two of them,
	// and verifies that:
	//   - The healthy node is cleaned up immediately
	//   - The failing nodes are retained and retried
	//   - As errors are cleared, each node is eventually cleaned up
	It("should not get stuck when node cleanup fails (issue #8643)", func() {
		// Start the controller.
		c.Start(stopChan)

		fakeClient := cli.IPAM().(*fakeIPAMClient)
		fc := cli.(*FakeCalicoClient)

		// Inject errors for node-b and node-c to simulate "block not empty" failures.
		// node-a will succeed immediately.
		fc.SetReleaseHostAffinityError("node-b", fmt.Errorf("block is not empty"))
		fc.SetReleaseHostAffinityError("node-c", fmt.Errorf("block is not empty"))

		// Create blocks with tunnel address allocations for three nodes that don't
		// exist in Kubernetes (simulating node deletion during scale-down).
		type testNode struct {
			name   string
			cidr   string
			handle string
		}
		nodes := []testNode{
			{"node-a", "10.0.0.0/30", "vxlan-tunnel-addr-node-a"},
			{"node-b", "10.0.1.0/30", "vxlan-tunnel-addr-node-b"},
			{"node-c", "10.0.2.0/30", "vxlan-tunnel-addr-node-c"},
		}
		for _, n := range nodes {
			cidr := net.MustParseCIDR(n.cidr)
			aff := fmt.Sprintf("host:%s", n.name)
			handle := n.handle
			idx := 0
			b := model.AllocationBlock{
				CIDR:        cidr,
				Affinity:    &aff,
				Allocations: []*int{&idx, nil, nil, nil},
				Unallocated: []int{1, 2, 3},
				Attributes: []model.AllocationAttribute{
					{
						HandleID: &handle,
						ActiveOwnerAttrs: map[string]string{
							ipam.AttributeNode: n.name,
							ipam.AttributeType: ipam.AttributeTypeVXLAN,
						},
					},
				},
			}
			kvp := model.KVPair{Key: model.BlockKey{CIDR: cidr}, Value: &b}
			c.onUpdate(bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew})
		}

		// Wait for all blocks to be cached.
		for _, n := range nodes {
			cidr := n.cidr
			Eventually(func() bool {
				done := c.pause()
				defer done()
				_, ok := c.allBlocks[cidr]
				return ok
			}, 1*time.Second, 100*time.Millisecond).Should(BeTrue(), "Block %s should be cached", cidr)
		}

		// Trigger a full sync.
		c.fullScanNextSync("forced by test")
		c.onStatusUpdate(bapi.InSync)

		// node-a should be cleaned up (no error injected).
		Eventually(func() bool {
			return fakeClient.affinityReleased("node-a")
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue(), "node-a affinity should be released")

		// node-b and node-c should NOT be released — their cleanup is failing.
		Consistently(func() bool {
			return fakeClient.affinityReleased("node-b") || fakeClient.affinityReleased("node-c")
		}, 2*time.Second, 100*time.Millisecond).Should(BeFalse(), "node-b and node-c should not be released while errors persist")

		// Verify that the dirty node count is bounded — it should only contain the two failing
		// nodes, not grow unbounded across syncs.
		done := c.pause()
		Expect(len(c.allocationState.dirtyNodes)).To(BeNumerically("<=", 2),
			"dirty node count should not grow unbounded")
		done()

		// Clear the error for node-b. The retry controller will eventually schedule
		// another sync and node-b should be cleaned up.
		fc.SetReleaseHostAffinityError("node-b", nil)

		Eventually(func() bool {
			return fakeClient.affinityReleased("node-b")
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue(), "node-b affinity should be released after error is cleared")

		// node-c should still be failing.
		Expect(fakeClient.affinityReleased("node-c")).To(BeFalse(), "node-c should still be stuck")

		// Clear the error for node-c.
		fc.SetReleaseHostAffinityError("node-c", nil)

		Eventually(func() bool {
			return fakeClient.affinityReleased("node-c")
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue(), "node-c affinity should be released after error is cleared")
	})

	// Regression test: verifies the controller makes progress even when ALL nodes fail
	// cleanup simultaneously (zero progress in a pass). The dirty node set should stay
	// bounded across syncs, and nodes should recover once errors clear.
	It("should handle all nodes failing cleanup without growing dirty set", func() {
		c.Start(stopChan)

		fakeClient := cli.IPAM().(*fakeIPAMClient)
		fc := cli.(*FakeCalicoClient)

		// Inject errors for ALL nodes.
		fc.SetReleaseHostAffinityError("node-x", fmt.Errorf("block is not empty"))
		fc.SetReleaseHostAffinityError("node-y", fmt.Errorf("block is not empty"))

		type testNode struct {
			name   string
			cidr   string
			handle string
		}
		nodes := []testNode{
			{"node-x", "10.0.10.0/30", "vxlan-tunnel-addr-node-x"},
			{"node-y", "10.0.11.0/30", "vxlan-tunnel-addr-node-y"},
		}
		for _, n := range nodes {
			cidr := net.MustParseCIDR(n.cidr)
			aff := fmt.Sprintf("host:%s", n.name)
			handle := n.handle
			idx := 0
			b := model.AllocationBlock{
				CIDR:        cidr,
				Affinity:    &aff,
				Allocations: []*int{&idx, nil, nil, nil},
				Unallocated: []int{1, 2, 3},
				Attributes: []model.AllocationAttribute{
					{
						HandleID: &handle,
						ActiveOwnerAttrs: map[string]string{
							ipam.AttributeNode: n.name,
							ipam.AttributeType: ipam.AttributeTypeVXLAN,
						},
					},
				},
			}
			kvp := model.KVPair{Key: model.BlockKey{CIDR: cidr}, Value: &b}
			c.onUpdate(bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew})
		}

		// Wait for blocks to be cached.
		for _, n := range nodes {
			cidr := n.cidr
			Eventually(func() bool {
				done := c.pause()
				defer done()
				_, ok := c.allBlocks[cidr]
				return ok
			}, 1*time.Second, 100*time.Millisecond).Should(BeTrue(), "Block %s should be cached", cidr)
		}

		// Trigger a full sync.
		c.fullScanNextSync("forced by test")
		c.onStatusUpdate(bapi.InSync)

		// Neither node should be released since all are failing.
		Consistently(func() bool {
			return fakeClient.affinityReleased("node-x") || fakeClient.affinityReleased("node-y")
		}, 2*time.Second, 100*time.Millisecond).Should(BeFalse(), "no nodes should be released while all errors persist")

		// Dirty node count should stay bounded at the number of failing nodes (2),
		// not grow across repeated sync attempts.
		done := c.pause()
		Expect(len(c.allocationState.dirtyNodes)).To(BeNumerically("<=", 2),
			"dirty node count should not grow unbounded when all nodes fail")
		done()

		// Clear errors — both nodes should recover.
		fc.SetReleaseHostAffinityError("node-x", nil)
		fc.SetReleaseHostAffinityError("node-y", nil)

		Eventually(func() bool {
			return fakeClient.affinityReleased("node-x")
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue(), "node-x should be released after error is cleared")

		Eventually(func() bool {
			return fakeClient.affinityReleased("node-y")
		}, assertionTimeout, 100*time.Millisecond).Should(BeTrue(), "node-y should be released after error is cleared")
	})
})

// createBlock creates a block based on the given pods and CIDR, and sends it as an update to the controller.
func createBlock(pods []v1.Pod, host, cidrStr string) bapi.Update {
	var affinity *string
	if host != "" {
		aff := fmt.Sprintf("host:%s", host)
		affinity = &aff
	}
	cidr := net.MustParseCIDR(cidrStr)

	// Create a bootstrap block for access to IPToOrdinal.
	block := model.AllocationBlock{CIDR: cidr}

	assignments := map[int]int{}
	attrs := []model.AllocationAttribute{}
	for i, pod := range pods {
		attrs = append(attrs, model.AllocationAttribute{
			HandleID: &pod.Name,
			ActiveOwnerAttrs: map[string]string{
				ipam.AttributeNode:      host,
				ipam.AttributePod:       pod.Name,
				ipam.AttributeNamespace: pod.Namespace,
			},
		})
		ord, err := block.IPToOrdinal(net.MustParseIP(pod.Status.PodIP))
		Expect(err).NotTo(HaveOccurred())
		assignments[ord] = i
	}

	alloc, unalloc := makeAllocationsArrays(int(cidr.Network().NumAddrs().Int64()), assignments)
	block = model.AllocationBlock{
		CIDR:        cidr,
		Affinity:    affinity,
		Allocations: alloc,
		Unallocated: unalloc,
		Attributes:  attrs,
	}
	kvp := model.KVPair{Key: model.BlockKey{CIDR: cidr}, Value: &block}
	return bapi.Update{KVPair: kvp, UpdateType: bapi.UpdateTypeKVNew}
}

// makeAllocationsArray creates an array of pointers to integers, with the given assignments.
// assigned is a map of ordinal to attribute index.
func makeAllocationsArrays(n int, assinged map[int]int) ([]*int, []int) {
	allocs := make([]*int, n)
	for i := range allocs {
		allocs[i] = nil
	}
	for k, v := range assinged {
		allocs[k] = &v
	}

	unalloc := []int{}
	for i := range allocs {
		if allocs[i] == nil {
			unalloc = append(unalloc, i)
		}
	}
	return allocs, unalloc
}
