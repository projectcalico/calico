// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

// Memory leak regression tests for the IPAM controller.
// File location: kube-controllers/pkg/controllers/node/ipam_leak_test.go
//
// These tests cover leak patterns confirmed in production issues that were not
// otherwise unit-tested:
//
//  1. confirmedLeaks map cleanup (issue #5218, #8155)
//     Entries added to confirmedLeaks must be removed after successful GC.
//     If not, the map grows proportionally to pod churn rate over the
//     controller's lifetime.
//
//  2. Pod informer transformer reduces heap growth (issue #5218 / PR #10402)
//     The pod informer must store slim pods (via SetTransform), not full pods.
//     This tests both the transformer's correctness and the heap impact.
//
//  3. IP pool metric vectors are unregistered on pool deletion
//     Per-pool Prometheus gauges must be removed when a pool is deleted to
//     prevent stale metric descriptor accumulation.
//
//  4. confirmedLeaks and handleTracker orphaning on block deletion
//     When a block is deleted (e.g., node decommissioned), onBlockDeleted must
//     clean up confirmedLeaks and handleTracker entries for allocations in that
//     block.  If it does not, those entries can accumulate permanently:
//       - confirmedLeaks: if real IPAM returns "not allocated" (not in releasedOpts)
//         for IPs from a deleted block, the GC fallback never fires and the entries
//         live for the life of the process.
//       - handleTracker.allocationsByHandle: no code path calls removeAllocation
//         after a block is deleted, so stale handle entries accumulate for every
//         allocation that was GC'd from a subsequently-deleted block.

package node

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/converter"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// makePodAllocBlock creates a block update with a single pod IP allocation for a
// node that doesn't exist in Kubernetes — simulating a leaked IP.
func makePodAllocBlock(cidr, node, podHandle string) bapi.Update {
	parsed := cnet.MustParseCIDR(cidr)
	aff := fmt.Sprintf("host:%s", node)
	idx := 0
	b := model.AllocationBlock{
		CIDR:        parsed,
		Affinity:    &aff,
		Allocations: []*int{&idx, nil, nil, nil},
		Unallocated: []int{1, 2, 3},
		Attributes: []model.AllocationAttribute{
			{
				AttrPrimary: &podHandle,
				AttrSecondary: map[string]string{
					ipam.AttributeNode:      node,
					ipam.AttributePod:       "dead-pod",
					ipam.AttributeNamespace: "default",
				},
			},
		},
	}
	return bapi.Update{
		KVPair:     model.KVPair{Key: model.BlockKey{CIDR: parsed}, Value: &b},
		UpdateType: bapi.UpdateTypeKVNew,
	}
}

var _ = Describe("Memory leak regression tests", func() {

	// -------------------------------------------------------------------------
	// 1. confirmedLeaks map cleanup
	// -------------------------------------------------------------------------

	Describe("confirmedLeaks map cleanup (regression: issue #5218)", func() {
		var c *IPAMController
		var stopChan chan struct{}

		BeforeEach(func() {
			cs := fake.NewSimpleClientset()
			cli := NewFakeCalicoClient()

			factory := informers.NewSharedInformerFactory(cs, 0)
			podInformer := factory.Core().V1().Pods().Informer()
			nodeInformer := factory.Core().V1().Nodes().Informer()

			cfg := config.NodeControllerConfig{
				LeakGracePeriod: &metav1.Duration{Duration: gracePeriod},
			}
			stopChan = make(chan struct{})
			factory.Start(stopChan)
			cache.WaitForCacheSync(stopChan, podInformer.HasSynced, nodeInformer.HasSynced)

			c = NewIPAMController(cfg, cli, cs, podInformer.GetIndexer(), nodeInformer.GetIndexer())
			c.consolidationWindow = 1 * time.Millisecond
		})

		AfterEach(func() {
			assertConsistentState(c)
			close(stopChan)
		})

		It("removes entries from confirmedLeaks after successful GC", func() {
			// This is the core regression test for issue #5218.
			//
			// An IP is allocated to a pod that no longer exists. After the grace
			// period the allocation is promoted to confirmedLeaks. After GC
			// successfully releases the handle, the entry MUST be removed.
			//
			// If it is not removed, confirmedLeaks grows forever: on a cluster
			// running short-lived jobs (Airflow, CI runners, batch workloads)
			// this map accumulates millions of entries over weeks of uptime.
			c.Start(stopChan)

			podHandle := "k8s-pod.dead-pod.default.10.0.5.0"
			update := makePodAllocBlock("10.0.5.0/30", "dead-node", podHandle)
			c.onUpdate(update)

			// Wait for the block to land in the cache.
			Eventually(func() bool {
				done := c.pause()
				defer done()
				_, ok := c.allBlocks["10.0.5.0/30"]
				return ok
			}, 1*time.Second, 50*time.Millisecond).Should(BeTrue())

			// Drive a full sync.
			c.fullScanNextSync("test: confirmedLeaks cleanup")
			c.onStatusUpdate(bapi.InSync)

			fakeIPAM := c.client.IPAM().(*fakeIPAMClient)

			// After the grace period the IP handle should be released.
			Eventually(func() bool {
				return fakeIPAM.handlesReleased[podHandle]
			}, assertionTimeout, 50*time.Millisecond).Should(BeTrue(),
				"IP handle should be released via GC after grace period")

			// THE LEAK CHECK: after release, the entry must be gone from confirmedLeaks.
			Eventually(func() int {
				done := c.pause()
				defer done()
				return len(c.confirmedLeaks)
			}, assertionTimeout, 50*time.Millisecond).Should(BeZero(),
				"confirmedLeaks must be empty after successful GC — "+
					"if entries remain, this map grows for the life of the process "+
					"proportionally to pod churn rate (issue #5218)")
		})

		It("confirmedLeaks does not re-grow after GC on repeated syncs", func() {
			// Guard against the entry being re-added after GC on subsequent syncs.
			// This would indicate the allocation is being re-detected as leaked
			// even after being successfully cleaned up.
			c.Start(stopChan)

			podHandle := "k8s-pod.restarted.default.10.0.6.0"
			update := makePodAllocBlock("10.0.6.0/30", "dead-node-2", podHandle)
			c.onUpdate(update)

			Eventually(func() bool {
				done := c.pause()
				defer done()
				_, ok := c.allBlocks["10.0.6.0/30"]
				return ok
			}, 1*time.Second, 50*time.Millisecond).Should(BeTrue())

			c.fullScanNextSync("test: repeated sync")
			c.onStatusUpdate(bapi.InSync)

			fakeIPAM := c.client.IPAM().(*fakeIPAMClient)
			Eventually(func() bool {
				return fakeIPAM.handlesReleased[podHandle]
			}, assertionTimeout, 50*time.Millisecond).Should(BeTrue())

			// Verify the map stays empty — not just momentarily empty.
			Consistently(func() int {
				done := c.pause()
				defer done()
				return len(c.confirmedLeaks)
			}, gracePeriod, 50*time.Millisecond).Should(BeZero(),
				"confirmedLeaks must stay empty after GC — "+
					"it must not regrow due to repeated syncs or watch reconnects")
		})
	})

	// -------------------------------------------------------------------------
	// 2. Pod transformer heap reduction
	// -------------------------------------------------------------------------

	Describe("pod informer transformer reduces heap growth (regression: issue #5218 / PR #10402)", func() {
		const podCount = 500

		fatPodForMemTest := func(i int) *v1.Pod {
			envVars := make([]v1.EnvVar, 20)
			for j := range envVars {
				envVars[j] = v1.EnvVar{
					Name:  fmt.Sprintf("ENV_%d_%d", i, j),
					Value: "a-reasonably-long-environment-variable-value-consuming-heap",
				}
			}
			return &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:            fmt.Sprintf("pod-%d", i),
					Namespace:       "default",
					UID:             types.UID(fmt.Sprintf("uid-%d", i)),
					ResourceVersion: fmt.Sprintf("%d", i*100),
					Annotations: map[string]string{
						"kubectl.kubernetes.io/last-applied-configuration": fmt.Sprintf(
							`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-%d"},"spec":{"containers":[{"name":"main","image":"app:latest","env":%d}]}}`,
							i, len(envVars)),
					},
				},
				Spec: v1.PodSpec{
					NodeName:           fmt.Sprintf("node-%d", i%10),
					ServiceAccountName: "default",
					Containers: []v1.Container{
						{Name: "main", Image: "app:latest", Env: envVars},
					},
				},
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					PodIP: fmt.Sprintf("10.0.%d.%d", i/256, i%256),
				},
			}
		}

		It("transformer strips the bulk data that causes the memory leak", func() {
			// Verifies the transformer removes the high-cardinality fields that
			// caused unbounded memory growth in issue #5218. We use a deterministic
			// content-size approach rather than runtime.MemStats (which is sensitive
			// to GC timing and page alignment).
			//
			// For each fat pod we compute the total character count of the fields
			// that the transformer should strip (env var names+values, annotation
			// values, container names+images), then verify that the slim pod retains
			// none of that content.
			transformer := converter.PodTransformer(true)

			totalFatEnvChars := 0
			totalFatAnnotationChars := 0
			totalSlimEnvChars := 0
			totalSlimAnnotationChars := 0
			totalSlimContainers := 0

			for i := 0; i < podCount; i++ {
				fat := fatPodForMemTest(i)

				// Measure the "fat" fields that should be stripped.
				for _, c := range fat.Spec.Containers {
					for _, e := range c.Env {
						totalFatEnvChars += len(e.Name) + len(e.Value)
					}
				}
				for k, v := range fat.Annotations {
					// Only count annotations the transformer should drop.
					if k != "kubectl.kubernetes.io/last-applied-configuration" {
						continue
					}
					totalFatAnnotationChars += len(v)
				}

				slim, err := transformer(fat)
				Expect(err).NotTo(HaveOccurred())
				slimPod := slim.(*v1.Pod)

				// Measure the retained content.
				for _, c := range slimPod.Spec.Containers {
					totalSlimContainers++
					for _, e := range c.Env {
						totalSlimEnvChars += len(e.Name) + len(e.Value)
					}
				}
				for k, v := range slimPod.Annotations {
					if k == "kubectl.kubernetes.io/last-applied-configuration" {
						totalSlimAnnotationChars += len(v)
					}
				}
			}

			Expect(totalFatEnvChars).To(BeNumerically(">", 10000),
				"fat pods should carry substantial env var content (test sanity check)")
			Expect(totalFatAnnotationChars).To(BeNumerically(">", 1000),
				"fat pods should carry substantial annotation content (test sanity check)")

			// THE LEAK GUARDS: these must all be zero after transformation.
			Expect(totalSlimContainers).To(BeZero(),
				"transformer must strip all containers — "+
					"env vars inside containers were the primary source of memory growth in issue #5218")
			Expect(totalSlimEnvChars).To(BeZero(),
				"transformer must strip all env vars")
			Expect(totalSlimAnnotationChars).To(BeZero(),
				"transformer must strip the last-applied-configuration annotation — "+
					"this annotation duplicates the entire pod manifest as a JSON string")
		})

		It("informer with SetTransform stores slim pods, not full pods", func() {
			// Verifies that when SetTransform is registered on the pod informer
			// (the production path added in PR #10402), pods stored in the
			// indexer are the slim version with containers stripped.
			//
			// This is a regression guard: if someone removes the SetTransform
			// call from InitControllers, this test will catch it immediately.
			cs := fake.NewSimpleClientset()

			factory := informers.NewSharedInformerFactory(cs, 0)
			podInformer := factory.Core().V1().Pods().Informer()
			podInformer.SetTransform(converter.PodTransformer(true))

			stopChan := make(chan struct{})
			defer close(stopChan)
			factory.Start(stopChan)
			cache.WaitForCacheSync(stopChan, podInformer.HasSynced)

			// Create a fat pod through the fake clientset.
			pod := &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "live-pod",
					Namespace: "default",
					UID:       types.UID("live-pod-uid"),
					Annotations: map[string]string{
						"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"v1","kind":"Pod"}`,
					},
				},
				Spec: v1.PodSpec{
					NodeName: "node-1",
					Containers: []v1.Container{
						{
							Name:  "main",
							Image: "app:v1",
							Env:   []v1.EnvVar{{Name: "SECRET_KEY", Value: "do-not-cache-this"}},
						},
					},
				},
				Status: v1.PodStatus{Phase: v1.PodRunning, PodIP: "10.0.7.1"},
			}
			_, err := cs.CoreV1().Pods("default").Create(context.Background(), pod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Wait for the informer to pick up and transform the pod.
			Eventually(func() bool {
				_, exists, err := podInformer.GetIndexer().GetByKey("default/live-pod")
				return err == nil && exists
			}, 2*time.Second, 50*time.Millisecond).Should(BeTrue(),
				"pod should appear in informer cache")

			obj, exists, err := podInformer.GetIndexer().GetByKey("default/live-pod")
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeTrue())
			cached := obj.(*v1.Pod)

			// THE LEAK GUARD: the cached pod must be the slim version.
			Expect(cached.Spec.Containers).To(BeEmpty(),
				"pod stored in informer cache must have containers stripped — "+
					"full pods in the cache were the root cause of issue #5218. "+
					"If this fails, SetTransform is no longer registered on the pod informer.")

			// Essential fields must still be present for allocationIsValid to work.
			Expect(cached.Name).To(Equal("live-pod"))
			Expect(cached.Namespace).To(Equal("default"))
			Expect(cached.Spec.NodeName).To(Equal("node-1"))
			Expect(cached.Status.PodIP).To(Equal("10.0.7.1"))
			Expect(cached.Annotations).NotTo(HaveKey("kubectl.kubernetes.io/last-applied-configuration"),
				"last-applied-configuration annotation must be stripped")
		})
	})

	// -------------------------------------------------------------------------
	// 3. IP pool metric vectors unregistered on pool deletion
	// -------------------------------------------------------------------------

	Describe("IP pool metrics cleanup (regression: metric accumulation on pool churn)", func() {
		var c *IPAMController
		var stopChan chan struct{}

		BeforeEach(func() {
			cs := fake.NewSimpleClientset()
			cli := NewFakeCalicoClient()

			factory := informers.NewSharedInformerFactory(cs, 0)
			podInformer := factory.Core().V1().Pods().Informer()
			nodeInformer := factory.Core().V1().Nodes().Informer()

			cfg := config.NodeControllerConfig{}
			stopChan = make(chan struct{})
			factory.Start(stopChan)
			cache.WaitForCacheSync(stopChan, podInformer.HasSynced, nodeInformer.HasSynced)

			c = NewIPAMController(cfg, cli, cs, podInformer.GetIndexer(), nodeInformer.GetIndexer())
		})

		AfterEach(func() {
			close(stopChan)
		})


		It("unregisters metric vectors when a pool is deleted", func() {
			pool := &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pool"},
				Spec:       apiv3.IPPoolSpec{CIDR: "192.168.100.0/24"},
			}
			// onPoolUpdated and onPoolDeleted update the package-level gauge maps
			// synchronously, so no pause needed — we call them directly from the test.
			c.onPoolUpdated(pool)

			_, registered := inUseAllocationGauges[pool.Name]
			Expect(registered).To(BeTrue(),
				"metric vectors should be registered when a pool is created")

			c.onPoolDeleted(pool.Name)

			_, stillRegistered := inUseAllocationGauges[pool.Name]
			Expect(stillRegistered).To(BeFalse(),
				"metric vectors must be unregistered when a pool is deleted — "+
					"stale descriptors in the Prometheus registry are a slow memory leak "+
					"proportional to total pool create/delete cycles")
		})

		It("does not accumulate metrics across repeated pool create/delete cycles", func() {
			const cycles = 5
			poolName := "cycling-pool"

			for i := 0; i < cycles; i++ {
				pool := &apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: poolName},
					Spec:       apiv3.IPPoolSpec{CIDR: "192.168.200.0/24"},
				}
				c.onPoolUpdated(pool)
				c.onPoolDeleted(poolName)
			}

			_, stillRegistered := inUseAllocationGauges[poolName]
			Expect(stillRegistered).To(BeFalse(),
				"metric vectors must be cleaned up after pool deletion regardless "+
					"of how many times the pool was recreated")
		})
	})

	// -------------------------------------------------------------------------
	// 4. confirmedLeaks and handleTracker orphaning on block deletion
	// -------------------------------------------------------------------------
	//
	// Scenario: a node is decommissioned while leaked IP allocations are
	// pending GC.  IPAM deletes the block (onBlockDeleted), but that function
	// does not touch confirmedLeaks or handleTracker.allocationsByHandle.
	//
	// In production, if the real IPAM subsequently returns "not allocated" for
	// those IPs (i.e. they are absent from ReleaseIPs' releasedOpts return),
	// the GC fallback never fires and the entries remain for the life of the
	// process.  The fake IPAM always succeeds, which masks this production risk
	// in most unit tests.

	Describe("block deletion orphaning of confirmedLeaks and handleTracker", func() {
		// newControllerWithState returns an IPAMController with its internal maps
		// pre-populated to simulate an allocation that has already been identified
		// as a confirmed leak.  The controller is NOT started, so onBlockDeleted
		// can be called directly and synchronously without goroutine interference.
		newControllerWithState := func(blockCIDR, node, handle, ip string) (*IPAMController, *allocation) {
			cs := fake.NewSimpleClientset()
			cli := NewFakeCalicoClient()
			factory := informers.NewSharedInformerFactory(cs, 0)
			podInformer := factory.Core().V1().Pods().Informer()
			nodeInformer := factory.Core().V1().Nodes().Informer()
			cfg := config.NodeControllerConfig{
				LeakGracePeriod: &metav1.Duration{Duration: gracePeriod},
			}
			stopChan := make(chan struct{})
			factory.Start(stopChan)
			cache.WaitForCacheSync(stopChan, podInformer.HasSynced, nodeInformer.HasSynced)
			close(stopChan)

			c := NewIPAMController(cfg, cli, cs, podInformer.GetIndexer(), nodeInformer.GetIndexer())

			parsed := cnet.MustParseCIDR(blockCIDR)
			leakedAt := time.Now().Add(-1 * time.Hour)
			alloc := &allocation{
				ip:     ip,
				handle: handle,
				attrs: map[string]string{
					ipam.AttributeNode:      node,
					ipam.AttributePod:       "leaked-pod",
					ipam.AttributeNamespace: "default",
				},
				block:         blockCIDR,
				leakedAt:      &leakedAt,
				confirmedLeak: true,
			}

			// Inject the state that the controller would normally have built up
			// incrementally via onBlockUpdated + checkAllocations.
			c.allBlocks[blockCIDR] = model.KVPair{Key: model.BlockKey{CIDR: parsed}}
			c.allocationsByBlock[blockCIDR] = map[string]*allocation{alloc.id(): alloc}
			c.nodesByBlock[blockCIDR] = node
			c.blocksByNode[node] = map[string]bool{blockCIDR: true}
			c.allocationState.allocationsByNode[node] = map[string]*allocation{alloc.id(): alloc}
			c.handleTracker.setAllocation(alloc)
			c.confirmedLeaks[alloc.id()] = alloc

			return c, alloc
		}

		It("confirmedLeaks entries survive block deletion (onBlockDeleted does not clean them)", func() {
			// This test documents a real gap: onBlockDeleted cleans allBlocks,
			// allocationsByBlock, nodesByBlock, blocksByNode — but NOT confirmedLeaks.
			//
			// Production impact: when a decommissioned node's block is deleted by IPAM
			// BEFORE the GC cycle runs, the confirmedLeaks entries for that block's
			// allocations can never be cleaned if the real IPAM returns "not allocated"
			// (i.e., the IPs are absent from ReleaseIPs' releasedOpts).
			//
			// Expected: this test FAILS until onBlockDeleted is fixed to also delete
			// confirmedLeaks entries for allocations in the deleted block.
			c, alloc := newControllerWithState(
				"10.199.0.0/30", "decommissioned-node", "k8s-pod.leaked.default.10.199.0.1", "10.199.0.1",
			)

			Expect(c.confirmedLeaks).To(HaveLen(1), "pre-condition: confirmedLeaks has one entry")

			parsed := cnet.MustParseCIDR("10.199.0.0/30")
			c.onBlockDeleted(model.BlockKey{CIDR: parsed})

			// THE LEAK CHECK: onBlockDeleted must clean up confirmedLeaks entries
			// for allocations in the deleted block.
			Expect(c.confirmedLeaks).To(BeEmpty(),
				fmt.Sprintf(
					"onBlockDeleted must remove confirmedLeaks[%q] — "+
						"without this, entries for allocations in deleted blocks accumulate "+
						"permanently when production IPAM returns 'not allocated' for freed IPs "+
						"(the fake IPAM masks this by always returning all IPs in releasedOpts)",
					alloc.id(),
				))
		})

		It("handleTracker entries survive block deletion (onBlockDeleted does not call removeAllocation)", func() {
			// This test documents a second gap in onBlockDeleted: it does not call
			// handleTracker.removeAllocation for allocations in the deleted block.
			//
			// Normal (non-deletion) path: when a block is UPDATED and an IP is
			// released, onBlockUpdated calls handleTracker.removeAllocation — clean.
			// But when a block is DELETED, the update never arrives, so the handle
			// tracker retains stale entries permanently.
			//
			// Production impact: every IP GC'd from a deleted block leaves behind a
			// dead entry in handleTracker.allocationsByHandle.  On high-churn clusters
			// (spot instances, batch jobs) with frequent node turnover this map grows
			// without bound.
			//
			// Expected: this test FAILS until onBlockDeleted is fixed to also call
			// handleTracker.removeAllocation for each allocation in the deleted block.
			c, alloc := newControllerWithState(
				"10.199.1.0/30", "decommissioned-node-2", "k8s-pod.leaked2.default.10.199.1.1", "10.199.1.1",
			)

			Expect(c.handleTracker.allocationsByHandle).To(HaveKey(alloc.handle),
				"pre-condition: handleTracker has the allocation's handle")

			parsed := cnet.MustParseCIDR("10.199.1.0/30")
			c.onBlockDeleted(model.BlockKey{CIDR: parsed})

			// THE LEAK CHECK: onBlockDeleted must clean up handleTracker entries.
			Expect(c.handleTracker.allocationsByHandle).NotTo(HaveKey(alloc.handle),
				fmt.Sprintf(
					"onBlockDeleted must call handleTracker.removeAllocation for handle %q — "+
						"without this, stale handle entries accumulate permanently. "+
						"The normal cleanup path (onBlockUpdated) is never triggered for deleted blocks.",
					alloc.handle,
				))
		})

		It("handleTracker retains stale entries after GC releases allocations from a deleted block", func() {
			// This test exercises the full controller pipeline to show that
			// handleTracker.allocationsByHandle accumulates stale entries permanently
			// after a node decommission:
			//
			//   1. Block is observed → allocation tracked in handleTracker
			//   2. GC runs → confirmedLeaks cleaned, but handleTracker NOT cleaned
			//      (garbageCollectKnownLeaks calls allocationState.release but not
			//       handleTracker.removeAllocation)
			//   3. Block is deleted → onBlockDeleted does not clean handleTracker
			//   4. Result: handleTracker.allocationsByHandle retains the stale entry
			//      permanently — no code path will ever remove it.
			//
			// In production the watch delivers a block-update event when an IP is
			// released by GC, and that onBlockUpdated call would clean handleTracker.
			// But when the block itself is DELETED (node decommission), that update
			// never arrives, so the entry lives forever.
			cs := fake.NewSimpleClientset()
			cli := NewFakeCalicoClient()
			factory := informers.NewSharedInformerFactory(cs, 0)
			podInformer := factory.Core().V1().Pods().Informer()
			nodeInformer := factory.Core().V1().Nodes().Informer()
			cfg := config.NodeControllerConfig{
				LeakGracePeriod: &metav1.Duration{Duration: gracePeriod},
			}
			stopChan := make(chan struct{})
			factory.Start(stopChan)
			cache.WaitForCacheSync(stopChan, podInformer.HasSynced, nodeInformer.HasSynced)
			defer close(stopChan)

			c := NewIPAMController(cfg, cli, cs, podInformer.GetIndexer(), nodeInformer.GetIndexer())
			c.consolidationWindow = 1 * time.Millisecond
			c.Start(stopChan)

			podHandle := "k8s-pod.gc-then-delete.default.10.199.2.0"
			update := makePodAllocBlock("10.199.2.0/30", "transient-node", podHandle)
			c.onUpdate(update)

			// Wait for the block to be cached.
			Eventually(func() bool {
				done := c.pause()
				defer done()
				_, ok := c.allBlocks["10.199.2.0/30"]
				return ok
			}, time.Second, 50*time.Millisecond).Should(BeTrue())

			c.fullScanNextSync("test: handle tracker gc then delete")
			c.onStatusUpdate(bapi.InSync)

			// Wait for GC to successfully release the IP handle.
			fakeIPAM := c.client.IPAM().(*fakeIPAMClient)
			Eventually(func() bool {
				return fakeIPAM.handlesReleased[podHandle]
			}, assertionTimeout, 50*time.Millisecond).Should(BeTrue(),
				"GC must release the leaked IP handle")

			// confirmedLeaks should be clean after GC.
			Eventually(func() int {
				done := c.pause()
				defer done()
				return len(c.confirmedLeaks)
			}, assertionTimeout, 50*time.Millisecond).Should(BeZero(),
				"confirmedLeaks must be empty after GC")

			// Now delete the block (simulating IPAM block cleanup when node is
			// decommissioned after GC has already run).
			parsedBlock := cnet.MustParseCIDR("10.199.2.0/30")
			c.onUpdate(bapi.Update{
				KVPair:     model.KVPair{Key: model.BlockKey{CIDR: parsedBlock}},
				UpdateType: bapi.UpdateTypeKVDeleted,
			})

			// Wait for block deletion to propagate.
			Eventually(func() bool {
				done := c.pause()
				defer done()
				_, ok := c.allBlocks["10.199.2.0/30"]
				return !ok
			}, time.Second, 50*time.Millisecond).Should(BeTrue(),
				"block must be removed from allBlocks after deletion event")

			// THE HANDLETRACKER LEAK: even though confirmedLeaks is empty and the
			// block is gone, handleTracker.allocationsByHandle still holds the handle.
			//
			// Root cause: neither garbageCollectKnownLeaks nor onBlockDeleted calls
			// handleTracker.removeAllocation.  In production the watch callback
			// (onBlockUpdated) would normally clean this on a non-deletion update,
			// but a block *deletion* event never produces a subsequent update.
			//
			// Expected: this test FAILS until garbageCollectKnownLeaks or
			// onBlockDeleted is fixed to call handleTracker.removeAllocation.
			Eventually(func() bool {
				done := c.pause()
				defer done()
				return len(c.handleTracker.allocationsByHandle) == 0
			}, time.Second, 50*time.Millisecond).Should(BeTrue(),
				"handleTracker.allocationsByHandle must be empty after GC releases all leaks "+
					"from a deleted block — stale entries accumulate permanently since no code "+
					"path calls handleTracker.removeAllocation for this scenario")
		})
	})
})
