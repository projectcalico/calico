// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// intPtr returns a pointer to the given int.
func intPtr(i int) *int { return &i }

// makeBlock builds a minimal AllocationBlock for tests, with one allocation
// per ordinal => handleID mapping in handles. Only the fields used by the GC
// path are populated.
func makeBlock(cidr string, handles map[int]string) model.KVPair {
	_, ipNet, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())
	size := 1
	for _, b := range []byte(ipNet.IP.To4()) {
		_ = b
	}
	// Compute size from prefix.
	ones, bits := ipNet.Mask.Size()
	size = 1 << (bits - ones)

	allocs := make([]*int, size)
	attrs := make([]model.AllocationAttribute, 0, len(handles))
	for ord, h := range handles {
		idx := len(attrs)
		hCopy := h
		attrs = append(attrs, model.AllocationAttribute{HandleID: &hCopy})
		allocs[ord] = intPtr(idx)
	}
	return model.KVPair{
		Key: model.BlockKey{CIDR: cnet.MustParseCIDR(cidr)},
		Value: &model.AllocationBlock{
			CIDR:        cnet.MustParseCIDR(cidr),
			Allocations: allocs,
			Attributes:  attrs,
		},
	}
}

var _ = Describe("Handle GC unit tests", func() {
	Describe("classifyHandle", func() {
		It("returns OK when handle and expected match", func() {
			h := &model.IPAMHandle{HandleID: "h1", Block: map[string]int{"10.0.0.0/26": 2}}
			Expect(classifyHandle(h, map[string]int{"10.0.0.0/26": 2})).To(Equal(classOK))
		})
		It("returns Orphan when handle exists but expected is empty", func() {
			h := &model.IPAMHandle{HandleID: "h1", Block: map[string]int{}}
			Expect(classifyHandle(h, nil)).To(Equal(classOrphan))
		})
		It("returns Missing when handle does not exist but expected is non-empty", func() {
			Expect(classifyHandle(nil, map[string]int{"10.0.0.0/26": 1})).To(Equal(classMissing))
		})
		It("returns OK when both nil/empty", func() {
			Expect(classifyHandle(nil, nil)).To(Equal(classOK))
		})
		It("returns Skewed when counts disagree", func() {
			h := &model.IPAMHandle{HandleID: "h1", Block: map[string]int{"10.0.0.0/26": 5}}
			Expect(classifyHandle(h, map[string]int{"10.0.0.0/26": 2})).To(Equal(classSkewed))
		})
		It("returns Skewed when block keys differ", func() {
			h := &model.IPAMHandle{HandleID: "h1", Block: map[string]int{"10.0.0.0/26": 1}}
			Expect(classifyHandle(h, map[string]int{"10.0.1.0/26": 1})).To(Equal(classSkewed))
		})
		It("returns Skewed (not Orphan) when handle has refs but reality is empty", func() {
			h := &model.IPAMHandle{HandleID: "h1", Block: map[string]int{"10.0.0.0/26": 1}}
			// A non-empty handle that no block actually references is
			// Skewed: we rewrite Block to empty (one cycle), then the
			// follow-up cycle classifies it as Orphan and deletes it.
			Expect(classifyHandle(h, nil)).To(Equal(classSkewed))
		})
		It("returns StuckDeleted when Deleted=true regardless of counts", func() {
			h := &model.IPAMHandle{HandleID: "h1", Block: map[string]int{"10.0.0.0/26": 1}, Deleted: true}
			Expect(classifyHandle(h, map[string]int{"10.0.0.0/26": 1})).To(Equal(classStuckDeleted))
		})
	})

	Describe("computeExpectedHandles", func() {
		var c *IPAMController
		BeforeEach(func() {
			c = &IPAMController{allBlocks: map[string]model.KVPair{}}
		})
		It("aggregates counts per block per handle", func() {
			c.allBlocks["10.0.0.0/26"] = makeBlock("10.0.0.0/26", map[int]string{
				0: "h1", 1: "h1", 2: "h2",
			})
			c.allBlocks["10.0.1.0/26"] = makeBlock("10.0.1.0/26", map[int]string{
				0: "h1",
			})
			expected := c.computeExpectedHandles()
			Expect(expected).To(Equal(map[string]map[string]int{
				"h1": {"10.0.0.0/26": 2, "10.0.1.0/26": 1},
				"h2": {"10.0.0.0/26": 1},
			}))
		})
		It("ignores allocations with no HandleID", func() {
			b := makeBlock("10.0.0.0/26", nil)
			ab := b.Value.(*model.AllocationBlock)
			ab.Allocations[0] = intPtr(0)
			ab.Attributes = append(ab.Attributes, model.AllocationAttribute{HandleID: nil})
			c.allBlocks["10.0.0.0/26"] = b
			Expect(c.computeExpectedHandles()).To(BeEmpty())
		})
		It("ignores out-of-bounds attribute indices defensively", func() {
			b := makeBlock("10.0.0.0/26", nil)
			ab := b.Value.(*model.AllocationBlock)
			// Bogus index that would otherwise panic.
			ab.Allocations[0] = intPtr(42)
			c.allBlocks["10.0.0.0/26"] = b
			Expect(c.computeExpectedHandles()).To(BeEmpty())
		})
	})

	Describe("handleSignature stability", func() {
		It("differs when actual block map changes", func() {
			h := &model.IPAMHandle{HandleID: "h1", Block: map[string]int{"10.0.0.0/26": 1}}
			kvp := &model.KVPair{Revision: "1", Value: h}
			s1 := handleSignature(classSkewed, kvp, map[string]int{"10.0.0.0/26": 2})
			h.Block["10.0.0.0/26"] = 5
			s2 := handleSignature(classSkewed, kvp, map[string]int{"10.0.0.0/26": 2})
			Expect(s1).NotTo(Equal(s2))
		})
		It("differs when expected changes", func() {
			h := &model.IPAMHandle{HandleID: "h1", Block: map[string]int{"10.0.0.0/26": 1}}
			kvp := &model.KVPair{Revision: "1", Value: h}
			s1 := handleSignature(classSkewed, kvp, map[string]int{"10.0.0.0/26": 2})
			s2 := handleSignature(classSkewed, kvp, map[string]int{"10.0.0.0/26": 3})
			Expect(s1).NotTo(Equal(s2))
		})
		It("differs when ResourceVersion changes", func() {
			h := &model.IPAMHandle{HandleID: "h1", Block: map[string]int{"10.0.0.0/26": 1}}
			s1 := handleSignature(classSkewed, &model.KVPair{Revision: "1", Value: h}, map[string]int{"10.0.0.0/26": 2})
			s2 := handleSignature(classSkewed, &model.KVPair{Revision: "2", Value: h}, map[string]int{"10.0.0.0/26": 2})
			Expect(s1).NotTo(Equal(s2))
		})
	})

	Describe("reconcileHandles end-to-end", func() {
		var (
			c    *IPAMController
			fcli *FakeCalicoClient
		)
		newController := func() (*IPAMController, *FakeCalicoClient) {
			fcli := NewFakeCalicoClient()
			cs := fake.NewClientset()
			factory := informers.NewSharedInformerFactory(cs, 0)
			pod := factory.Core().V1().Pods().Informer()
			node := factory.Core().V1().Nodes().Informer()
			cfg := config.NodeControllerConfig{
				LeakGracePeriod:     &metav1.Duration{Duration: gracePeriod},
				IPAMHandleGCEnabled: true,
			}
			defInf := kubevirt.NewDeferredInformersWithIndexers(
				cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{}),
				cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{}),
			)
			ctrl := NewIPAMController(cfg, fcli, cs, pod.GetIndexer(), node.GetIndexer(), defInf)
			return ctrl, fcli
		}

		runCycles := func(n int) {
			for range n {
				err := c.reconcileHandles(context.TODO())
				Expect(err).NotTo(HaveOccurred())
			}
		}

		// seedHandle plants a handle into both the fake backend (the source
		// of truth for repair operations) and the controller's allHandles
		// cache (the watcher-fed view that the reconciler diffs against).
		// In production these are kept in sync by the syncer; in unit tests
		// we drive both directly.
		seedHandle := func(id string, blocks map[string]int, deleted bool) {
			kvp := fcli.SeedHandle(id, blocks, deleted)
			c.handleHandleUpdate(*kvp)
		}

		// deleteFromBackendOnly removes a handle from the controller's
		// cache but leaves the backend untouched (used to simulate the
		// syncer observing a deletion).
		deleteFromCacheOnly := func(id string) {
			c.handleHandleUpdate(model.KVPair{Key: model.IPAMHandleKey{HandleID: id}})
		}
		_ = deleteFromCacheOnly

		BeforeEach(func() {
			c, fcli = newController()
		})

		It("deletes orphan handles after stability cycles", func() {
			// Handle exists in datastore but no block references it.
			seedHandle("h-orphan", map[string]int{}, false)
			// Repairs require requiredStableCycles consecutive observations.
			runCycles(requiredStableCycles - 1)
			Expect(fcli.GetHandle("h-orphan")).NotTo(BeNil())
			runCycles(1)
			Expect(fcli.GetHandle("h-orphan")).To(BeNil())
		})

		It("creates a missing handle when a block references one that doesn't exist", func() {
			c.allBlocks["10.0.0.0/26"] = makeBlock("10.0.0.0/26", map[int]string{0: "h-missing", 1: "h-missing"})
			runCycles(requiredStableCycles - 1)
			Expect(fcli.GetHandle("h-missing")).To(BeNil())
			runCycles(1)
			h := fcli.GetHandle("h-missing")
			Expect(h).NotTo(BeNil())
			Expect(h.Block).To(Equal(map[string]int{"10.0.0.0/26": 2}))
		})

		It("rewrites a skewed handle to match block reality", func() {
			c.allBlocks["10.0.0.0/26"] = makeBlock("10.0.0.0/26", map[int]string{0: "h-skewed"})
			seedHandle("h-skewed", map[string]int{"10.0.0.0/26": 99}, false)
			runCycles(requiredStableCycles)
			Expect(fcli.GetHandle("h-skewed").Block).To(Equal(map[string]int{"10.0.0.0/26": 1}))
		})

		It("revives a stuck soft-deleted handle that still has block references", func() {
			c.allBlocks["10.0.0.0/26"] = makeBlock("10.0.0.0/26", map[int]string{0: "h-stuck"})
			seedHandle("h-stuck", map[string]int{"10.0.0.0/26": 1}, true)
			runCycles(requiredStableCycles)
			h := fcli.GetHandle("h-stuck")
			Expect(h).NotTo(BeNil())
			Expect(h.Deleted).To(BeFalse())
			Expect(h.Block).To(Equal(map[string]int{"10.0.0.0/26": 1}))
		})

		It("hard-deletes a stuck soft-deleted handle whose blocks have been freed", func() {
			seedHandle("h-stuck-empty", map[string]int{}, true)
			runCycles(requiredStableCycles)
			Expect(fcli.GetHandle("h-stuck-empty")).To(BeNil())
		})

		It("does not repair before requiredStableCycles", func() {
			seedHandle("h-flap", map[string]int{}, false)
			runCycles(requiredStableCycles - 1)
			Expect(fcli.GetHandle("h-flap")).NotTo(BeNil())
		})

		It("resets stability when handle is touched between cycles", func() {
			seedHandle("h-touched", map[string]int{}, false)
			runCycles(1)
			// Mutate the handle (simulating an in-flight client write that
			// would bump the ResourceVersion). This must reset stability.
			seedHandle("h-touched", map[string]int{}, false)
			runCycles(requiredStableCycles - 1)
			Expect(fcli.GetHandle("h-touched")).NotTo(BeNil())
			runCycles(1)
			Expect(fcli.GetHandle("h-touched")).To(BeNil())
		})

		It("resets stability when expected (block-derived) state changes", func() {
			c.allBlocks["10.0.0.0/26"] = makeBlock("10.0.0.0/26", map[int]string{0: "h-flux"})
			seedHandle("h-flux", map[string]int{"10.0.0.0/26": 99}, false)
			runCycles(1)
			// Block changes — handle's expected count flips. Stability resets.
			c.allBlocks["10.0.0.0/26"] = makeBlock("10.0.0.0/26", map[int]string{0: "h-flux", 1: "h-flux"})
			runCycles(requiredStableCycles - 1)
			// Should still be 99 — repair shouldn't have fired yet.
			Expect(fcli.GetHandle("h-flux").Block["10.0.0.0/26"]).To(Equal(99))
			runCycles(1)
			Expect(fcli.GetHandle("h-flux").Block["10.0.0.0/26"]).To(Equal(2))
		})

		It("never deletes a non-empty handle as part of a Skewed repair (safety)", func() {
			// Set up: block has one allocation for h-safety, but handle has
			// vastly inflated count. Skewed → rewrite to 1, NOT delete.
			c.allBlocks["10.0.0.0/26"] = makeBlock("10.0.0.0/26", map[int]string{0: "h-safety"})
			seedHandle("h-safety", map[string]int{"10.0.0.0/26": 50, "10.0.1.0/26": 99}, false)
			runCycles(requiredStableCycles)
			h := fcli.GetHandle("h-safety")
			Expect(h).NotTo(BeNil(), "handle must not be deleted")
			Expect(h.Block).To(Equal(map[string]int{"10.0.0.0/26": 1}))
		})

		It("respects the IPAMHandleGCEnabled=false knob", func() {
			c.config.IPAMHandleGCEnabled = false
			seedHandle("h-disabled", map[string]int{}, false)
			runCycles(requiredStableCycles + 5)
			Expect(fcli.GetHandle("h-disabled")).NotTo(BeNil())
		})

		It("treats CAS conflict as a no-op and re-evaluates next cycle", func() {
			c.allBlocks["10.0.0.0/26"] = makeBlock("10.0.0.0/26", map[int]string{0: "h-conflict"})
			seedHandle("h-conflict", map[string]int{"10.0.0.0/26": 99}, false)
			runCycles(requiredStableCycles - 1)
			// Mid-flight, a real client touches the handle (RV bumps).
			seedHandle("h-conflict", map[string]int{"10.0.0.0/26": 99}, false)
			// On the next reconcile, the handle has the new RV. Because
			// stability resets when RV changes, no repair fires this cycle.
			runCycles(1)
			Expect(fcli.GetHandle("h-conflict").Block["10.0.0.0/26"]).To(Equal(99))
			// Subsequent cycles eventually do repair once stability is re-established.
			runCycles(requiredStableCycles)
			Expect(fcli.GetHandle("h-conflict").Block["10.0.0.0/26"]).To(Equal(1))
		})

		It("populates allHandles via the syncer dispatch path", func() {
			// Drive the same path the watcher syncer uses in production:
			// bapi.Update → onUpdate → syncerUpdates → handleUpdate →
			// handleHandleUpdate → c.allHandles.
			//
			// We bypass the channel so the test is synchronous; both
			// onUpdate and handleHandleUpdate are pure data-plane code.
			id := "h-via-syncer"
			rev := "42"
			c.handleUpdate(model.KVPair{
				Key:      model.IPAMHandleKey{HandleID: id},
				Value:    &model.IPAMHandle{HandleID: id, Block: map[string]int{"10.0.0.0/26": 3}},
				Revision: rev,
			})
			Expect(c.allHandles).To(HaveKey(id))
			Expect(c.allHandles[id].Revision).To(Equal(rev))

			// A subsequent delete event clears it.
			c.handleUpdate(model.KVPair{Key: model.IPAMHandleKey{HandleID: id}})
			Expect(c.allHandles).NotTo(HaveKey(id))
		})

		It("ignores OK handles", func() {
			c.allBlocks["10.0.0.0/26"] = makeBlock("10.0.0.0/26", map[int]string{0: "h-ok"})
			seedHandle("h-ok", map[string]int{"10.0.0.0/26": 1}, false)
			runCycles(requiredStableCycles + 2)
			h := fcli.GetHandle("h-ok")
			Expect(h).NotTo(BeNil())
			Expect(h.Block).To(Equal(map[string]int{"10.0.0.0/26": 1}))
			// No stability tracking left over.
			Expect(c.handleGC.stability).NotTo(HaveKey("h-ok"))
		})
	})
})
