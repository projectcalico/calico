// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package node

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// requiredStableCycles is the number of consecutive sync cycles a divergent
// handle must remain in the same state before the GC will repair it. Combined
// with the ResourceVersion-stable check, this filters out transient divergence
// caused by in-flight CNI allocations and releases.
const requiredStableCycles = 3

// handleGCClass classifies an IPAMHandle's state relative to block reality.
type handleGCClass int

const (
	classOK handleGCClass = iota
	// classOrphan: handle exists, no block references it. Safe to delete.
	classOrphan
	// classMissing: a block references a handle that does not exist. Recreate.
	classMissing
	// classSkewed: handle exists with non-empty block map that disagrees with
	// reality. Rewrite to match reality. Never delete a non-empty handle —
	// doing so turns a counter mismatch into a permanent IP leak (the CNI
	// plugin's ReleaseByHandle iterates Spec.Block).
	classSkewed
	// classStuckDeleted: handle has Spec.Deleted=true but the soft-delete has
	// not been followed by a hard-delete (the deleter probably died). Reset
	// the flag and resync block state.
	classStuckDeleted
)

func (c handleGCClass) String() string {
	switch c {
	case classOK:
		return "ok"
	case classOrphan:
		return "orphan"
	case classMissing:
		return "missing"
	case classSkewed:
		return "skewed"
	case classStuckDeleted:
		return "stuck_deleted"
	}
	return "unknown"
}

// handleStability tracks a divergent handle across cycles. A repair fires only
// once the same diff has been observed for requiredStableCycles consecutive
// cycles AND the underlying signature hasn't changed (no actor has touched
// the handle or any contributing block in that window).
type handleStability struct {
	signature string
	cycles    int
}

// handleGCState carries cross-cycle state for the handle reconciler.
type handleGCState struct {
	// stability tracks per-handle divergence across cycles.
	stability map[string]handleStability
}

func newHandleGCState() *handleGCState {
	return &handleGCState{stability: map[string]handleStability{}}
}

// computeExpectedHandles walks the block cache and computes, for each handle
// referenced by any block allocation, the per-block reference count that the
// handle should hold. It is the source-of-truth for handle reconciliation:
// blocks own the actual allocations, so they define what the handle index
// must say.
func (c *IPAMController) computeExpectedHandles() map[string]map[string]int {
	expected := map[string]map[string]int{}
	for blockCIDR, kvp := range c.allBlocks {
		b, ok := kvp.Value.(*model.AllocationBlock)
		if !ok || b == nil {
			continue
		}
		for _, attrIdx := range b.Allocations {
			if attrIdx == nil {
				continue
			}
			if *attrIdx < 0 || *attrIdx >= len(b.Attributes) {
				continue
			}
			h := b.Attributes[*attrIdx].HandleID
			if h == nil || *h == "" {
				continue
			}
			byBlock, ok := expected[*h]
			if !ok {
				byBlock = map[string]int{}
				expected[*h] = byBlock
			}
			byBlock[blockCIDR]++
		}
	}
	return expected
}

// classifyHandle returns the GC class of a single (handle, expected) pair.
// Either side may be nil/empty: a missing handle with a non-empty expected
// is classMissing, an existing handle whose expected is empty is classOrphan,
// and so on.
func classifyHandle(handle *model.IPAMHandle, expected map[string]int) handleGCClass {
	if handle == nil {
		if len(expected) == 0 {
			return classOK
		}
		return classMissing
	}
	if handle.Deleted {
		// We treat StuckDeleted as a class even if the block map happens to
		// match expected: a Deleted=true handle is unusable (Get() on it
		// triggers a hard-delete) and must be either revived or removed.
		return classStuckDeleted
	}
	if blockMapsEqual(handle.Block, expected) {
		if len(handle.Block) == 0 {
			// Handle has no entries and reality says it shouldn't either —
			// this is a leftover orphan, eligible for hard-delete.
			return classOrphan
		}
		return classOK
	}
	// Counts disagree. Even if reality is empty, classify as Skewed: we'll
	// rewrite the handle to match (which empties it). The follow-up cycle
	// then sees a truly-empty handle and classifies it as Orphan, which is
	// when the hard-delete fires. Two-step delete avoids ever directly
	// removing a non-empty handle (which would break CNI ReleaseByHandle
	// for any allocation still racing through the system).
	return classSkewed
}

func blockMapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// signature builds a string that uniquely identifies the (actual, expected)
// pair for a handle. If the underlying handle is mutated (RV bump) or a
// contributing block changes (expected map changes), the signature changes
// and stability resets.
func handleSignature(class handleGCClass, kvp *model.KVPair, expected map[string]int) string {
	var actualRV string
	var actualBlocks string
	var actualDeleted bool
	if kvp != nil {
		actualRV = kvp.Revision
		if h, ok := kvp.Value.(*model.IPAMHandle); ok && h != nil {
			actualBlocks = canonicalBlockMap(h.Block)
			actualDeleted = h.Deleted
		}
	}
	return fmt.Sprintf("%s|rv=%s|del=%t|act=%s|exp=%s",
		class, actualRV, actualDeleted, actualBlocks, canonicalBlockMap(expected))
}

func canonicalBlockMap(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%d", k, m[k])
	}
	return b.String()
}

// reconcileHandles runs one pass of the handle GC: diff the watcher-fed
// handle cache against the block-derived expected state, and repair anything
// that's been divergent for requiredStableCycles. Called from syncIPAM after
// the block-level scan has finished.
//
// Safety rules (see plan):
//
//  1. Never delete a non-empty handle. Only classOrphan (and classStuckDeleted
//     with empty expected) deletes.
//  2. Repair direction is "set to expected", not "delta-adjust".
//  3. CAS or nothing — every write uses the live Revision from the syncer.
//  4. Soft-delete (Deleted=true) is treated as divergence: if it persists for
//     requiredStableCycles, the deleter has clearly died and we revive the
//     handle to match reality (or hard-delete it if expected is empty).
func (c *IPAMController) reconcileHandles(ctx context.Context) error {
	defer logIfSlow(time.Now(), "Handle GC complete")

	if !c.config.IPAMHandleGCEnabled {
		return nil
	}
	if c.bc == nil {
		// No backend client (some narrow test fakes). Nothing we can do.
		return nil
	}

	// The watcher syncer keeps c.allHandles up to date; no list call needed.
	actual := c.allHandles
	expected := c.computeExpectedHandles()

	// Visit the union of expected and actual handle IDs.
	seen := map[string]bool{}
	for id := range actual {
		seen[id] = true
	}
	for id := range expected {
		seen[id] = true
	}

	stillDivergent := map[string]bool{}
	for id := range seen {
		actKvp := actual[id]
		var actHandle *model.IPAMHandle
		if actKvp != nil {
			actHandle, _ = actKvp.Value.(*model.IPAMHandle)
		}
		exp := expected[id]
		class := classifyHandle(actHandle, exp)

		handleGCDiffsObserved.WithLabelValues(class.String()).Inc()

		if class == classOK {
			continue
		}
		stillDivergent[id] = true

		sig := handleSignature(class, actKvp, exp)
		prev, ok := c.handleGC.stability[id]
		if !ok || prev.signature != sig {
			c.handleGC.stability[id] = handleStability{signature: sig, cycles: 1}
			continue
		}
		prev.cycles++
		c.handleGC.stability[id] = prev

		if prev.cycles < requiredStableCycles {
			continue
		}

		// Stable for long enough — repair.
		if err := c.repairHandle(ctx, id, class, actKvp, exp); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"handle": id,
				"class":  class.String(),
			}).Warn("Failed to repair IPAM handle; will retry next cycle")
			// Reset stability so transient errors don't get permanently stuck.
			delete(c.handleGC.stability, id)
			continue
		}

		// Successful repair — drop stability tracking; next cycle will
		// re-observe the new state.
		delete(c.handleGC.stability, id)
	}

	// GC stability entries for handles that have returned to OK or that
	// no longer exist in either map.
	for id := range c.handleGC.stability {
		if !stillDivergent[id] {
			delete(c.handleGC.stability, id)
		}
	}

	// Update divergent gauge.
	handleGCDivergent.Set(float64(len(stillDivergent)))

	return nil
}

// repairHandle dispatches a single handle repair based on class. Each repair
// is CAS-conditional on the listed Revision; on conflict (a real client
// modified the handle in the meantime) we abort the repair and rely on the
// next cycle to re-evaluate against fresh data.
func (c *IPAMController) repairHandle(
	ctx context.Context,
	handleID string,
	class handleGCClass,
	actKvp *model.KVPair,
	expected map[string]int,
) error {
	logc := log.WithFields(log.Fields{"handle": handleID, "class": class.String()})

	switch class {
	case classOrphan:
		// Existing handle, nothing references it — hard-delete via DeleteKVP.
		// Safety: defensive re-check; we must never delete a non-empty handle
		// (would break ReleaseByHandle and leak IPs).
		if h, ok := actKvp.Value.(*model.IPAMHandle); !ok || h == nil || len(h.Block) != 0 {
			logc.Warn("Refusing to delete non-empty handle (race?); skipping")
			return nil
		}
		_, err := c.bc.DeleteKVP(ctx, actKvp)
		if err != nil {
			if isCASConflict(err) {
				handleGCCASConflicts.Inc()
				logc.Debug("CAS conflict deleting orphan handle; will re-evaluate")
				return nil
			}
			return err
		}
		handleGCRepairs.WithLabelValues("delete").Inc()
		logc.Info("Garbage collected orphan IPAM handle")
		return nil

	case classMissing:
		if len(expected) == 0 {
			return nil
		}
		// Defensive copy: don't share the expected map with the backend.
		blocks := copyBlockMap(expected)
		newKvp := &model.KVPair{
			Key: model.IPAMHandleKey{HandleID: handleID},
			Value: &model.IPAMHandle{
				HandleID: handleID,
				Block:    blocks,
			},
		}
		_, err := c.bc.Create(ctx, newKvp)
		if err != nil {
			// AlreadyExists is the benign race: a real client created the
			// handle just before our create. Drop and re-evaluate.
			if _, ok := err.(cerrors.ErrorResourceAlreadyExists); ok {
				handleGCCASConflicts.Inc()
				logc.Debug("Handle was concurrently created; will re-evaluate")
				return nil
			}
			return err
		}
		handleGCRepairs.WithLabelValues("create").Inc()
		logc.WithField("blocks", expected).Info("Recreated missing IPAM handle")
		return nil

	case classSkewed:
		// Rewrite Spec.Block to expected. expected may be empty: in that case
		// this clears the handle without deleting it. The next cycle then
		// classifies the now-empty handle as Orphan and hard-deletes it.
		// This two-step path avoids ever directly deleting a handle that
		// still has refs (which would break CNI ReleaseByHandle).
		h, ok := actKvp.Value.(*model.IPAMHandle)
		if !ok || h == nil {
			return fmt.Errorf("unexpected handle KVPair value")
		}
		if expected == nil {
			h.Block = map[string]int{}
		} else {
			h.Block = copyBlockMap(expected)
		}
		_, err := c.bc.Update(ctx, actKvp)
		if err != nil {
			if isCASConflict(err) {
				handleGCCASConflicts.Inc()
				logc.Debug("CAS conflict overwriting handle; will re-evaluate")
				return nil
			}
			return err
		}
		handleGCRepairs.WithLabelValues("overwrite").Inc()
		logc.WithField("blocks", expected).Info("Repaired skewed IPAM handle")
		return nil

	case classStuckDeleted:
		h, ok := actKvp.Value.(*model.IPAMHandle)
		if !ok || h == nil {
			return fmt.Errorf("unexpected handle KVPair value")
		}
		if len(expected) == 0 {
			// Deleter died, and the handle has nothing to repair. Hard-delete.
			_, err := c.bc.DeleteKVP(ctx, actKvp)
			if err != nil {
				if isCASConflict(err) {
					handleGCCASConflicts.Inc()
					return nil
				}
				return err
			}
			handleGCRepairs.WithLabelValues("delete").Inc()
			logc.Info("Hard-deleted stuck soft-deleted IPAM handle")
			return nil
		}
		// Revive the handle: clear Deleted, set Block to expected.
		h.Deleted = false
		h.Block = copyBlockMap(expected)
		_, err := c.bc.Update(ctx, actKvp)
		if err != nil {
			if isCASConflict(err) {
				handleGCCASConflicts.Inc()
				return nil
			}
			return err
		}
		handleGCRepairs.WithLabelValues("undelete").Inc()
		logc.WithField("blocks", expected).Info("Revived stuck soft-deleted IPAM handle")
		return nil
	}
	return nil
}

func isCASConflict(err error) bool {
	if _, ok := err.(cerrors.ErrorResourceUpdateConflict); ok {
		return true
	}
	if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
		// If the resource went away between list and write, treat as a
		// conflict — the next cycle will see the new state.
		return true
	}
	return false
}

func copyBlockMap(m map[string]int) map[string]int {
	cp := make(map[string]int, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

// Prometheus metrics for handle GC. Registered in init.
var (
	handleGCRepairs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ipam_handle_gc_repairs_total",
		Help: "Number of IPAMHandle repair actions performed by kube-controllers, by action.",
	}, []string{"action"})

	handleGCDiffsObserved = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ipam_handle_gc_diffs_observed_total",
		Help: "Number of IPAMHandle diffs observed by kube-controllers, by class.",
	}, []string{"class"})

	handleGCCASConflicts = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ipam_handle_gc_cas_conflicts_total",
		Help: "Number of CAS conflicts encountered while repairing IPAMHandles.",
	})

	handleGCDivergent = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ipam_handle_gc_divergent_handles",
		Help: "Number of IPAMHandles currently divergent from block reality.",
	})
)

func init() {
	prometheus.MustRegister(handleGCRepairs)
	prometheus.MustRegister(handleGCDiffsObserved)
	prometheus.MustRegister(handleGCCASConflicts)
	prometheus.MustRegister(handleGCDivergent)
}
