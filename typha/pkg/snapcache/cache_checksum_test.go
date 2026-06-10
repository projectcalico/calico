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

package snapcache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/typha/pkg/synccheck"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// recomputeChecksum walks a breadcrumb's B-tree and computes the checksum from
// scratch, so we can assert that the incrementally-maintained value matches.
func recomputeChecksum(crumb *Breadcrumb) synccheck.Checksum {
	var c synccheck.Checksum
	crumb.KVs.Ascend(func(entry syncproto.SerializedUpdate) bool {
		c.Add(entry.Key, entry.Value)
		return true
	})
	return c
}

// waitForCrumbWithCount drives the cache until a breadcrumb with the expected
// number of KVs appears, then returns it.
func waitForCrumbWithCount(t *testing.T, cache *Cache, want int) *Breadcrumb {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		crumb := cache.CurrentBreadcrumb()
		if crumb.KVs.Len() == want {
			return crumb
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for breadcrumb with %d KVs (have %d)", want, crumb.KVs.Len())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func cfgUpdate(name, value, rev string, t api.UpdateType) api.Update {
	return api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: name},
			Value:    value,
			Revision: rev,
		},
		UpdateType: t,
	}
}

func cfgDelete(name string) api.Update {
	return api.Update{
		KVPair:     model.KVPair{Key: model.GlobalConfigKey{Name: name}},
		UpdateType: api.UpdateTypeKVDeleted,
	}
}

// TestCacheChecksum_MatchesRecompute drives a sequence of inserts, an in-place
// clobber, a delete and a delete-of-absent key through the cache and checks
// that, at every breadcrumb, the snapshotted checksum matches a
// recompute-from-scratch over the breadcrumb's B-tree and that KVCount matches
// the B-tree length.
func TestCacheChecksum_MatchesRecompute(t *testing.T) {
	cache := New(Config{
		MaxBatchSize:   10,
		WakeUpInterval: 10 * time.Second,
		Name:           "checksum-test",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache.Start(ctx)

	assertConsistent := func(crumb *Breadcrumb) {
		t.Helper()
		want := recomputeChecksum(crumb)
		if crumb.Checksum != want {
			t.Fatalf("seq %d: breadcrumb checksum %+v != recompute %+v",
				crumb.SequenceNumber, crumb.Checksum, want)
		}
		if int(crumb.Checksum.KVCount) != crumb.KVs.Len() {
			t.Fatalf("seq %d: checksum KVCount %d != B-tree len %d",
				crumb.SequenceNumber, crumb.Checksum.KVCount, crumb.KVs.Len())
		}
	}

	// Insert three keys.
	cache.OnUpdates([]api.Update{
		cfgUpdate("a", "va", "1", api.UpdateTypeKVNew),
		cfgUpdate("b", "vb", "1", api.UpdateTypeKVNew),
		cfgUpdate("c", "vc", "1", api.UpdateTypeKVNew),
	})
	crumb := waitForCrumbWithCount(t, cache, 3)
	assertConsistent(crumb)
	checksumAfterInsert := crumb.Checksum

	// Clobber "b" with a new value; count unchanged, checksum changes.
	cache.OnUpdates([]api.Update{cfgUpdate("b", "vb2", "2", api.UpdateTypeKVUpdated)})
	crumb = mustNext(t, crumb, ctx)
	assertConsistent(crumb)
	if crumb.Checksum == checksumAfterInsert {
		t.Fatal("clobber did not change the checksum")
	}
	if crumb.Checksum.KVCount != 3 {
		t.Fatalf("clobber changed KVCount: got %d, want 3", crumb.Checksum.KVCount)
	}

	// Delete "c"; count drops to 2.
	cache.OnUpdates([]api.Update{cfgDelete("c")})
	crumb = mustNext(t, crumb, ctx)
	assertConsistent(crumb)
	if crumb.Checksum.KVCount != 2 {
		t.Fatalf("delete did not drop KVCount: got %d, want 2", crumb.Checksum.KVCount)
	}

	// Delete an absent key.  This is a no-op for the live set; the cache still
	// records a delta (so a breadcrumb is published), but the checksum and count
	// must be unchanged.
	before := crumb.Checksum
	cache.OnUpdates([]api.Update{cfgDelete("does-not-exist")})
	crumb = mustNext(t, crumb, ctx)
	assertConsistent(crumb)
	if crumb.Checksum != before {
		t.Fatalf("delete-of-absent changed the checksum: %+v != %+v", crumb.Checksum, before)
	}
}

// TestCacheChecksum_DedupeSkipDoesNotChangeChecksum verifies that a no-op write
// (same value re-sent) does not perturb the checksum even though it flows
// through the cache.
func TestCacheChecksum_DedupeSkipDoesNotChangeChecksum(t *testing.T) {
	cache := New(Config{
		MaxBatchSize:   10,
		WakeUpInterval: 10 * time.Second,
		Name:           "checksum-dedupe-test",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache.Start(ctx)

	cache.OnUpdates([]api.Update{cfgUpdate("k", "v", "1", api.UpdateTypeKVNew)})
	crumb := waitForCrumbWithCount(t, cache, 1)
	checksumK := crumb.Checksum

	// Re-send the same key/value at a different revision.  WouldBeNoOp ignores
	// the revision, so this is a dedupe-skip: it must not be applied to the
	// checksum.  We send a genuinely new key in the same batch to force a
	// breadcrumb we can observe.
	cache.OnUpdates([]api.Update{
		cfgUpdate("k", "v", "2", api.UpdateTypeKVUpdated),
		cfgUpdate("k2", "v2", "1", api.UpdateTypeKVNew),
	})
	crumb = waitForCrumbWithCount(t, cache, 2)

	// The breadcrumb checksum must equal a recompute over its B-tree (i.e. "k"
	// contributes exactly once, not twice from the skipped no-op write).
	if want := recomputeChecksum(crumb); crumb.Checksum != want {
		t.Fatalf("dedupe-skip perturbed the checksum: got %+v, recompute %+v", crumb.Checksum, want)
	}
	// And "k" must contribute the same digest it did before: adding k2 to the
	// single-key checksum should yield the two-key checksum.
	withK2 := checksumK
	for _, entry := range crumbEntries(crumb) {
		if entry.Key != pathFor(t, "k") {
			withK2.Add(entry.Key, entry.Value)
		}
	}
	if crumb.Checksum != withK2 {
		t.Fatalf("k's contribution changed across the dedupe-skip: got %+v, want %+v", crumb.Checksum, withK2)
	}
}

func crumbEntries(crumb *Breadcrumb) []syncproto.SerializedUpdate {
	var out []syncproto.SerializedUpdate
	crumb.KVs.Ascend(func(entry syncproto.SerializedUpdate) bool {
		out = append(out, entry)
		return true
	})
	return out
}

func mustNext(t *testing.T, crumb *Breadcrumb, ctx context.Context) *Breadcrumb {
	t.Helper()
	next, err := crumb.Next(ctx)
	if err != nil {
		t.Fatalf("failed to get next breadcrumb: %v", err)
	}
	return next
}

func pathFor(t *testing.T, name string) string {
	t.Helper()
	path, err := model.KeyToDefaultPath(model.GlobalConfigKey{Name: name})
	if err != nil {
		t.Fatalf("failed to compute path: %v", err)
	}
	return fmt.Sprint(path)
}
