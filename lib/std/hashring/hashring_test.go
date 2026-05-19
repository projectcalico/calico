// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package hashring

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"testing"
)

var configs = []struct {
	name             string
	replicas, probes int
}{
	{"vnodes_R100_P1", 100, 1},
	{"multiprobe_R1_P21", 1, 21},
	{"hybrid_R10_P10", 10, 10},
}

func forEachConfig(t *testing.T, fn func(t *testing.T, replicas, probes int)) {
	t.Helper()
	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			fn(t, cfg.replicas, cfg.probes)
		})
	}
}

func newRing[V any](replicas, probes int) *Ring[V] {
	return New[V](WithReplicas(replicas), WithProbes(probes))
}

func TestEmptyRing_LookupReturnsFalse(t *testing.T) {
	forEachConfig(t, func(t *testing.T, replicas, probes int) {
		r := newRing[string](replicas, probes)
		v, ok := r.Lookup("anything")
		if ok {
			t.Fatalf("expected ok=false on empty ring, got ok=true value=%q", v)
		}
		if v != "" {
			t.Fatalf("expected zero value, got %q", v)
		}
		if r.Len() != 0 {
			t.Fatalf("expected Len=0, got %d", r.Len())
		}
	})
}

func TestSingleMember_AlwaysReturned(t *testing.T) {
	forEachConfig(t, func(t *testing.T, replicas, probes int) {
		r := newRing[string](replicas, probes)
		r.Insert("only", "value-of-only")
		if r.Len() != 1 {
			t.Fatalf("expected Len=1, got %d", r.Len())
		}
		for i := range 100 {
			v, ok := r.Lookup(fmt.Sprintf("key-%d", i))
			if !ok || v != "value-of-only" {
				t.Fatalf("Lookup #%d: ok=%v v=%q", i, ok, v)
			}
		}
	})
}

func TestDeterministic_SameInputsSameResults(t *testing.T) {
	forEachConfig(t, func(t *testing.T, replicas, probes int) {
		build := func() *Ring[string] {
			r := newRing[string](replicas, probes)
			for _, m := range []string{"a", "b", "c", "d", "e"} {
				r.Insert(m, m)
			}
			return r
		}
		r1 := build()
		r2 := build()
		for i := range 1000 {
			k := fmt.Sprintf("key-%d", i)
			v1, ok1 := r1.Lookup(k)
			v2, ok2 := r2.Lookup(k)
			if v1 != v2 || ok1 != ok2 {
				t.Fatalf("key=%q: r1=(%q,%v) r2=(%q,%v)", k, v1, ok1, v2, ok2)
			}
		}
	})
}

func TestInsert_IdempotentUpdatesValue(t *testing.T) {
	forEachConfig(t, func(t *testing.T, replicas, probes int) {
		r := newRing[string](replicas, probes)
		r.Insert("a", "v1")
		r.Insert("b", "v2")
		entriesBefore := len(r.entries)
		if entriesBefore != 2*replicas {
			t.Fatalf("entries=%d want=%d", entriesBefore, 2*replicas)
		}

		r.Insert("a", "v1-updated")

		if got := len(r.entries); got != entriesBefore {
			t.Fatalf("entries grew: before=%d after=%d", entriesBefore, got)
		}
		if r.Len() != 2 {
			t.Fatalf("Len=%d, want 2", r.Len())
		}

		// Find a key that lands on member "a", then check it sees the new value.
		foundA := false
		for i := 0; i < 1000 && !foundA; i++ {
			k := fmt.Sprintf("k%d", i)
			v, _ := r.Lookup(k)
			if v == "v1-updated" {
				foundA = true
			}
			if v == "v1" {
				t.Fatalf("key %q still returned old value v1", k)
			}
		}
		if !foundA {
			t.Fatalf("never observed updated value for member a")
		}
	})
}

func TestRemove_ExactNoTrace(t *testing.T) {
	forEachConfig(t, func(t *testing.T, replicas, probes int) {
		r := newRing[string](replicas, probes)
		for _, m := range []string{"a", "b", "c"} {
			r.Insert(m, m)
		}
		r.Remove("b")
		// Len reflects the removal immediately; entries/members
		// state is swept lazily on the next Lookup.
		if r.Len() != 2 {
			t.Fatalf("Len=%d, want 2", r.Len())
		}
		// Trigger the sweep, then assert no internal trace remains.
		_, _ = r.Lookup("warmup")
		if _, ok := r.members["b"]; ok {
			t.Fatalf("member 'b' still in members map after sweep")
		}
		for _, e := range r.entries {
			if e.key == "b" {
				t.Fatalf("entry with key 'b' still present after sweep")
			}
		}
		for i := range 1000 {
			v, ok := r.Lookup(fmt.Sprintf("k%d", i))
			if !ok || v == "b" {
				t.Fatalf("Lookup returned removed value: ok=%v v=%q", ok, v)
			}
		}
	})
}

// TestRemove_IsDeferredUntilLookup documents the laziness contract:
// Remove only queues a sweep; the entries slice and members map
// retain the key until the next Lookup performs the sweep. Insert
// of a queued-for-removal key un-queues it and preserves the
// original ring positions.
func TestRemove_IsDeferredUntilLookup(t *testing.T) {
	r := newRing[string](10, 1)
	r.Insert("a", "a-v1")
	r.Insert("b", "b-v1")
	entriesAfterInsert := len(r.entries)

	r.Remove("a")
	// Len reflects removal immediately.
	if r.Len() != 1 {
		t.Fatalf("Len after Remove=%d, want 1", r.Len())
	}
	// But entries and members still hold "a" until the sweep.
	if len(r.entries) != entriesAfterInsert {
		t.Fatalf("entries len changed before sweep: got %d want %d", len(r.entries), entriesAfterInsert)
	}
	if _, ok := r.members["a"]; !ok {
		t.Fatalf("members lost 'a' before sweep")
	}
	if _, ok := r.deletedKeys["a"]; !ok {
		t.Fatalf("deletedKeys missing 'a' after Remove")
	}

	// Re-inserting un-queues without churning entries.
	r.Insert("a", "a-v2")
	if _, ok := r.deletedKeys["a"]; ok {
		t.Fatalf("deletedKeys still contains 'a' after re-Insert")
	}
	if len(r.entries) != entriesAfterInsert {
		t.Fatalf("entries len changed by re-Insert: got %d want %d", len(r.entries), entriesAfterInsert)
	}
	if r.members["a"] != "a-v2" {
		t.Fatalf("re-Insert did not update value: got %q", r.members["a"])
	}

	// Now actually remove and trigger a sweep.
	r.Remove("a")
	_, _ = r.Lookup("warmup")
	if _, ok := r.members["a"]; ok {
		t.Fatalf("members still has 'a' after sweep")
	}
	if len(r.deletedKeys) != 0 {
		t.Fatalf("deletedKeys not cleared after sweep")
	}
	if len(r.entries) != 10 {
		t.Fatalf("entries=%d after sweep, want 10 (just b's replicas)", len(r.entries))
	}
}

func TestRemove_AbsentIsNoOp(t *testing.T) {
	forEachConfig(t, func(t *testing.T, replicas, probes int) {
		r := newRing[string](replicas, probes)
		r.Insert("a", "a")
		r.Insert("b", "b")

		before := make(map[string]string, 1000)
		for i := range 1000 {
			k := fmt.Sprintf("k%d", i)
			v, _ := r.Lookup(k)
			before[k] = v
		}

		r.Remove("not-present")

		if r.Len() != 2 {
			t.Fatalf("Len=%d, want 2", r.Len())
		}
		for k, want := range before {
			got, _ := r.Lookup(k)
			if got != want {
				t.Fatalf("ownership for %q changed: before=%q after=%q", k, want, got)
			}
		}
	})
}

func TestSortDeferral_BulkVsInterleaved(t *testing.T) {
	forEachConfig(t, func(t *testing.T, replicas, probes int) {
		rng := rand.New(rand.NewPCG(1, 2))
		members := make([]string, 20)
		for i := range members {
			members[i] = fmt.Sprintf("member-%d-%d", i, rng.Uint32())
		}

		bulk := newRing[string](replicas, probes)
		for _, m := range members {
			bulk.Insert(m, m)
		}

		interleaved := newRing[string](replicas, probes)
		for _, m := range members {
			interleaved.Insert(m, m)
			// Force a sort between inserts.
			_, _ = interleaved.Lookup("warmup")
		}

		for i := range 2000 {
			k := fmt.Sprintf("probe-%d", i)
			vb, _ := bulk.Lookup(k)
			vi, _ := interleaved.Lookup(k)
			if vb != vi {
				t.Fatalf("key=%q bulk=%q interleaved=%q", k, vb, vi)
			}
		}
	})
}

func TestStabilityUnderReinsert(t *testing.T) {
	forEachConfig(t, func(t *testing.T, replicas, probes int) {
		probe := func(r *Ring[string]) []string {
			out := make([]string, 1000)
			for i := range out {
				v, _ := r.Lookup(fmt.Sprintf("k-%d", i))
				out[i] = v
			}
			return out
		}

		r1 := newRing[string](replicas, probes)
		for _, m := range []string{"a", "b", "c"} {
			r1.Insert(m, m)
		}
		want := probe(r1)

		r2 := newRing[string](replicas, probes)
		for _, m := range []string{"c", "a", "b"} {
			r2.Insert(m, m)
		}
		got := probe(r2)

		if !slices.Equal(want, got) {
			t.Fatalf("answers differ across insertion orders")
		}
	})
}

func TestConsistentHashingProperty_RemovalMovesOneOverN(t *testing.T) {
	forEachConfig(t, func(t *testing.T, replicas, probes int) {
		const N = 8
		const keyProbes = 10000

		r := newRing[string](replicas, probes)
		for i := range N {
			m := fmt.Sprintf("m%d", i)
			r.Insert(m, m)
		}

		before := make([]string, keyProbes)
		for i := range before {
			before[i], _ = r.Lookup(fmt.Sprintf("k-%d", i))
		}

		r.Remove("m3")

		moved := 0
		for i := range before {
			v, _ := r.Lookup(fmt.Sprintf("k-%d", i))
			if v != before[i] {
				moved++
			}
		}

		frac := float64(moved) / float64(keyProbes)
		lower := 0.5 / float64(N)
		upper := 2.0 / float64(N)
		if frac < lower || frac > upper {
			t.Fatalf("moved fraction %.3f not in [%.3f, %.3f]", frac, lower, upper)
		}

		// Sanity: keys previously owned by m3 must all have moved.
		for i := range before {
			if before[i] == "m3" {
				v, _ := r.Lookup(fmt.Sprintf("k-%d", i))
				if v == "m3" {
					t.Fatalf("key %d still returns removed member m3", i)
				}
			}
		}
	})
}

func TestDistribution_RoughlyEven(t *testing.T) {
	forEachConfig(t, func(t *testing.T, replicas, probes int) {
		const M = 10
		const keyProbes = 10000

		r := newRing[string](replicas, probes)
		for i := range M {
			m := fmt.Sprintf("m%d", i)
			r.Insert(m, m)
		}

		counts := make(map[string]int, M)
		for i := range keyProbes {
			v, _ := r.Lookup(fmt.Sprintf("probe-%d", i))
			counts[v]++
		}

		if len(counts) != M {
			t.Fatalf("only %d members received any keys", len(counts))
		}
		// Loose bound: regression guard, not a quality metric. Some
		// configs (replicas=1, probes=1) are bare CH and can be very
		// uneven; widen if flaky.
		for m, c := range counts {
			frac := float64(c) / float64(keyProbes)
			if frac < 0.02 || frac > 0.30 {
				t.Errorf("member %s owns %.3f of keys (want 0.02..0.30)", m, frac)
			}
		}
	})
}

func TestHashCollision_TiebreakIsKeyOrder(t *testing.T) {
	// Hash always returns 0. With identical hashes, ownership must
	// depend only on member keys, not insertion order. Run against
	// each config so probes>1 inherits the tiebreak too.
	constHash := func(_ []byte) uint64 { return 0 }
	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			mk := func() *Ring[string] {
				return New[string](WithHash(constHash), WithReplicas(cfg.replicas), WithProbes(cfg.probes))
			}
			r1 := mk()
			for _, m := range []string{"alpha", "bravo", "charlie"} {
				r1.Insert(m, m)
			}
			r2 := mk()
			for _, m := range []string{"charlie", "alpha", "bravo"} {
				r2.Insert(m, m)
			}

			for i := range 100 {
				k := fmt.Sprintf("k%d", i)
				v1, _ := r1.Lookup(k)
				v2, _ := r2.Lookup(k)
				if v1 != v2 {
					t.Fatalf("collision tiebreak nondeterministic: %q vs %q", v1, v2)
				}
			}
		})
	}
}

// saltedKey reproduces the package-internal encoding used by
// saltedHash so tests can pin specific hash outputs by string match.
func saltedKey(k string, i int) string {
	var idx [4]byte
	binary.LittleEndian.PutUint32(idx[:], uint32(i))
	return k + "\x00" + string(idx[:])
}

// TestLookup_WrapsAroundRing pins specific hash values so the lookup
// probe falls past the maximum entry hash, exercising the
// `idx == len(entries) -> idx = 0` branch in Lookup.
func TestLookup_WrapsAroundRing(t *testing.T) {
	known := map[string]uint64{
		saltedKey("low", 0):             100,
		saltedKey("high", 0):            200,
		saltedKey("probe-below", 0):     50,
		saltedKey("probe-between", 0):   150,
		saltedKey("probe-above-max", 0): 250,
	}
	stub := func(b []byte) uint64 {
		v, ok := known[string(b)]
		if !ok {
			t.Fatalf("unexpected hash input %q", b)
		}
		return v
	}
	r := New[string](WithHash(stub))
	r.Insert("low", "low-val")
	r.Insert("high", "high-val")

	cases := []struct {
		key, want string
	}{
		{"probe-below", "low-val"},     // hash=50, next entry at 100
		{"probe-between", "high-val"},  // hash=150, next entry at 200
		{"probe-above-max", "low-val"}, // hash=250, wraps to entry at 100
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			v, ok := r.Lookup(tc.key)
			if !ok || v != tc.want {
				t.Fatalf("got (%q, %v), want (%q, true)", v, ok, tc.want)
			}
		})
	}
}

// TestLookup_MultiProbeWrapDistance verifies that when a probe wraps
// around the ring its distance is computed correctly as a large
// uint64 (via modular subtraction underflow), so a non-wrapping probe
// with a smaller real distance still wins.
func TestLookup_MultiProbeWrapDistance(t *testing.T) {
	known := map[string]uint64{
		saltedKey("alpha", 0): 100,
		saltedKey("beta", 0):  200,
		// Lookup key "k", two probes:
		//   probe 0 at 99  -> closest entry is alpha@100, distance=1
		//   probe 1 at 250 -> wraps to alpha@100,
		//                     distance = 100 - 250 (uint64) ≈ 2^64
		// Probe 0 must win.
		saltedKey("k", 0): 99,
		saltedKey("k", 1): 250,
	}
	stub := func(b []byte) uint64 {
		v, ok := known[string(b)]
		if !ok {
			t.Fatalf("unexpected hash input %q", b)
		}
		return v
	}
	r := New[string](WithHash(stub), WithProbes(2))
	r.Insert("alpha", "alpha-val")
	r.Insert("beta", "beta-val")

	v, ok := r.Lookup("k")
	if !ok || v != "alpha-val" {
		t.Fatalf("got (%q, %v), want (alpha-val, true)", v, ok)
	}
}

// TestLookup_MultiProbeWrapWins verifies the opposite case: a probe
// that wraps but has a smaller wrapped distance than a non-wrapping
// probe must still be selected. Both probes wrap; the one whose
// nearest entry is closer wins.
func TestLookup_MultiProbeWrapWins(t *testing.T) {
	known := map[string]uint64{
		saltedKey("alpha", 0): 100,
		saltedKey("beta", 0):  200,
		// Probe 0 at 300 -> wraps to alpha@100, distance = 100 - 300 (uint64) huge.
		// Probe 1 at 199 -> beta@200, distance = 1. Probe 1 wins (no wrap).
		saltedKey("k", 0): 300,
		saltedKey("k", 1): 199,
	}
	stub := func(b []byte) uint64 {
		v, ok := known[string(b)]
		if !ok {
			t.Fatalf("unexpected hash input %q", b)
		}
		return v
	}
	r := New[string](WithHash(stub), WithProbes(2))
	r.Insert("alpha", "alpha-val")
	r.Insert("beta", "beta-val")

	v, ok := r.Lookup("k")
	if !ok || v != "beta-val" {
		t.Fatalf("got (%q, %v), want (beta-val, true)", v, ok)
	}
}

func TestNew_PanicsOnBadArgs(t *testing.T) {
	cases := []struct {
		name string
		call func()
	}{
		{"zero replicas", func() { _ = New[string](WithReplicas(0)) }},
		{"negative replicas", func() { _ = New[string](WithReplicas(-1)) }},
		{"zero probes", func() { _ = New[string](WithProbes(0)) }},
		{"negative probes", func() { _ = New[string](WithProbes(-1)) }},
		{"nil hash", func() { _ = New[string](WithHash(nil)) }},
		{"nil hash with options", func() { _ = New[string](WithHash(nil), WithReplicas(50)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("expected panic")
				}
			}()
			tc.call()
		})
	}
}

func TestGenericValueType(t *testing.T) {
	type backend struct {
		addr string
		port int
	}
	forEachConfig(t, func(t *testing.T, replicas, probes int) {
		r := New[backend](WithReplicas(replicas), WithProbes(probes))
		r.Insert("a", backend{addr: "10.0.0.1", port: 80})
		r.Insert("b", backend{addr: "10.0.0.2", port: 80})
		v, ok := r.Lookup("some-key")
		if !ok {
			t.Fatalf("ok=false")
		}
		if v.port != 80 {
			t.Fatalf("got %+v", v)
		}
	})
}

func TestProbeCount_LookupHashesKeyP(t *testing.T) {
	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			var calls int
			counting := func(b []byte) uint64 {
				calls++
				// Return a key-dependent value so members still
				// occupy distinct ring positions. The exact mapping
				// is irrelevant — this test only checks call count.
				var h uint64 = 14695981039346656037
				for _, c := range b {
					h ^= uint64(c)
					h *= 1099511628211
				}
				return h
			}
			r := New[string](WithHash(counting), WithReplicas(cfg.replicas), WithProbes(cfg.probes))
			for _, m := range []string{"a", "b", "c"} {
				r.Insert(m, m)
			}
			// Warm the sort so it doesn't count against Lookup.
			_, _ = r.Lookup("warmup")
			calls = 0
			_, _ = r.Lookup("query")
			if calls != cfg.probes {
				t.Fatalf("Lookup hashed key %d times, want %d", calls, cfg.probes)
			}
		})
	}
}

func TestMemorySavings_EntriesScaleWithReplicas(t *testing.T) {
	const N = 50
	cases := []struct {
		name             string
		replicas, probes int
		wantEntries      int
	}{
		{"vnodes_R100", 100, 1, N * 100},
		{"multiprobe_R1", 1, 21, N},
		{"hybrid_R10", 10, 10, N * 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRing[string](tc.replicas, tc.probes)
			for i := range N {
				m := fmt.Sprintf("m%d", i)
				r.Insert(m, m)
			}
			if got := len(r.entries); got != tc.wantEntries {
				t.Fatalf("entries=%d want=%d", got, tc.wantEntries)
			}
		})
	}
}

func FuzzRing(f *testing.F) {
	f.Add(uint64(1), uint64(2), uint(50), uint(1))
	f.Add(uint64(42), uint64(99), uint(7), uint(11))
	f.Add(uint64(0), uint64(0), uint(1), uint(21))
	f.Add(uint64(7), uint64(8), uint(10), uint(10))

	f.Fuzz(func(t *testing.T, seed1, seed2 uint64, replicas, probes uint) {
		// Keep R and P to sane ranges so the test stays fast.
		rep := int(replicas%64) + 1
		prb := int(probes%32) + 1

		rng := rand.New(rand.NewPCG(seed1, seed2))
		r := newRing[string](rep, prb)
		alphabet := []string{"a", "b", "c", "d", "e", "f", "g", "h"}

		for op := range 200 {
			k := alphabet[rng.IntN(len(alphabet))]
			switch rng.IntN(3) {
			case 0:
				r.Insert(k, k+"-v")
			case 1:
				r.Remove(k)
			case 2:
				_, _ = r.Lookup(fmt.Sprintf("probe-%d", op))
			}

			// Invariants after every op. With deferred deletes:
			//   - members and entries flush together at sweep time,
			//     so len(entries) == len(members)*replicas always.
			//   - deletedKeys is a subset of members.
			//   - Len = live = members - deletedKeys.
			if r.Len() != len(r.members)-len(r.deletedKeys) {
				t.Fatalf("Len()=%d members=%d deleted=%d", r.Len(), len(r.members), len(r.deletedKeys))
			}
			wantEntries := len(r.members) * rep
			if len(r.entries) != wantEntries {
				t.Fatalf("entries=%d want=%d (members=%d R=%d)", len(r.entries), wantEntries, len(r.members), rep)
			}
			for _, e := range r.entries {
				if _, ok := r.members[e.key]; !ok {
					t.Fatalf("entry key %q not in members map", e.key)
				}
			}
			for k := range r.deletedKeys {
				if _, ok := r.members[k]; !ok {
					t.Fatalf("deletedKey %q not in members map", k)
				}
			}
			if r.sorted {
				if !sort.SliceIsSorted(r.entries, func(i, j int) bool {
					a, b := r.entries[i], r.entries[j]
					if a.hash != b.hash {
						return a.hash < b.hash
					}
					return a.key < b.key
				}) {
					t.Fatalf("sorted=true but entries not actually sorted")
				}
			}
		}
	})
}

// BenchmarkRemove measures the cost of a single Remove on a populated
// ring. With deferred deletion this is O(1) regardless of ring size.
// Each iteration re-Inserts before Removing so the timer only sees
// the Remove call.
func BenchmarkRemove(b *testing.B) {
	cases := []struct {
		name             string
		members          int
		replicas, probes int
	}{
		{"N1000_R100_P1", 1000, 100, 1},
		{"N1000_R1_P21", 1000, 1, 21},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			r := newRing[string](tc.replicas, tc.probes)
			for i := range tc.members {
				m := fmt.Sprintf("member-%d", i)
				r.Insert(m, m)
			}
			_, _ = r.Lookup("warmup") // sort + ensure no pending sweep
			b.ResetTimer()
			i := 0
			for b.Loop() {
				// Re-Insert (un-queues if needed) then Remove.
				k := fmt.Sprintf("member-%d", i%tc.members)
				b.StopTimer()
				r.Insert(k, k)
				b.StartTimer()
				r.Remove(k)
				i++
			}
		})
	}
}

// BenchmarkBulkRemoveThenLookup amortises a batch of Removes plus the
// single Lookup that pays for the sweep. Demonstrates the benefit of
// deferred deletion: the slice scan happens once for the whole batch
// rather than once per Remove.
func BenchmarkBulkRemoveThenLookup(b *testing.B) {
	cases := []struct {
		name             string
		members          int
		removeBatch      int
		replicas, probes int
	}{
		{"N1000_remove500_R100_P1", 1000, 500, 100, 1},
		{"N1000_remove500_R1_P21", 1000, 500, 1, 21},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			memberNames := make([]string, tc.members)
			for i := range memberNames {
				memberNames[i] = fmt.Sprintf("member-%d", i)
			}
			for b.Loop() {
				b.StopTimer()
				r := newRing[string](tc.replicas, tc.probes)
				for _, m := range memberNames {
					r.Insert(m, m)
				}
				_, _ = r.Lookup("warmup")
				b.StartTimer()
				for i := range tc.removeBatch {
					r.Remove(memberNames[i])
				}
				_, _ = r.Lookup("post-batch")
			}
		})
	}
}

// BenchmarkFirstLookup measures the cost of the first Lookup after a
// bulk Insert (i.e. one Lookup includes the deferred sort of the
// virtual-node table). Each iteration rebuilds the ring; the timer is
// paused around setup so only the sort+lookup is measured.
func BenchmarkFirstLookup(b *testing.B) {
	cases := []struct {
		name             string
		members          int
		replicas, probes int
	}{
		{"N50_R100_P1", 50, 100, 1},
		{"N50_R1_P21", 50, 1, 21},
		{"N50_R10_P10", 50, 10, 10},
		{"N1000_R100_P1", 1000, 100, 1},
		{"N1000_R1_P21", 1000, 1, 21},
		{"N1000_R10_P10", 1000, 10, 10},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			memberNames := make([]string, tc.members)
			for i := range memberNames {
				memberNames[i] = fmt.Sprintf("member-%d", i)
			}
			for b.Loop() {
				b.StopTimer()
				r := newRing[string](tc.replicas, tc.probes)
				for _, m := range memberNames {
					r.Insert(m, m)
				}
				b.StartTimer()
				_, _ = r.Lookup("first-lookup-key")
			}
		})
	}
}

func BenchmarkLookup(b *testing.B) {
	cases := []struct {
		name     string
		members  int
		replicas int
		probes   int
	}{
		{"N50_R100_P1", 50, 100, 1},
		{"N50_R1_P21", 50, 1, 21},
		{"N50_R10_P10", 50, 10, 10},
		{"N1000_R100_P1", 1000, 100, 1},
		{"N1000_R1_P21", 1000, 1, 21},
		{"N1000_R10_P10", 1000, 10, 10},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			r := newRing[string](tc.replicas, tc.probes)
			for i := range tc.members {
				m := fmt.Sprintf("member-%d", i)
				r.Insert(m, m)
			}
			// Warm the sort.
			_, _ = r.Lookup("warmup")
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				// Vary the key so we exercise the ring, not a single cached probe path.
				_, _ = r.Lookup(fmt.Sprintf("benchmark-key-%d", i))
			}
		})
	}
}
