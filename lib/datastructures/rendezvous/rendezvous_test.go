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

package rendezvous

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"sort"
	"testing"
)

// combinedKey reproduces the package-internal encoding used by
// combinedHash so tests can pin specific hash outputs by string match.
func combinedKey(member, key string) string {
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(member)))
	return string(n[:]) + member + key
}

// bruteForceLookup independently computes the HRW winner for key over
// the given members, applying the same highest-score / lower-key
// tiebreak as Lookup. Used to cross-check Lookup.
func bruteForceLookup(h Hash, members []string, key string) string {
	best := ""
	var bestScore uint64
	first := true
	for _, m := range members {
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], uint32(len(m)))
		buf := append(append(append([]byte{}, n[:]...), m...), key...)
		s := h(buf)
		if first || s > bestScore || (s == bestScore && m < best) {
			bestScore, best, first = s, m, false
		}
	}
	return best
}

// bruteForceRank independently computes the full descending-preference
// order over members for key, applying the same highest-score /
// lower-key tiebreak as Rank. Used to cross-check Rank.
func bruteForceRank(h Hash, members []string, key string) []string {
	type sk struct {
		score uint64
		key   string
	}
	scored := make([]sk, len(members))
	for i, m := range members {
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], uint32(len(m)))
		buf := append(append(append([]byte{}, n[:]...), m...), key...)
		scored[i] = sk{score: h(buf), key: m}
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		return scored[i].key < scored[j].key
	})
	out := make([]string, len(scored))
	for i, s := range scored {
		out[i] = s.key
	}
	return out
}

func TestEmpty_LookupReturnsFalse(t *testing.T) {
	r := New[string]()
	v, ok := r.Lookup("anything")
	if ok {
		t.Fatalf("expected ok=false on empty, got ok=true value=%q", v)
	}
	if v != "" {
		t.Fatalf("expected zero value, got %q", v)
	}
	if r.Len() != 0 {
		t.Fatalf("expected Len=0, got %d", r.Len())
	}
}

func TestSingleMember_AlwaysReturned(t *testing.T) {
	r := New[string]()
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
}

func TestDeterministic_SameInputsSameResults(t *testing.T) {
	build := func() *Rendezvous[string] {
		r := New[string]()
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
}

func TestDeterministic_IndependentOfInsertionOrder(t *testing.T) {
	probe := func(r *Rendezvous[string]) []string {
		out := make([]string, 1000)
		for i := range out {
			out[i], _ = r.Lookup(fmt.Sprintf("k-%d", i))
		}
		return out
	}

	r1 := New[string]()
	for _, m := range []string{"a", "b", "c", "d", "e"} {
		r1.Insert(m, m)
	}
	want := probe(r1)

	// Insert the same members in a different order; map layout differs
	// but ownership must be identical.
	r2 := New[string]()
	for _, m := range []string{"e", "c", "a", "d", "b"} {
		r2.Insert(m, m)
	}
	got := probe(r2)

	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("key %d: order1=%q order2=%q", i, want[i], got[i])
		}
	}
}

func TestInsert_IdempotentUpdatesValue(t *testing.T) {
	r := New[string]()
	r.Insert("a", "v1")
	r.Insert("b", "v2")
	if r.Len() != 2 {
		t.Fatalf("Len=%d, want 2", r.Len())
	}

	r.Insert("a", "v1-updated")
	if r.Len() != 2 {
		t.Fatalf("Len=%d after re-Insert, want 2", r.Len())
	}

	// Find a key owned by "a", confirm it now sees the new value and
	// the old value is never returned anywhere.
	foundA := false
	for i := range 1000 {
		v, _ := r.Lookup(fmt.Sprintf("k%d", i))
		if v == "v1-updated" {
			foundA = true
		}
		if v == "v1" {
			t.Fatalf("key %d still returned old value v1", i)
		}
	}
	if !foundA {
		t.Fatalf("never observed updated value for member a")
	}
}

func TestRemove_Exact(t *testing.T) {
	r := New[string]()
	for _, m := range []string{"a", "b", "c"} {
		r.Insert(m, m)
	}
	r.Remove("b")
	if r.Len() != 2 {
		t.Fatalf("Len=%d, want 2", r.Len())
	}
	if _, ok := r.members["b"]; ok {
		t.Fatalf("member 'b' still in members map after Remove")
	}
	for i := range 1000 {
		v, ok := r.Lookup(fmt.Sprintf("k%d", i))
		if !ok || v == "b" {
			t.Fatalf("Lookup returned removed value: ok=%v v=%q", ok, v)
		}
	}
}

func TestRemove_AbsentIsNoOp(t *testing.T) {
	r := New[string]()
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
}

func TestNew_PanicsOnBadArgs(t *testing.T) {
	cases := []struct {
		name string
		call func()
	}{
		{"nil hash", func() { _ = New[string](WithHash(nil)) }},
		{"nil hash with options", func() { _ = New[string](WithHash(nil), WithHash(nil)) }},
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
	r := New[backend]()
	r.Insert("a", backend{addr: "10.0.0.1", port: 80})
	r.Insert("b", backend{addr: "10.0.0.2", port: 80})
	v, ok := r.Lookup("some-key")
	if !ok {
		t.Fatalf("ok=false")
	}
	if v.port != 80 {
		t.Fatalf("got %+v", v)
	}
}

// TestRemove_OnlyMovesOwnedKeys is the headline rendezvous property,
// strictly stronger than the ring's: after removing M, every key whose
// owner was not M keeps the EXACT same owner (zero collateral
// movement), and every key M used to own moves to some survivor.
func TestRemove_OnlyMovesOwnedKeys(t *testing.T) {
	const N = 8
	const keys = 10000

	r := New[string]()
	for i := range N {
		m := fmt.Sprintf("m%d", i)
		r.Insert(m, m)
	}

	before := make([]string, keys)
	for i := range before {
		before[i], _ = r.Lookup(fmt.Sprintf("k-%d", i))
	}

	r.Remove("m3")

	for i := range before {
		after, _ := r.Lookup(fmt.Sprintf("k-%d", i))
		if before[i] == "m3" {
			if after == "m3" {
				t.Fatalf("key %d still owned by removed m3", i)
			}
		} else if after != before[i] {
			t.Fatalf("key %d not owned by removed member moved: before=%q after=%q",
				i, before[i], after)
		}
	}
}

// TestInsert_OnlyStealsKeys is the symmetric property: adding a member
// only reassigns keys TO the newcomer; no key moves between two
// incumbents.
func TestInsert_OnlyStealsKeys(t *testing.T) {
	const N = 8
	const keys = 10000

	r := New[string]()
	for i := range N {
		m := fmt.Sprintf("m%d", i)
		r.Insert(m, m)
	}

	before := make([]string, keys)
	for i := range before {
		before[i], _ = r.Lookup(fmt.Sprintf("k-%d", i))
	}

	r.Insert("newcomer", "newcomer")

	for i := range before {
		after, _ := r.Lookup(fmt.Sprintf("k-%d", i))
		if after != before[i] && after != "newcomer" {
			t.Fatalf("key %d moved between incumbents: before=%q after=%q",
				i, before[i], after)
		}
	}
}

func TestRemovalMovesRoughlyOneOverN(t *testing.T) {
	const N = 8
	const keys = 10000

	r := New[string]()
	for i := range N {
		m := fmt.Sprintf("m%d", i)
		r.Insert(m, m)
	}

	before := make([]string, keys)
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

	frac := float64(moved) / float64(keys)
	lower := 0.5 / float64(N)
	upper := 2.0 / float64(N)
	if frac < lower || frac > upper {
		t.Fatalf("moved fraction %.3f not in [%.3f, %.3f]", frac, lower, upper)
	}
}

func TestDistribution_RoughlyEven(t *testing.T) {
	const M = 10
	const keys = 10000

	r := New[string]()
	for i := range M {
		m := fmt.Sprintf("m%d", i)
		r.Insert(m, m)
	}

	counts := make(map[string]int, M)
	for i := range keys {
		v, _ := r.Lookup(fmt.Sprintf("probe-%d", i))
		counts[v]++
	}

	if len(counts) != M {
		t.Fatalf("only %d members received any keys", len(counts))
	}
	// Loose regression bound. HRW is naturally even (expected 0.1
	// each), so this is a wide guard rather than a quality metric.
	for m, c := range counts {
		frac := float64(c) / float64(keys)
		if frac < 0.05 || frac > 0.20 {
			t.Errorf("member %s owns %.3f of keys (want 0.05..0.20)", m, frac)
		}
	}
}

// TestLookup_HighestScoreWins pins per-member scores via a stub hash
// and asserts the member with the highest score is returned.
func TestLookup_HighestScoreWins(t *testing.T) {
	const key = "the-key"
	scores := map[string]uint64{
		combinedKey("alpha", key):   100,
		combinedKey("bravo", key):   300, // highest -> winner
		combinedKey("charlie", key): 200,
	}
	stub := func(b []byte) uint64 {
		v, ok := scores[string(b)]
		if !ok {
			t.Fatalf("unexpected hash input %q", b)
		}
		return v
	}
	r := New[string](WithHash(stub))
	for _, m := range []string{"alpha", "bravo", "charlie"} {
		r.Insert(m, m)
	}
	v, ok := r.Lookup(key)
	if !ok || v != "bravo" {
		t.Fatalf("got (%q, %v), want (bravo, true)", v, ok)
	}
}

func TestHashCollision_TiebreakIsKeyOrder(t *testing.T) {
	// Hash always returns 0: every member ties on every key, so
	// ownership must depend only on member key (the lexicographically
	// smaller wins) and be independent of insertion order.
	constHash := func(_ []byte) uint64 { return 0 }
	mk := func(order []string) *Rendezvous[string] {
		r := New[string](WithHash(constHash))
		for _, m := range order {
			r.Insert(m, m)
		}
		return r
	}
	r1 := mk([]string{"alpha", "bravo", "charlie"})
	r2 := mk([]string{"charlie", "alpha", "bravo"})
	for i := range 100 {
		k := fmt.Sprintf("k%d", i)
		v1, _ := r1.Lookup(k)
		v2, _ := r2.Lookup(k)
		if v1 != v2 {
			t.Fatalf("collision tiebreak nondeterministic: %q vs %q", v1, v2)
		}
		// "alpha" is the lexicographically smallest member.
		if v1 != "alpha" {
			t.Fatalf("tiebreak winner=%q, want alpha (smallest key)", v1)
		}
	}
}

// TestCombinedHash_Injective guards the length prefix: without it,
// ("a","bc") and ("ab","c") would hash the same buffer. They must
// produce different scores.
func TestCombinedHash_Injective(t *testing.T) {
	r := New[string]()
	s1 := r.combinedHash("a", "bc")
	s2 := r.combinedHash("ab", "c")
	if s1 == s2 {
		t.Fatalf("combinedHash collided across the member/key boundary: %d", s1)
	}
}

func TestLookup_MatchesBruteForce(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	members := make([]string, 30)
	for i := range members {
		members[i] = fmt.Sprintf("member-%d-%d", i, rng.Uint32())
	}
	r := New[string]()
	for _, m := range members {
		r.Insert(m, m)
	}
	for i := range 5000 {
		k := fmt.Sprintf("probe-%d", i)
		got, ok := r.Lookup(k)
		if !ok {
			t.Fatalf("key %q: ok=false", k)
		}
		want := bruteForceLookup(defaultHash, members, k)
		if got != want {
			t.Fatalf("key %q: Lookup=%q bruteForce=%q", k, got, want)
		}
	}
}

func TestRank_Empty(t *testing.T) {
	r := New[string]()
	if got := r.Rank("anything"); got != nil {
		t.Fatalf("Rank on empty = %v, want nil", got)
	}
}

func TestRank_FirstEqualsLookup(t *testing.T) {
	r := New[string]()
	for _, m := range []string{"a", "b", "c", "d", "e"} {
		r.Insert(m, m)
	}
	for i := range 1000 {
		k := fmt.Sprintf("key-%d", i)
		order := r.Rank(k)
		if len(order) == 0 {
			t.Fatalf("key %q: empty rank", k)
		}
		want, _ := r.Lookup(k)
		if order[0] != want {
			t.Fatalf("key %q: Rank[0]=%q Lookup=%q", k, order[0], want)
		}
	}
}

func TestRank_IsPermutationOfMembers(t *testing.T) {
	members := []string{"a", "b", "c", "d", "e", "f", "g"}
	r := New[string]()
	for _, m := range members {
		r.Insert(m, m)
	}
	for i := range 500 {
		order := r.Rank(fmt.Sprintf("k-%d", i))
		if len(order) != len(members) {
			t.Fatalf("rank len=%d want %d", len(order), len(members))
		}
		seen := make(map[string]bool, len(order))
		for _, v := range order {
			if seen[v] {
				t.Fatalf("member %q appears twice in rank", v)
			}
			seen[v] = true
		}
		if len(seen) != len(members) {
			t.Fatalf("rank covered %d distinct members, want %d", len(seen), len(members))
		}
	}
}

// TestRank_MatchesBruteForceOrder cross-checks the whole ordering, not
// just the head, against an independent score-sorted list.
func TestRank_MatchesBruteForceOrder(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	members := make([]string, 20)
	for i := range members {
		members[i] = fmt.Sprintf("member-%d-%d", i, rng.Uint32())
	}
	r := New[string]()
	for _, m := range members {
		r.Insert(m, m)
	}
	for i := range 1000 {
		k := fmt.Sprintf("probe-%d", i)
		got := r.Rank(k)
		want := bruteForceRank(defaultHash, members, k)
		if len(got) != len(want) {
			t.Fatalf("key %q: len got=%d want=%d", k, len(got), len(want))
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("key %q: rank[%d] got=%q want=%q", k, j, got[j], want[j])
			}
		}
	}
}

// TestRank_StableUnderRemoval is the property that makes Rank usable
// as a failover list: removing a member yields the same order with
// that member deleted — survivors never reorder relative to each
// other.
func TestRank_StableUnderRemoval(t *testing.T) {
	members := []string{"a", "b", "c", "d", "e", "f"}
	r := New[string]()
	for _, m := range members {
		r.Insert(m, m)
	}
	for i := range 500 {
		k := fmt.Sprintf("node-%d", i)
		before := r.Rank(k)

		r.Remove("c")
		after := r.Rank(k)
		r.Insert("c", "c") // restore for the next iteration

		// after must equal before with "c" filtered out, same order.
		want := make([]string, 0, len(before))
		for _, v := range before {
			if v != "c" {
				want = append(want, v)
			}
		}
		if len(after) != len(want) {
			t.Fatalf("key %q: len after=%d want=%d", k, len(after), len(want))
		}
		for j := range want {
			if after[j] != want[j] {
				t.Fatalf("key %q: survivor order changed at %d: %q vs %q",
					k, j, after[j], want[j])
			}
		}
	}
}

// TestRank_FallbackSpreadsEvenly checks that not just the primary
// (rank 0) but the first fallback (rank 1) is balanced across members
// — i.e. load stays even when nodes fail over to their second choice.
func TestRank_FallbackSpreadsEvenly(t *testing.T) {
	const M = 10
	const keys = 10000
	r := New[string]()
	for i := range M {
		m := fmt.Sprintf("m%d", i)
		r.Insert(m, m)
	}
	counts := make(map[string]int, M)
	for i := range keys {
		order := r.Rank(fmt.Sprintf("probe-%d", i))
		counts[order[1]]++ // first fallback
	}
	if len(counts) != M {
		t.Fatalf("only %d members ever appeared as first fallback", len(counts))
	}
	for m, c := range counts {
		frac := float64(c) / float64(keys)
		if frac < 0.05 || frac > 0.20 {
			t.Errorf("member %s is first fallback for %.3f of keys (want 0.05..0.20)", m, frac)
		}
	}
}

func TestRank_Deterministic_IndependentOfInsertionOrder(t *testing.T) {
	r1 := New[string]()
	for _, m := range []string{"a", "b", "c", "d", "e"} {
		r1.Insert(m, m)
	}
	r2 := New[string]()
	for _, m := range []string{"e", "c", "a", "d", "b"} {
		r2.Insert(m, m)
	}
	for i := range 500 {
		k := fmt.Sprintf("k-%d", i)
		o1, o2 := r1.Rank(k), r2.Rank(k)
		for j := range o1 {
			if o1[j] != o2[j] {
				t.Fatalf("key %q rank[%d]: order1=%q order2=%q", k, j, o1[j], o2[j])
			}
		}
	}
}

func FuzzRendezvous(f *testing.F) {
	f.Add(uint64(1), uint64(2))
	f.Add(uint64(42), uint64(99))
	f.Add(uint64(0), uint64(0))
	f.Add(uint64(7), uint64(8))

	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
		rng := rand.New(rand.NewPCG(seed1, seed2))
		r := New[string]()
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

			// Invariants after every op.
			if r.Len() != len(r.members) {
				t.Fatalf("Len()=%d members=%d", r.Len(), len(r.members))
			}

			query := fmt.Sprintf("q-%d", op)
			v1, ok1 := r.Lookup(query)
			v2, ok2 := r.Lookup(query)
			if v1 != v2 || ok1 != ok2 {
				t.Fatalf("Lookup not repeatable: (%q,%v) vs (%q,%v)", v1, ok1, v2, ok2)
			}
			if ok1 != (len(r.members) > 0) {
				t.Fatalf("ok=%v but members=%d", ok1, len(r.members))
			}
			if ok1 {
				if _, present := r.members[keyOfValue(v1)]; !present {
					t.Fatalf("Lookup returned value %q not backed by a live member", v1)
				}
				// Cross-check against brute force over the live set.
				live := make([]string, 0, len(r.members))
				for m := range r.members {
					live = append(live, m)
				}
				want := bruteForceLookup(defaultHash, live, query)
				if keyOfValue(v1) != want {
					t.Fatalf("Lookup winner=%q bruteForce=%q", keyOfValue(v1), want)
				}

				// Rank must be a permutation of the live members in
				// brute-force order, and its head must agree with
				// Lookup.
				order := r.Rank(query)
				if len(order) != len(live) {
					t.Fatalf("Rank len=%d live=%d", len(order), len(live))
				}
				if order[0] != v1 {
					t.Fatalf("Rank[0]=%q Lookup=%q", order[0], v1)
				}
				wantOrder := bruteForceRank(defaultHash, live, query)
				for j := range wantOrder {
					if keyOfValue(order[j]) != wantOrder[j] {
						t.Fatalf("Rank[%d]=%q bruteForce=%q", j, keyOfValue(order[j]), wantOrder[j])
					}
				}
			}
		}
	})
}

// keyOfValue inverts the "k -> k+\"-v\"" mapping the fuzz test stores,
// recovering the member key from a returned value.
func keyOfValue(v string) string {
	return v[:len(v)-len("-v")]
}

func BenchmarkLookup(b *testing.B) {
	for _, n := range []int{10, 50, 1000} {
		b.Run(fmt.Sprintf("N%d", n), func(b *testing.B) {
			r := New[string]()
			for i := range n {
				m := fmt.Sprintf("member-%d", i)
				r.Insert(m, m)
			}
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				_, _ = r.Lookup(fmt.Sprintf("benchmark-key-%d", i))
			}
		})
	}
}

func BenchmarkRank(b *testing.B) {
	for _, n := range []int{10, 50, 1000} {
		b.Run(fmt.Sprintf("N%d", n), func(b *testing.B) {
			r := New[string]()
			for i := range n {
				m := fmt.Sprintf("member-%d", i)
				r.Insert(m, m)
			}
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				_ = r.Rank(fmt.Sprintf("benchmark-key-%d", i))
			}
		})
	}
}

func BenchmarkInsert(b *testing.B) {
	r := New[string]()
	i := 0
	for b.Loop() {
		k := fmt.Sprintf("member-%d", i%1000)
		r.Insert(k, k)
		i++
	}
}

func BenchmarkRemove(b *testing.B) {
	r := New[string]()
	for i := range 1000 {
		m := fmt.Sprintf("member-%d", i)
		r.Insert(m, m)
	}
	b.ResetTimer()
	i := 0
	for b.Loop() {
		k := fmt.Sprintf("member-%d", i%1000)
		b.StopTimer()
		r.Insert(k, k)
		b.StartTimer()
		r.Remove(k)
		i++
	}
}
