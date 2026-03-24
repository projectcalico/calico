// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package uniquelabels

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/maphash"
	"reflect"
	"sync"
	"testing"
	"unsafe"

	"github.com/projectcalico/calico/lib/std/uniquestr"
)

// unsafeTestOnlyReset resets the global key table and cache to their
// initial (empty) state.  It must only be called from tests and is NOT
// safe for concurrent use; the caller must ensure no other goroutine is
// calling Make or reading Maps at the same time.
//
// Maps created before a reset become invalid: their compact bitfields
// reference positions from the old key table, so read operations on those
// Maps will return incorrect results.
func unsafeTestOnlyReset() {
	unsafeTestOnlyResetKeyTable()
	unsafeTestOnlyResetCache()
}

func unsafeTestOnlyResetCache() {
	recentCache.entries = [recentMapCacheSize]recentMapCacheEntry{}
}

func unsafeTestOnlyResetKeyTable() {
	globalKeyTable = keyTable{}
	globalKeyTable.snap.Store(&keyTableSnap{
		byHandle: make(map[uniquestr.Handle]uint8),
	})
}

func TestInternedLabelsJSONRoundTrip(t *testing.T) {
	unsafeTestOnlyReset()
	for _, m := range []map[string]string{
		nil,
		{},
		{"foo": "bar", "bar": "baz"},
	} {
		t.Run(fmt.Sprint(m), func(t *testing.T) {
			j, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}

			in := Make(m)
			j2, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}

			// Both encodings sort keys, so byte-exact comparison is valid.
			if !bytes.Equal(j, j2) {
				t.Errorf("Interned map should produce same JSON as normal map; got %s, want %s", j2, j)
			}

			var out Map
			err = json.Unmarshal(j2, &out)
			if err != nil {
				t.Fatal(err)
			}
			if !in.Equals(out) {
				t.Errorf("Interned map didn't round trip. Got %v, want %v", out, in)
			}
		})
	}
}

func TestUnmarshalBadJSON(t *testing.T) {
	var out Map
	err := json.Unmarshal([]byte("[]"), &out)
	if err == nil {
		t.Errorf("Unmarshal didn't fail on invalid JSON")
	}
}

func TestGetString(t *testing.T) {
	unsafeTestOnlyReset()
	m := Make(map[string]string{"a": "b", "c": "d"})

	v, ok := m.GetString("a")
	if !ok || v != "b" {
		t.Errorf("GetString(\"a\") didn't return \"b\"")
	}
	v, ok = m.GetString("c")
	if !ok || v != "d" {
		t.Errorf("GetString(\"c\") didn't return \"d\"")
	}
	v, ok = m.GetString("foo")
	if ok || v != "" {
		t.Errorf("GetString(\"foo\") didn't return nil, false")
	}
}

func TestAllStrings(t *testing.T) {
	unsafeTestOnlyReset()
	input := map[string]string{"a": "b", "c": "d"}
	m := Make(input)
	seen := map[string]string{}
	for k, v := range m.AllStrings() {
		if _, ok := seen[k]; ok {
			t.Errorf("AllStrings returned duplicate key %q", k)
		}
		seen[k] = v
	}
	if !reflect.DeepEqual(seen, input) {
		t.Errorf("AllStrings didn't produce same map; got %v, want %v", seen, input)
	}

	// Check that break is properly handled.
	for range m.AllStrings() {
		break
	}
}

func TestAllHandles(t *testing.T) {
	unsafeTestOnlyReset()
	input := map[string]string{"a": "b", "c": "d"}
	m := Make(input)
	seen := map[string]string{}
	for k, v := range m.AllHandles() {
		if _, ok := seen[k.Value()]; ok {
			t.Errorf("AllStrings returned duplicate key %q", k.Value())
		}
		seen[k.Value()] = v.Value()
	}
	if !reflect.DeepEqual(seen, input) {
		t.Errorf("AllHandles didn't produce same map; got %v, want %v", seen, input)
	}

	// Check that break is properly handled.
	for range m.AllHandles() {
		break
	}
}

func sameBackingPtr(a, b Map) bool {
	return a.ptr == b.ptr
}

func TestMakeCacheHit(t *testing.T) {
	unsafeTestOnlyReset()
	input := map[string]string{"a": "b", "c": "d"}

	m1 := Make(input)
	m2 := Make(input)

	// Both calls should return the same underlying allocation from the cache.
	if !sameBackingPtr(m1, m2) {
		t.Errorf("expected Make to return cached Map on repeat call")
	}
}

func TestMakeCacheMiss(t *testing.T) {
	unsafeTestOnlyReset()
	m1 := Make(map[string]string{"a": "b"})
	m2 := Make(map[string]string{"x": "y"})

	if sameBackingPtr(m1, m2) {
		t.Errorf("different inputs should produce different Map instances")
	}
}

func TestMakeCacheEviction(t *testing.T) {
	unsafeTestOnlyReset()
	// Use a private cache so we don't interfere with other tests.
	c := recentMapCache{seed: maphash.MakeSeed()}

	input1 := map[string]string{"a": "b"}
	input2 := map[string]string{"x": "y"}

	// Force both inputs into the same slot by computing their hashes and
	// using Store directly.
	hash1 := c.hashMapStringString(input1)
	m1 := Make(input1)
	c.Store(hash1, m1)

	// Verify it's cached.
	cached, _, ok := c.Lookup(input1)
	if !ok {
		t.Fatal("expected cache hit for input1")
	}
	if !sameBackingPtr(cached, m1) {
		t.Fatal("cached map should be the same instance")
	}

	// Overwrite the same slot with a different entry that has the same
	// index (we force this by using the same hash value).
	m2 := Make(input2)
	c.Store(hash1, m2) // Same hash => same slot, evicts input1.

	// input1 should now miss.
	_, _, ok = c.Lookup(input1)
	if ok {
		t.Error("expected cache miss for input1 after eviction")
	}

	// input2 won't hit either because the stored hash doesn't match
	// input2's real hash (we used hash1). That's fine — this tests that
	// the old entry was evicted.
}

func TestMakeCacheHashCollision(t *testing.T) {
	unsafeTestOnlyReset()
	// Two different inputs that are forced into the same cache slot
	// should still return correct (different) results from Make.
	// We can't easily force a natural collision, but we can verify
	// that Make returns correct values regardless of cache state.
	inputs := make([]map[string]string, recentMapCacheSize+1)
	for i := range inputs {
		inputs[i] = map[string]string{"key": fmt.Sprintf("value-%d", i)}
	}

	// Fill the cache beyond capacity to force collisions.
	results := make([]Map, len(inputs))
	for i, input := range inputs {
		results[i] = Make(input)
	}

	// Every result should have the correct content regardless of cache state.
	for i, input := range inputs {
		if !results[i].EquivalentTo(input) {
			t.Errorf("Make result %d has wrong content", i)
		}
	}
}

func TestMakeCacheConcurrent(t *testing.T) {
	unsafeTestOnlyReset()
	const goroutines = 16
	const iterations = 1000
	inputs := []map[string]string{
		{"a": "1"},
		{"b": "2"},
		{"c": "3"},
		{"a": "1", "b": "2"},
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for i := range iterations {
				input := inputs[i%len(inputs)]
				m := Make(input)
				if !m.EquivalentTo(input) {
					t.Errorf("concurrent Make returned wrong content")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestEquivalentTo(t *testing.T) {
	unsafeTestOnlyReset()
	for _, tc := range []struct {
		name     string
		mapInput map[string]string
		compare  map[string]string
		want     bool
	}{
		{"equal", map[string]string{"a": "b"}, map[string]string{"a": "b"}, true},
		{"different value", map[string]string{"a": "b"}, map[string]string{"a": "x"}, false},
		{"extra key", map[string]string{"a": "b"}, map[string]string{"a": "b", "c": "d"}, false},
		{"missing key", map[string]string{"a": "b", "c": "d"}, map[string]string{"a": "b"}, false},
		{"both empty", map[string]string{}, map[string]string{}, true},
		{"empty vs non-empty", map[string]string{}, map[string]string{"a": "b"}, false},
		{"both nil", nil, nil, true},
		{"nil vs empty", nil, map[string]string{}, false},
		{"empty vs nil", map[string]string{}, nil, false},
		{"nil vs non-empty", nil, map[string]string{"a": "b"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Make(tc.mapInput)
			got := m.EquivalentTo(tc.compare)
			if got != tc.want {
				t.Errorf("Make(%v).EquivalentTo(%v) = %v, want %v", tc.mapInput, tc.compare, got, tc.want)
			}
		})
	}
}

func TestIntersectAndFilter(t *testing.T) {
	unsafeTestOnlyReset()
	for _, tc := range []struct {
		description      string
		m1, m2, expected map[string]string
		filter           func(uniquestr.Handle, uniquestr.Handle) bool
	}{
		{
			description: "nil with empty",
			m1:          nil,
			m2:          map[string]string{},
			expected:    nil,
		},
		{
			description: "empty with empty",
			m1:          map[string]string{},
			m2:          map[string]string{},
			expected:    map[string]string{},
		},
		{
			description: "empty with a:b",
			m1:          map[string]string{},
			m2:          map[string]string{"a": "b"},
			expected:    map[string]string{},
		},
		{
			description: "a:b with a:b",
			m1:          map[string]string{"a": "b"},
			m2:          map[string]string{"a": "b"},
			expected:    map[string]string{"a": "b"},
		},
		{
			description: "a:b with c:d",
			m1:          map[string]string{"a": "b"},
			m2:          map[string]string{"c": "d"},
			expected:    map[string]string{},
		},
		{
			description: "a:b with a:b c:d",
			m1:          map[string]string{"a": "b"},
			m2:          map[string]string{"a": "b", "c": "d"},
			expected:    map[string]string{"a": "b"},
		},
		{
			description: "a:b c:d with a:b c:e",
			m1:          map[string]string{"a": "b", "c": "d"},
			m2:          map[string]string{"a": "b", "c": "e"},
			expected:    map[string]string{"a": "b"},
		},
		{
			description: "a:b with a:b c:d filter on a",
			m1:          map[string]string{"a": "b", "c": "d"},
			m2:          map[string]string{"a": "b", "c": "d"},
			expected:    map[string]string{"a": "b"},
			filter: func(h uniquestr.Handle, _ uniquestr.Handle) bool {
				return h.Value() == "a"
			},
		},
		{
			description: "a:b with a:b c:d filter on c",
			m1:          map[string]string{"a": "b", "c": "d"},
			m2:          map[string]string{"a": "b", "c": "d"},
			expected:    map[string]string{"c": "d"},
			filter: func(h uniquestr.Handle, _ uniquestr.Handle) bool {
				return h.Value() == "c"
			},
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			um1 := Make(tc.m1)
			um2 := Make(tc.m2)
			out := IntersectAndFilter(um1, um2, tc.filter).RecomputeOriginalMap()
			if !reflect.DeepEqual(out, tc.expected) {
				t.Fatalf("IntersectAndFilter(%v,%v) returned unexpected result; got %v, want %v",
					tc.m1, tc.m2, out, tc.expected)
			}

			out = IntersectAndFilter(um2, um1, tc.filter).RecomputeOriginalMap()
			if !reflect.DeepEqual(out, tc.expected) {
				t.Errorf("IntersectAndFilter(%v,%v) returned unexpected result; got %v, want %v",
					tc.m2, tc.m1, out, tc.expected)
			}
		})
	}
}

// ---- Tests specific to the compact representation ----

func TestCompactRepresentation(t *testing.T) {
	unsafeTestOnlyReset()
	// Make should use the compact representation for maps whose keys
	// fit in the global key table.
	m := Make(map[string]string{"alpha": "1", "beta": "2"})
	if !m.isCompact() {
		t.Fatal("expected compact representation")
	}
	if m.Len() != 2 {
		t.Errorf("Len() = %d, want 2", m.Len())
	}
	v, ok := m.GetString("alpha")
	if !ok || v != "1" {
		t.Errorf("GetString(alpha) = %q, %v; want 1, true", v, ok)
	}
	v, ok = m.GetString("beta")
	if !ok || v != "2" {
		t.Errorf("GetString(beta) = %q, %v; want 2, true", v, ok)
	}
	_, ok = m.GetString("gamma")
	if ok {
		t.Error("GetString(gamma) should return false")
	}
}

func TestCompactEmptyIsCompact(t *testing.T) {
	if !Empty.isCompact() {
		t.Error("Empty should use compact representation")
	}
	if Empty.Len() != 0 {
		t.Errorf("Empty.Len() = %d, want 0", Empty.Len())
	}
}

func TestCompactEqualsRegular(t *testing.T) {
	unsafeTestOnlyReset()
	// A compact map and a fallback map with the same content should be
	// equal.
	input := map[string]string{"p": "q", "r": "s"}
	compact := Make(input)
	if !compact.isCompact() {
		t.Fatal("expected compact representation after reset")
	}

	fb := makeFallback(input)

	if !compact.Equals(fb) {
		t.Error("compact and fallback with same content should be equal")
	}
	if !fb.Equals(compact) {
		t.Error("fallback and compact with same content should be equal")
	}
}

func TestCompactManyKeys(t *testing.T) {
	unsafeTestOnlyReset()
	// Create a map with many keys and verify the compact representation.
	input := make(map[string]string, 30)
	for i := range 30 {
		input[fmt.Sprintf("key-%d", i)] = fmt.Sprintf("val-%d", i)
	}
	m := Make(input)
	if !m.isCompact() {
		t.Fatal("expected compact representation for 30-key map")
	}
	if m.Len() != 30 {
		t.Errorf("Len() = %d, want 30", m.Len())
	}
	if !m.EquivalentTo(input) {
		t.Errorf("map content mismatch")
	}
}

func TestNilAndEmptySemantics(t *testing.T) {
	if !Nil.IsNil() {
		t.Error("Nil.IsNil() should be true")
	}
	if Empty.IsNil() {
		t.Error("Empty.IsNil() should be false")
	}
	if Nil.Len() != 0 {
		t.Errorf("Nil.Len() = %d, want 0", Nil.Len())
	}
	if Empty.Len() != 0 {
		t.Errorf("Empty.Len() = %d, want 0", Empty.Len())
	}

	// Nil and Empty should compare equal (matches maps.Equal behavior).
	if !Nil.Equals(Empty) {
		t.Error("Nil should equal Empty")
	}
	if !Empty.Equals(Nil) {
		t.Error("Empty should equal Nil")
	}

	// But EquivalentTo distinguishes nil from empty.
	if Nil.EquivalentTo(map[string]string{}) {
		t.Error("Nil should not be equivalent to empty map")
	}
	if Empty.EquivalentTo(nil) {
		t.Error("Empty should not be equivalent to nil")
	}
}

func TestIntersectAndFilterReturnsCompact(t *testing.T) {
	unsafeTestOnlyReset()
	a := Make(map[string]string{"x": "1", "y": "2", "z": "3"})
	b := Make(map[string]string{"x": "1", "z": "3"})
	if !a.isCompact() || !b.isCompact() {
		t.Fatal("expected compact representation after reset")
	}

	// Intersection of a ∩ b should be {x:1, z:3} and compact.
	result := IntersectAndFilter(a, b, nil)
	if !result.isCompact() {
		t.Error("IntersectAndFilter should return compact map when input is compact")
	}
	if !result.EquivalentTo(map[string]string{"x": "1", "z": "3"}) {
		t.Errorf("wrong content: %v", result)
	}

	// With a filter that excludes "x", result should be {z:3} and compact.
	result = IntersectAndFilter(a, b, func(k uniquestr.Handle, _ uniquestr.Handle) bool {
		return k.Value() != "x"
	})
	if !result.isCompact() {
		t.Error("filtered IntersectAndFilter should return compact map")
	}
	if !result.EquivalentTo(map[string]string{"z": "3"}) {
		t.Errorf("wrong content: %v", result)
	}

	// Intersection that yields empty should return Empty (compact).
	result = IntersectAndFilter(a, b, func(uniquestr.Handle, uniquestr.Handle) bool {
		return false
	})
	if !result.isCompact() {
		t.Error("empty IntersectAndFilter result should be compact (Empty)")
	}
	if result.Len() != 0 {
		t.Error("expected empty result")
	}
}

func TestCompactEqualsOptimization(t *testing.T) {
	unsafeTestOnlyReset()
	input := map[string]string{"eq-a": "1", "eq-b": "2"}
	m1 := Make(input)
	// Build a second Map via mapBuilder directly to bypass the cache,
	// ensuring the test exercises the compact value-comparison path
	// rather than returning early via pointer equality.
	var buf [maxKeyTableSize]kvHandle
	b := mapBuilder(buf[:0])
	for k, v := range input {
		b = append(b, kvHandle{uniquestr.Make(k), uniquestr.Make(v)})
	}
	m2 := b.build()
	m3 := Make(map[string]string{"eq-a": "1", "eq-b": "99"})
	m4 := Make(map[string]string{"eq-a": "1"})
	if !m1.isCompact() || !m2.isCompact() || !m3.isCompact() || !m4.isCompact() {
		t.Fatal("expected compact representation after reset")
	}
	if m1.ptr == m2.ptr {
		t.Fatal("m1 and m2 should be distinct allocations to test the compact comparison path")
	}

	// Same content, distinct allocations → equal via compact comparison.
	if !m1.Equals(m2) {
		t.Error("identical compact maps should be equal")
	}
	// Same keys, different values → not equal.
	if m1.Equals(m3) {
		t.Error("compact maps with different values should not be equal")
	}
	// Different key sets → not equal (bitfield mismatch).
	if m1.Equals(m4) {
		t.Error("compact maps with different key sets should not be equal")
	}
}

func TestUnmarshalJSONProducesCompact(t *testing.T) {
	unsafeTestOnlyReset()
	// UnmarshalJSON goes through Make, which registers keys.
	// No pre-registration needed.
	data := []byte(`{"jk1":"x","jk2":"y"}`)
	var m Map
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if !m.isCompact() {
		t.Error("UnmarshalJSON should produce compact map")
	}
	if !m.EquivalentTo(map[string]string{"jk1": "x", "jk2": "y"}) {
		t.Errorf("wrong content: %v", m)
	}
}

func TestKeyTableConcurrent(t *testing.T) {
	unsafeTestOnlyReset()
	// Concurrent Make calls with new keys should not race.
	const goroutines = 8
	const keysPerGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := range goroutines {
		go func() {
			defer wg.Done()
			input := make(map[string]string, keysPerGoroutine)
			for k := range keysPerGoroutine {
				input[fmt.Sprintf("conc-g%d-k%d", g, k)] = fmt.Sprintf("v%d", k)
			}
			m := Make(input)
			if !m.EquivalentTo(input) {
				t.Errorf("goroutine %d: Make returned wrong content", g)
			}
		}()
	}
	wg.Wait()
}

// ---- Tests for fallback representation ----

// fillKeyTable registers n unique dummy keys in the global key table,
// returning the number actually registered (capped at maxKeyTableSize).
func fillKeyTable(n int) int {
	for i := range n {
		m := map[string]string{fmt.Sprintf("fill-%d", i): "x"}
		result := Make(m)
		if !result.isCompact() {
			return i
		}
	}
	return min(n, maxKeyTableSize)
}

func TestFallbackMoreThan63Keys(t *testing.T) {
	unsafeTestOnlyReset()
	// A single map with 64 keys cannot fit in the 63-bit bitfield.
	input := make(map[string]string, 64)
	for i := range 64 {
		input[fmt.Sprintf("k%d", i)] = fmt.Sprintf("v%d", i)
	}
	m := Make(input)
	if m.isCompact() {
		t.Fatal("64-key map should use fallback representation")
	}
	if m.Len() != 64 {
		t.Errorf("Len() = %d, want 64", m.Len())
	}
	if !m.EquivalentTo(input) {
		t.Error("fallback map content mismatch")
	}
}

func TestFallbackTableFull(t *testing.T) {
	unsafeTestOnlyReset()
	// Fill all 63 slots with known keys.
	fillKeyTable(maxKeyTableSize)

	// A small map whose keys are all new should fall back because
	// there are no slots left.
	input := map[string]string{"brand-new-a": "1", "brand-new-b": "2"}
	m := Make(input)
	if m.isCompact() {
		t.Fatal("expected fallback when key table is full and keys are new")
	}
	if !m.EquivalentTo(input) {
		t.Error("fallback map content mismatch")
	}
}

func TestFallbackTableFullOneNewKey(t *testing.T) {
	unsafeTestOnlyReset()
	// Fill all 63 slots.
	fillKeyTable(maxKeyTableSize)

	// Build a map where one key is already known and one is not.
	// The unknown key can't be registered, so the whole map falls back.
	input := map[string]string{"fill-0": "reused", "never-seen": "new"}
	m := Make(input)
	if m.isCompact() {
		t.Fatal("expected fallback when table is full and map has one unknown key")
	}
	if !m.EquivalentTo(input) {
		t.Error("fallback map content mismatch")
	}

	// A map using only already-known keys should still be compact.
	known := map[string]string{"fill-0": "a", "fill-1": "b"}
	mk := Make(known)
	if !mk.isCompact() {
		t.Fatal("expected compact for map using only known keys")
	}
	if !mk.EquivalentTo(known) {
		t.Error("compact map content mismatch")
	}
}

func TestFallbackReadOperations(t *testing.T) {
	unsafeTestOnlyReset()
	// Force a fallback by exceeding 63 keys.
	input := make(map[string]string, 64)
	for i := range 64 {
		input[fmt.Sprintf("fb-%d", i)] = fmt.Sprintf("v%d", i)
	}
	m := Make(input)
	if m.isCompact() {
		t.Fatal("expected fallback representation")
	}

	// GetString
	v, ok := m.GetString("fb-0")
	if !ok || v != "v0" {
		t.Errorf("GetString(fb-0) = %q, %v; want v0, true", v, ok)
	}
	_, ok = m.GetString("nonexistent")
	if ok {
		t.Error("GetString(nonexistent) should return false")
	}

	// AllStrings round-trip
	seen := make(map[string]string, m.Len())
	for k, v := range m.AllStrings() {
		seen[k] = v
	}
	if !reflect.DeepEqual(seen, input) {
		t.Error("AllStrings round-trip mismatch for fallback map")
	}
}

// ---- Cross-type (compact vs fallback) tests ----

// makeFallback creates a fallback Map by building a handleMap manually.
func makeFallback(m map[string]string) Map {
	if m == nil {
		return Nil
	}
	if len(m) == 0 {
		return Empty
	}
	hm := make(handleMap, len(m))
	for k, v := range m {
		hm[uniquestr.Make(k)] = uniquestr.Make(v)
	}
	return Map{ptr: unsafe.Pointer(&fallbackMap{m: hm})}
}

func TestCrossTypeEquals(t *testing.T) {
	unsafeTestOnlyReset()
	for _, tc := range []struct {
		name string
		a, b map[string]string
		want bool
	}{
		{"same content", map[string]string{"a": "1", "b": "2"}, map[string]string{"a": "1", "b": "2"}, true},
		{"different values", map[string]string{"a": "1"}, map[string]string{"a": "99"}, false},
		{"different keys", map[string]string{"a": "1"}, map[string]string{"z": "1"}, false},
		{"subset", map[string]string{"a": "1"}, map[string]string{"a": "1", "b": "2"}, false},
		{"superset", map[string]string{"a": "1", "b": "2"}, map[string]string{"a": "1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compact := Make(tc.a)
			fallback := makeFallback(tc.b)
			if compact.isCompact() == fallback.isCompact() {
				t.Fatalf("test setup error: both maps have the same representation (compact=%v)", compact.isCompact())
			}
			if got := compact.Equals(fallback); got != tc.want {
				t.Errorf("compact.Equals(fallback) = %v, want %v", got, tc.want)
			}
			if got := fallback.Equals(compact); got != tc.want {
				t.Errorf("fallback.Equals(compact) = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCrossTypeIntersectAndFilter(t *testing.T) {
	unsafeTestOnlyReset()
	for _, tc := range []struct {
		name         string
		a, b         map[string]string
		expected     map[string]string
		filter       func(uniquestr.Handle, uniquestr.Handle) bool
		aType, bType string // "compact" or "fallback"
	}{
		{
			name:     "compact ∩ fallback, full overlap",
			a:        map[string]string{"a": "1", "b": "2"},
			b:        map[string]string{"a": "1", "b": "2"},
			expected: map[string]string{"a": "1", "b": "2"},
			aType:    "compact", bType: "fallback",
		},
		{
			name:     "compact ∩ fallback, partial overlap",
			a:        map[string]string{"a": "1", "b": "2"},
			b:        map[string]string{"a": "1", "c": "3"},
			expected: map[string]string{"a": "1"},
			aType:    "compact", bType: "fallback",
		},
		{
			name:     "compact ∩ fallback, no overlap",
			a:        map[string]string{"a": "1"},
			b:        map[string]string{"z": "9"},
			expected: map[string]string{},
			aType:    "compact", bType: "fallback",
		},
		{
			name:     "fallback ∩ compact, full overlap",
			a:        map[string]string{"x": "10", "y": "20"},
			b:        map[string]string{"x": "10", "y": "20"},
			expected: map[string]string{"x": "10", "y": "20"},
			aType:    "fallback", bType: "compact",
		},
		{
			name:     "fallback ∩ compact, with filter",
			a:        map[string]string{"f1": "v1", "f2": "v2"},
			b:        map[string]string{"f1": "v1", "f2": "v2"},
			expected: map[string]string{"f1": "v1"},
			aType:    "fallback", bType: "compact",
			filter: func(k uniquestr.Handle, _ uniquestr.Handle) bool {
				return k.Value() == "f1"
			},
		},
		{
			name:     "compact ∩ fallback, same keys different values",
			a:        map[string]string{"k": "compact-val"},
			b:        map[string]string{"k": "fallback-val"},
			expected: map[string]string{},
			aType:    "compact", bType: "fallback",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var a, b Map
			if tc.aType == "compact" {
				a = Make(tc.a)
			} else {
				a = makeFallback(tc.a)
			}
			if tc.bType == "compact" {
				b = Make(tc.b)
			} else {
				b = makeFallback(tc.b)
			}

			// Verify types are as expected.
			if tc.aType == "compact" && !a.isCompact() {
				t.Fatal("expected a to be compact")
			}
			if tc.aType == "fallback" && a.isCompact() {
				t.Fatal("expected a to be fallback")
			}
			if tc.bType == "compact" && !b.isCompact() {
				t.Fatal("expected b to be compact")
			}
			if tc.bType == "fallback" && b.isCompact() {
				t.Fatal("expected b to be fallback")
			}

			out := IntersectAndFilter(a, b, tc.filter).RecomputeOriginalMap()
			if !reflect.DeepEqual(out, tc.expected) {
				t.Errorf("IntersectAndFilter(a,b) = %v, want %v", out, tc.expected)
			}
			// Reversed order should give the same result.
			out = IntersectAndFilter(b, a, tc.filter).RecomputeOriginalMap()
			if !reflect.DeepEqual(out, tc.expected) {
				t.Errorf("IntersectAndFilter(b,a) = %v, want %v", out, tc.expected)
			}
		})
	}
}

func TestFallbackFallbackIntersect(t *testing.T) {
	unsafeTestOnlyReset()
	a := makeFallback(map[string]string{"a": "1", "b": "2", "c": "3"})
	b := makeFallback(map[string]string{"b": "2", "c": "99", "d": "4"})
	if a.isCompact() || b.isCompact() {
		t.Fatal("expected both maps to be fallback")
	}

	// The intersection builder registers keys in the key table, so the
	// result is compact even when the inputs were fallback.
	result := IntersectAndFilter(a, b, nil)
	expected := map[string]string{"b": "2"}
	if !result.EquivalentTo(expected) {
		t.Errorf("fallback ∩ fallback = %v, want %v", result.RecomputeOriginalMap(), expected)
	}
}

func TestFallbackIntersectProducesCompactWhenPossible(t *testing.T) {
	unsafeTestOnlyReset()
	// Register keys "a" and "b" in the key table via Make.
	Make(map[string]string{"a": "x", "b": "x"})

	// Build fallback maps that use those registered keys.
	a := makeFallback(map[string]string{"a": "1", "b": "2", "c": "3"})
	b := makeFallback(map[string]string{"a": "1", "c": "99"})
	if a.isCompact() || b.isCompact() {
		t.Fatal("expected both inputs to be fallback")
	}

	// Intersection is {"a": "1"}. Key "a" is in the table, so the
	// result should be compact.
	result := IntersectAndFilter(a, b, nil)
	if !result.isCompact() {
		t.Error("expected compact result when all intersection keys are in the key table")
	}
	if !result.EquivalentTo(map[string]string{"a": "1"}) {
		t.Errorf("wrong content: %v", result)
	}
}

func TestAppendJSONStringMatchesStdlib(t *testing.T) {
	cases := []string{
		"",
		"simple",
		"with space",
		`with"quotes`,
		"with\\backslash",
		"with\nnewline",
		"with\ttab",
		"with\x00null",
		"with/slash",
		"emoji: \U0001F600",
		"unicode: café",
		"mixed: a\"b\\c\nd\te\x01f",
		"kubernetes.io/name",
		"example.com/label-key",
	}
	for _, s := range cases {
		got := string(appendJSONString(nil, s))
		want, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("json.Marshal(%q) failed: %v", s, err)
		}
		if got != string(want) {
			t.Errorf("appendJSONString(%q) = %s, want %s", s, got, want)
		}
	}
}

func FuzzAppendJSONString(f *testing.F) {
	f.Add("")
	f.Add("simple")
	f.Add(`with"quotes`)
	f.Add("with\\backslash")
	f.Add("with\nnewline")
	f.Add("with\ttab")
	f.Add("with\x00null")
	f.Add("emoji: \U0001F600")
	f.Add("unicode: café")
	f.Add("kubernetes.io/name")
	f.Fuzz(func(t *testing.T, s string) {
		got := string(appendJSONString(nil, s))
		want, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("json.Marshal(%q) failed: %v", s, err)
		}
		if got != string(want) {
			t.Errorf("appendJSONString(%q) = %s, want %s", s, got, want)
		}
	})
}

func BenchmarkMarshalJSON(b *testing.B) {
	const nKeys = 15
	input := make(map[string]string, nKeys)
	for i := range nKeys {
		input[fmt.Sprintf("example.com/label-%d", i)] = fmt.Sprintf("value-%d", i)
	}

	b.Run("compact", func(b *testing.B) {
		unsafeTestOnlyReset()
		m := Make(input)
		if !m.isCompact() {
			b.Fatal("expected compact representation")
		}
		b.ResetTimer()
		b.ReportAllocs()
		for range b.N {
			_, err := m.MarshalJSON()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("fallback", func(b *testing.B) {
		m := makeFallback(input)
		if m.isCompact() {
			b.Fatal("expected fallback representation")
		}
		b.ResetTimer()
		b.ReportAllocs()
		for range b.N {
			_, err := m.MarshalJSON()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkUnmarshalJSON(b *testing.B) {
	const nKeys = 15
	input := make(map[string]string, nKeys)
	for i := range nKeys {
		input[fmt.Sprintf("example.com/label-%d", i)] = fmt.Sprintf("value-%d", i)
	}
	unsafeTestOnlyReset()
	m := Make(input)
	data, _ := m.MarshalJSON()

	b.Run("cache-hit", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var m Map
			_ = m.UnmarshalJSON(data)
		}
	})

	b.Run("cache-miss", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			b.StopTimer()
			unsafeTestOnlyResetCache()
			b.StartTimer()
			var m Map
			_ = m.UnmarshalJSON(data)
		}
	})
}

func TestFallbackMarshalJSON(t *testing.T) {
	unsafeTestOnlyReset()
	input := map[string]string{"zz": "last", "aa": "first", "mm": "middle"}
	fb := makeFallback(input)
	if fb.isCompact() {
		t.Fatal("expected fallback representation")
	}

	got, err := json.Marshal(fb)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("fallback MarshalJSON = %s, want %s", got, want)
	}

	// Round-trip: unmarshal and check equivalence.
	var rt Map
	if err := json.Unmarshal(got, &rt); err != nil {
		t.Fatal(err)
	}
	if !rt.EquivalentTo(input) {
		t.Errorf("round-trip mismatch: got %v", rt)
	}
}

func TestFallbackFallbackEquals(t *testing.T) {
	unsafeTestOnlyReset()
	a := makeFallback(map[string]string{"x": "1", "y": "2"})
	b := makeFallback(map[string]string{"x": "1", "y": "2"})
	c := makeFallback(map[string]string{"x": "1", "y": "99"})
	if a.isCompact() || b.isCompact() || c.isCompact() {
		t.Fatal("expected fallback representations")
	}

	if !a.Equals(b) {
		t.Error("identical fallback maps should be equal")
	}
	if a.Equals(c) {
		t.Error("fallback maps with different values should not be equal")
	}
}

func BenchmarkMake(b *testing.B) {
	const nKeys = 15
	input := make(map[string]string, nKeys)
	for i := range nKeys {
		input[fmt.Sprintf("example.com/label-%d", i)] = fmt.Sprintf("value-%d", i)
	}

	b.Run("cache-hit", func(b *testing.B) {
		unsafeTestOnlyReset()
		Make(input) // Prime the cache.
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			Make(input)
		}
	})

	b.Run("cache-miss", func(b *testing.B) {
		unsafeTestOnlyReset()
		// Pre-register keys so miss path doesn't include key registration.
		Make(input)
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			// Use a fresh cache to guarantee a miss.
			b.StopTimer()
			unsafeTestOnlyResetCache()
			b.StartTimer()

			Make(input)
		}
	})
}

func BenchmarkIntersectAndFilter(b *testing.B) {
	const nKeys = 15
	all := make(map[string]string, nKeys)
	for i := range nKeys {
		all[fmt.Sprintf("example.com/label-%d", i)] = fmt.Sprintf("value-%d", i)
	}

	// Build a filter that excludes ~half the keys.
	excludeSet := make(map[string]bool, nKeys)
	i := 0
	for k := range all {
		if i%2 == 0 {
			excludeSet[k] = true
		}
		i++
	}
	halfFilter := func(k uniquestr.Handle, _ uniquestr.Handle) bool {
		return !excludeSet[k.Value()]
	}

	for _, tc := range []struct {
		name   string
		filter func(uniquestr.Handle, uniquestr.Handle) bool
		aType  string // "compact" or "fallback"
	}{
		{"compact/no-filter", nil, "compact"},
		{"compact/with-filter", halfFilter, "compact"},
		{"fallback/no-filter", nil, "fallback"},
		{"fallback/with-filter", halfFilter, "fallback"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			unsafeTestOnlyReset()
			var a Map
			if tc.aType == "compact" {
				a = Make(all)
			} else {
				a = makeFallback(all)
			}
			bMap := Make(all)
			b.ResetTimer()
			b.ReportAllocs()
			for range b.N {
				IntersectAndFilter(a, bMap, tc.filter)
			}
		})
	}
}
