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
	"reflect"
	"sync"
	"testing"
	"unsafe"

	"github.com/projectcalico/calico/lib/std/uniquestr"
)

func TestInternedLabelsJSONRoundTrip(t *testing.T) {
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

func sameUnderlyingMap(a, b Map) bool {
	return a.ptr == b.ptr
}

func TestMakeCacheHit(t *testing.T) {
	input := map[string]string{"a": "b", "c": "d"}

	m1 := Make(input)
	m2 := Make(input)

	// Both calls should return the same underlying allocation from the cache.
	if !sameUnderlyingMap(m1, m2) {
		t.Errorf("expected Make to return cached Map on repeat call")
	}
}

func TestMakeCacheMiss(t *testing.T) {
	m1 := Make(map[string]string{"a": "b"})
	m2 := Make(map[string]string{"x": "y"})

	if sameUnderlyingMap(m1, m2) {
		t.Errorf("different inputs should produce different Map instances")
	}
}

func TestMakeCacheEviction(t *testing.T) {
	// Use a private cache so we don't interfere with other tests.
	c := recentMapCache{seed: recentCache.seed}

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
	if !sameUnderlyingMap(cached, m1) {
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
	// A compact map and a fallback map with the same content should be
	// equal.
	input := map[string]string{"p": "q", "r": "s"}
	compact := Make(input)
	if !compact.isCompact() {
		t.Skip("map not compact (key table may be full)")
	}

	// Build a fallback map manually.
	hm := make(handleMap, len(input))
	for k, v := range input {
		hm[uniquestr.Make(k)] = uniquestr.Make(v)
	}
	fb := Map{ptr: unsafeFallback(hm)}

	if !compact.Equals(fb) {
		t.Error("compact and fallback with same content should be equal")
	}
	if !fb.Equals(compact) {
		t.Error("fallback and compact with same content should be equal")
	}
}

// unsafeFallback is a test helper to create a fallback Map.
func unsafeFallback(hm handleMap) unsafe.Pointer {
	return unsafe.Pointer(&fallbackMap{m: hm})
}

func TestCompactManyKeys(t *testing.T) {
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
	a := Make(map[string]string{"x": "1", "y": "2", "z": "3"})
	b := Make(map[string]string{"x": "1", "z": "3"})
	if !a.isCompact() || !b.isCompact() {
		t.Skip("inputs not compact")
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
	m1 := Make(map[string]string{"eq-a": "1", "eq-b": "2"})
	m2 := Make(map[string]string{"eq-a": "1", "eq-b": "2"})
	m3 := Make(map[string]string{"eq-a": "1", "eq-b": "99"})
	m4 := Make(map[string]string{"eq-a": "1"})
	if !m1.isCompact() || !m2.isCompact() || !m3.isCompact() || !m4.isCompact() {
		t.Skip("inputs not compact")
	}

	// Same content → equal.
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
	// First, ensure the keys are registered by calling Make.
	_ = Make(map[string]string{"jk1": "a", "jk2": "b"})

	data := []byte(`{"jk1":"x","jk2":"y"}`)
	var m Map
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if !m.isCompact() {
		t.Error("UnmarshalJSON should produce compact map when keys are known")
	}
	if !m.EquivalentTo(map[string]string{"jk1": "x", "jk2": "y"}) {
		t.Errorf("wrong content: %v", m)
	}
}

func TestKeyTableConcurrent(t *testing.T) {
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
