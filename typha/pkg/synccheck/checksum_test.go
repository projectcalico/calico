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

package synccheck

import (
	"math/rand"
	"testing"
)

// TestEntryDigest_GoldenVectors pins the per-entry digest for a handful of
// fixed inputs.  These values must never change without a protocol version
// bump: both ends of a Typha connection compute them independently and compare.
// If a refactor changes one of these, the wire format has changed.
func TestEntryDigest_GoldenVectors(t *testing.T) {
	// Computed with the reference implementation in this package.  Pinning them
	// guards against accidental changes to the digest construction (length
	// prefix, byte order, hash function).
	cases := []struct {
		key   string
		value string
		want  uint64
	}{
		{"", "", 0x34c96acdcadb1bbb},
		{"a", "", 0xbd1698eada10e1c3},
		{"", "a", 0xcb1a3b8dd9fbe162},
		{"ab", "c", 0x4b60798139549d1d},
		{"a", "bc", 0x414239d99b92288c},
	}

	for _, tc := range cases {
		got := EntryDigest(tc.key, []byte(tc.value))
		if got != tc.want {
			t.Errorf("EntryDigest(%q, %q) = %#x, want %#x", tc.key, tc.value, got, tc.want)
		}
	}
}

// TestEntryDigest_Deterministic verifies the digest is stable across calls.
func TestEntryDigest_Deterministic(t *testing.T) {
	for i := 0; i < 100; i++ {
		key := randString(rand.Intn(20))
		val := []byte(randString(rand.Intn(40)))
		a := EntryDigest(key, val)
		b := EntryDigest(key, val)
		if a != b {
			t.Fatalf("digest not deterministic for key=%q val=%q: %#x vs %#x", key, val, a, b)
		}
	}
}

// TestEntryDigest_LengthPrefixDisambiguates checks the length prefix prevents
// (key,value) pairs from aliasing under concatenation.
func TestEntryDigest_LengthPrefixDisambiguates(t *testing.T) {
	// "ab"+"c" and "a"+"bc" concatenate to the same bytes but must differ
	// because the key length is mixed in.
	if EntryDigest("ab", []byte("c")) == EntryDigest("a", []byte("bc")) {
		t.Fatal("length prefix failed to disambiguate key/value boundary")
	}
}

// TestChecksum_OrderIndependence verifies that adding the same set of entries
// in different orders yields the same checksum.
func TestChecksum_OrderIndependence(t *testing.T) {
	type kv struct {
		k string
		v string
	}
	entries := []kv{
		{"key-a", "value-1"},
		{"key-b", "value-2"},
		{"key-c", "value-3"},
		{"key-d", "value-4"},
	}

	var forward Checksum
	for _, e := range entries {
		forward.Add(e.k, []byte(e.v))
	}

	var reverse Checksum
	for i := len(entries) - 1; i >= 0; i-- {
		reverse.Add(entries[i].k, []byte(entries[i].v))
	}

	if forward != reverse {
		t.Fatalf("checksum depends on insertion order: %+v vs %+v", forward, reverse)
	}
}

// TestChecksum_AddRemoveRoundTrips verifies that removing every entry returns
// the checksum to the empty state.
func TestChecksum_AddRemoveRoundTrips(t *testing.T) {
	var c Checksum
	type kv struct {
		k string
		v string
	}
	entries := []kv{
		{"key-a", "value-1"},
		{"key-b", "value-2"},
		{"key-c", "value-3"},
	}
	for _, e := range entries {
		c.Add(e.k, []byte(e.v))
	}
	for _, e := range entries {
		c.Remove(e.k, []byte(e.v))
	}
	if (c != Checksum{}) {
		t.Fatalf("add/remove did not round-trip to empty: %+v", c)
	}
}

// TestChecksum_Replace verifies an in-place value change matches a
// remove-then-add and leaves KVCount unchanged.
func TestChecksum_Replace(t *testing.T) {
	var viaReplace Checksum
	viaReplace.Add("k", []byte("old"))
	viaReplace.Replace("k", []byte("old"), []byte("new"))

	var viaRemoveAdd Checksum
	viaRemoveAdd.Add("k", []byte("old"))
	viaRemoveAdd.Remove("k", []byte("old"))
	viaRemoveAdd.Add("k", []byte("new"))

	if viaReplace != viaRemoveAdd {
		t.Fatalf("Replace != Remove+Add: %+v vs %+v", viaReplace, viaRemoveAdd)
	}
	if viaReplace.KVCount != 1 {
		t.Fatalf("Replace changed KVCount: got %d, want 1", viaReplace.KVCount)
	}
}

// TestChecksum_Property runs a random sequence of insert/clobber/delete
// operations against an incremental checksum and against a ground-truth map,
// asserting that the rolling checksum always equals a recompute-from-scratch.
func TestChecksum_Property(t *testing.T) {
	const numKeys = 50
	const numOps = 5000

	rng := rand.New(rand.NewSource(42))
	keys := make([]string, numKeys)
	for i := range keys {
		keys[i] = randStringRNG(rng, 5)
	}

	// Ground truth: the current live value for each key (nil == absent).
	truth := map[string][]byte{}
	var rolling Checksum

	recompute := func() Checksum {
		var c Checksum
		for k, v := range truth {
			c.Add(k, v)
		}
		return c
	}

	for op := 0; op < numOps; op++ {
		k := keys[rng.Intn(numKeys)]
		switch rng.Intn(3) {
		case 0, 1: // insert or clobber
			newVal := []byte(randStringRNG(rng, rng.Intn(10)))
			old, exists := truth[k]
			if !exists {
				rolling.Add(k, newVal)
			} else {
				// Skip no-op writes, mirroring the cache's dedupe behaviour.
				if string(old) == string(newVal) {
					continue
				}
				rolling.Replace(k, old, newVal)
			}
			truth[k] = newVal
		case 2: // delete
			old, exists := truth[k]
			if !exists {
				// Delete-of-absent is a no-op, mirroring the cache.
				continue
			}
			rolling.Remove(k, old)
			delete(truth, k)
		}

		// Every so often, assert the rolling value matches a full recompute.
		if op%97 == 0 {
			if got, want := rolling, recompute(); got != want {
				t.Fatalf("op %d: rolling checksum %+v != recompute %+v", op, got, want)
			}
		}
	}
	if got, want := rolling, recompute(); got != want {
		t.Fatalf("final: rolling checksum %+v != recompute %+v", got, want)
	}
}

func randString(n int) string {
	return randStringRNG(rand.New(rand.NewSource(int64(n)*7919+1)), n)
}

func randStringRNG(rng *rand.Rand, n int) string {
	const alphabet = "abcdefABCDEF0123456789/-_"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}
