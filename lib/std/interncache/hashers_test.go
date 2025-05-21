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

package interncache

import (
	"hash/maphash"
	"testing"
)

func TestComparableHasher(t *testing.T) {
	hasher := ComparableHasher[string]()
	sampleInputs := []string{
		"",
		"a",
		"b",
		"c",
		"ab",
	}
	testHasher(t, hasher, sampleInputs)
}

func TestMapHasher(t *testing.T) {
	hasher := MapHasher[string, string]()
	sampleInputs := []map[string]string{
		nil,
		{},
		{"a": "a"},
		{"a": "b"},
		{"b": "a"},
		{"a": "a", "b": "b"},
		{"a": "b", "b": "a"}, // Swapped values should give unique hash.
		{"a": "a", "b": "b", "c": "c"},
	}
	testHasher(t, hasher, sampleInputs)
}

func TestSliceHasher(t *testing.T) {
	hasher := SliceHasher[string]()
	sampleInputs := [][]string{
		nil,
		{},
		{"a"},
		{"a", "a"},
		{"a", ""},
		{"a", "b"},
		{"a", "b", "c"},
		{"b", "a", "c"}, // Order _should_ matter.
	}
	testHasher(t, hasher, sampleInputs)
}

func testHasher[T any](t *testing.T, hasher func(seed maphash.Seed, m *T) uint64, sampleInputs []T) {
	seed := maphash.MakeSeed()
	seenHashes := make(map[uint64]bool)
	for _, sampleInput := range sampleInputs {
		hashValue := hasher(seed, &sampleInput)
		hashValue2 := hasher(seed, &sampleInput)
		if hashValue != hashValue2 {
			t.Errorf("Hash values with same seed and same input should be equal: %d != %d (slice=%v)", hashValue, hashValue2, sampleInput)
		}
		if _, ok := seenHashes[hashValue]; ok {
			t.Errorf("Hash value %d already seen (input %v)", hashValue, sampleInput)
		}
		seenHashes[hashValue] = true
	}
}
