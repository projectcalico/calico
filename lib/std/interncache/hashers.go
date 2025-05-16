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

import "hash/maphash"

func ComparableHasher[T comparable]() func(maphash.Seed, *T) uint64 {
	return func(seed maphash.Seed, t *T) uint64 {
		return maphash.Comparable(seed, *t)
	}
}

func MapHasher[K comparable, V comparable]() func(maphash.Seed, *map[K]V) uint64 {
	return func(seed maphash.Seed, m *map[K]V) uint64 {
		var sum uint64
		// Map iteration order is random so we calculate the hash of each KV
		// independently and sum them up.
		for k, v := range *m {
			vHash := maphash.Comparable(seed, v)
			vHash = (vHash << 32) | (vHash >> 32) // Rotate to avoid collisions with the key
			kHash := maphash.Comparable(seed, k)
			sum += kHash * vHash
		}
		lenHash := maphash.Comparable(seed, len(*m))
		if *m == nil {
			lenHash = ^lenHash
		}
		sum += lenHash
		return sum
	}
}

func SliceHasher[T comparable]() func(maphash.Seed, *[]T) uint64 {
	return func(seed maphash.Seed, s *[]T) uint64 {
		var sum uint64
		for i, v := range *s {
			iHash := maphash.Comparable(seed, i)
			sum += iHash * maphash.Comparable(seed, v)
		}
		lenHash := maphash.Comparable(seed, len(*s))
		if *s == nil {
			lenHash = ^lenHash
		}
		sum += lenHash
		return sum
	}
}
