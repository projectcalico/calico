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

package uniquelabels

import (
	"hash/maphash"
	"iter"
	"sync"
)

// recentCache is a small, direct-mapped cache of recently-computed Map values.
// It is common for Make to be called in quick succession with the same input
// from different call sites (including UnmarshalJSON). The cache avoids
// redundant compact-struct allocations and key-table lookups.
var recentCache = recentMapCache{
	seed: maphash.MakeSeed(),
}

const recentMapCacheSize = 128 // Must be a power of two.

type recentMapCache struct {
	mu      sync.Mutex
	seed    maphash.Seed
	entries [recentMapCacheSize]recentMapCacheEntry
}

type recentMapCacheEntry struct {
	hash uint64
	m    Map
}

// LookupByHash checks the cache for a Map matching the given hash.
// validate is called (under the cache lock) to confirm the cached Map
// matches the caller's input.
func (c *recentMapCache) LookupByHash(hash uint64, validate func(Map) bool) (Map, bool) {
	idx := hash & (recentMapCacheSize - 1)

	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[idx]
	if entry.hash == hash && validate(entry.m) {
		return entry.m, true
	}
	return Map{}, false
}

// Lookup checks the cache for a Map matching the given map[string]string.
// Returns the cached Map and true on hit, or the zero Map and false on miss.
// The returned hash should be passed to Store on miss.
func (c *recentMapCache) Lookup(m map[string]string) (Map, uint64, bool) {
	hash := c.hashMapStringString(m)
	if cached, ok := c.LookupByHash(hash, func(cached Map) bool {
		return cached.EquivalentTo(m)
	}); ok {
		return cached, hash, true
	}
	return Map{}, hash, false
}

// Store stores a Map in the cache at the slot determined by hash.
func (c *recentMapCache) Store(hash uint64, result Map) {
	idx := hash & (recentMapCacheSize - 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[idx] = recentMapCacheEntry{hash: hash, m: result}
}

// hashMapStringString computes an order-independent hash of a
// map[string]string. Each key/value pair is hashed independently and XORed
// together so that iteration order does not matter.
func (c *recentMapCache) hashMapStringString(m map[string]string) uint64 {
	var combined uint64
	var h maphash.Hash
	h.SetSeed(c.seed)
	for k, v := range m {
		h.Reset()
		h.WriteString(k)
		h.WriteByte(0) // Separator so "ab"+"" != "a"+"b".
		h.WriteString(v)
		combined ^= h.Sum64()
	}
	return combined
}

// hashSeq computes an order-independent hash of an iter.Seq2[string, string]
// using the same algorithm as hashMapStringString.
func (c *recentMapCache) hashSeq(seq iter.Seq2[string, string]) uint64 {
	var combined uint64
	var h maphash.Hash
	h.SetSeed(c.seed)
	for k, v := range seq {
		h.Reset()
		h.WriteString(k)
		h.WriteByte(0)
		h.WriteString(v)
		combined ^= h.Sum64()
	}
	return combined
}
