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
	"math/bits"
	"unsafe"

	"github.com/projectcalico/calico/lib/std/uniquestr"
)

// kvHandle is a key-value pair of interned handles.
type kvHandle struct{ k, v uniquestr.Handle }

// mapBuilder collects kvHandle pairs and builds a Map.  The kvArr
// backing array lives on the stack for maps up to maxKeyTableSize
// entries; larger maps transparently promote to the heap via append.
type mapBuilder struct {
	kvArr [maxKeyTableSize]kvHandle
	kvs   []kvHandle
}

// init prepares the builder for use.  Must be called before Put.
func (b *mapBuilder) init() {
	b.kvs = b.kvArr[:0]
}

// Put appends a key-value handle pair.
func (b *mapBuilder) Put(k, v uniquestr.Handle) {
	b.kvs = append(b.kvs, kvHandle{k, v})
}

// Len returns the number of pairs collected so far.
func (b *mapBuilder) Len() int {
	return len(b.kvs)
}

// build constructs a Map from the collected pairs.  It tries the
// compact representation first (all keys known in the key table),
// falling back to a handleMap + registerKeys or plain fallbackMap.
func (b *mapBuilder) build() Map {
	n := len(b.kvs)

	// Try compact: all keys already known in the key table.
	if n <= maxKeyTableSize {
		snap := globalKeyTable.currentSnap()
		var bf uint64
		var valsByPos [maxKeyTableSize]uniquestr.Handle
		allKnown := true
		for _, kv := range b.kvs {
			if pos, ok := snap.byHandle[kv.k]; ok {
				bf |= uint64(1) << pos
				valsByPos[pos] = kv.v
			} else {
				allKnown = false
				break
			}
		}
		if allKnown {
			// Pack values in bit order.
			vals := make([]uniquestr.Handle, bits.OnesCount64(bf))
			remaining := bf
			for i := range vals {
				pos := uint(bits.TrailingZeros64(remaining))
				vals[i] = valsByPos[pos]
				remaining &= remaining - 1
			}
			return Map{ptr: allocCompact(bf|topBit, vals)}
		}
	}

	// Fallback: build a handleMap, try registerKeys for compact.
	hm := make(handleMap, n)
	for _, kv := range b.kvs {
		hm[kv.k] = kv.v
	}
	if bf, vals, ok := globalKeyTable.registerKeys(hm); ok {
		return Map{ptr: allocCompact(bf, vals)}
	}
	return Map{ptr: unsafe.Pointer(&fallbackMap{m: hm})}
}

// Finish builds the Map, consulting and populating the cache.
func (b *mapBuilder) Finish() Map {
	hash := b.computeHash()
	if cached, ok := recentCache.LookupByHash(hash, b.validate); ok {
		return cached
	}
	result := b.build()
	recentCache.Store(hash, result)
	return result
}

// computeHash computes an order-independent hash of the collected
// pairs using the same XOR-of-per-pair strategy as hashMapStringString.
func (b *mapBuilder) computeHash() uint64 {
	var combined uint64
	var h maphash.Hash
	h.SetSeed(recentCache.seed)
	for _, kv := range b.kvs {
		h.Reset()
		h.WriteString(kv.k.Value())
		h.WriteByte(0)
		h.WriteString(kv.v.Value())
		combined ^= h.Sum64()
	}
	return combined
}

// validate checks whether a cached Map contains exactly the pairs
// in the builder.  Used as the validator callback for LookupByHash.
func (b *mapBuilder) validate(m Map) bool {
	if m.Len() != len(b.kvs) {
		return false
	}
	for _, kv := range b.kvs {
		if v, ok := m.GetHandle(kv.k); !ok || v != kv.v {
			return false
		}
	}
	return true
}
