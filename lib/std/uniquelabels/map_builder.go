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

// mapBuilder is a slice of kvHandle pairs backed by a caller-provided
// stack array.  Because a slice header is only 24 bytes, value-receiver
// methods do not force the (large) backing array to escape to the heap.
// Non-inlineable methods like build() and Finish() receive a cheap copy
// of the slice header rather than a pointer to the backing storage.
//
// Callers declare the backing array on their own stack and slice it:
//
//	var buf [maxKeyTableSize]kvHandle
//	mb := mapBuilder(buf[:0])
//	mb = append(mb, kvHandle{k, v})
//
// append must be done at the call site (not in a method) to keep the
// backing array on the stack; a method returning append's result would
// cause the backing array to escape.
type mapBuilder []kvHandle

// Len returns the number of pairs collected so far.
func (b mapBuilder) Len() int {
	return len(b)
}

// build constructs a Map from the collected pairs.  It tries the
// compact representation first (all keys known in the key table),
// falling back to a handleMap + registerKeys or plain fallbackMap.
func (b mapBuilder) build() Map {
	n := len(b)

	// Try compact: all keys already known in the key table.
	if n <= maxKeyTableSize {
		snap := globalKeyTable.currentSnap()
		var bf uint64
		var valsByPos [maxKeyTableSize]uniquestr.Handle
		allKnown := true
		for _, kv := range b {
			if pos, ok := snap.byHandle[kv.k]; ok {
				bf |= uint64(1) << pos
				valsByPos[pos] = kv.v
			} else {
				allKnown = false
				break
			}
		}
		if allKnown {
			// Allocate the compact struct and pack values in bit order.
			cm := allocCompact(bf|topBit, bits.OnesCount64(bf))
			vals := cm.slice()
			remaining := bf
			for i := range vals {
				pos := uint(bits.TrailingZeros64(remaining))
				vals[i] = valsByPos[pos]
				remaining &= remaining - 1
			}
			return Map{ptr: unsafe.Pointer(cm)}
		}
	}

	// Fallback: try registerKeys with the builder directly.
	if cm, ok := globalKeyTable.registerKeys(b); ok {
		return Map{ptr: unsafe.Pointer(cm)}
	}
	// True fallback: build handleMap for fallbackMap storage.
	hm := make(handleMap, n)
	for _, kv := range b {
		hm[kv.k] = kv.v
	}
	return Map{ptr: unsafe.Pointer(&fallbackMap{m: hm})}
}

// Finish builds the Map, consulting and populating the cache.
func (b mapBuilder) Finish() Map {
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
func (b mapBuilder) computeHash() uint64 {
	var combined uint64
	var h maphash.Hash
	h.SetSeed(recentCache.seed)
	for _, kv := range b {
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
func (b mapBuilder) validate(m Map) bool {
	if m.Len() != len(b) {
		return false
	}
	for _, kv := range b {
		if v, ok := m.GetHandle(kv.k); !ok || v != kv.v {
			return false
		}
	}
	return true
}
