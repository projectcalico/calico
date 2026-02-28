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
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/projectcalico/calico/lib/std/uniquestr"
)

// maxKeyTableSize is the maximum number of distinct label keys tracked in the
// global key table.  Must be <= 63 because we use a uint64 bitfield with the
// top bit reserved as a tag.
const maxKeyTableSize = 63

// topBit is the tag in the first word of a compact map.  When set, the word
// _is_ the bitfield; when clear, the allocation is a fallbackMap.
const topBit = uint64(1) << 63

const handleSize = unsafe.Sizeof(uniquestr.Handle{}) // 8

// globalKeyTable is the package-wide key table shared by all Maps.
var globalKeyTable keyTable

// fallbackMap is used when the key table is full or a map can't use the
// compact representation.  The sentinel field occupies the same position as
// bitfield in the compact types; its top bit is always clear.
type fallbackMap struct {
	sentinel uint64 // always 0
	m        handleMap
}

// ---- reading helpers (work with any compact struct type) ----

func readKeyBits(ptr unsafe.Pointer) uint64 {
	return *(*uint64)(ptr) &^ topBit
}

func readValueAt(ptr unsafe.Pointer, arrayIdx int) uniquestr.Handle {
	return *(*uniquestr.Handle)(unsafe.Add(ptr, 8+uintptr(arrayIdx)*handleSize))
}

// ---- key table ----

// keyTableSnap is an immutable snapshot of the key table.
type keyTableSnap struct {
	byHandle map[uniquestr.Handle]uint8
	byIndex  [maxKeyTableSize]uniquestr.Handle
	len      int
}

func (s *keyTableSnap) clone() *keyTableSnap {
	c := &keyTableSnap{
		byHandle: make(map[uniquestr.Handle]uint8, len(s.byHandle)+8),
		len:      s.len,
	}
	for k, v := range s.byHandle {
		c.byHandle[k] = v
	}
	c.byIndex = s.byIndex
	return c
}

// keyTable maps frequently-seen label keys to bit positions.  The read path
// (snap.Load) is lock-free; writes take mu.
type keyTable struct {
	snap atomic.Pointer[keyTableSnap]
	mu   sync.Mutex
}

func init() {
	globalKeyTable.snap.Store(&keyTableSnap{
		byHandle: make(map[uniquestr.Handle]uint8),
	})
}

func (t *keyTable) currentSnap() *keyTableSnap {
	return t.snap.Load()
}

// registerKeys attempts to build a compact map from m.  On success it returns
// (bitfield|topBit, values, true).  If the table is full and some keys can't
// be registered, it returns (0, nil, false).
func (t *keyTable) registerKeys(m map[string]string) (uint64, []uniquestr.Handle, bool) {
	snap := t.snap.Load()

	// Fast path (lock-free): all keys already known.
	var bf uint64
	for k := range m {
		h := uniquestr.Make(k)
		if pos, found := snap.byHandle[h]; found {
			bf |= uint64(1) << pos
		} else {
			return t.registerKeysSlow(m)
		}
	}
	return bf | topBit, buildValues(snap, bf, m), true
}

// registerKeysSlow is the mutex-protected path for registering new keys.
func (t *keyTable) registerKeysSlow(m map[string]string) (uint64, []uniquestr.Handle, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	snap := t.snap.Load()

	// Count unknown keys.
	unknowns := 0
	for k := range m {
		if _, found := snap.byHandle[uniquestr.Make(k)]; !found {
			unknowns++
		}
	}
	if unknowns == 0 {
		// All keys now known (registered by another goroutine).
		var bf uint64
		for k := range m {
			bf |= uint64(1) << snap.byHandle[uniquestr.Make(k)]
		}
		return bf | topBit, buildValues(snap, bf, m), true
	}
	if snap.len+unknowns > maxKeyTableSize {
		return 0, nil, false
	}

	// Clone and register new keys.
	snap = snap.clone()
	var bf uint64
	for k := range m {
		h := uniquestr.Make(k)
		if pos, found := snap.byHandle[h]; found {
			bf |= uint64(1) << pos
		} else {
			pos := uint8(snap.len)
			snap.byHandle[h] = pos
			snap.byIndex[pos] = h
			snap.len++
			bf |= uint64(1) << pos
		}
	}
	t.snap.Store(snap)
	return bf | topBit, buildValues(snap, bf, m), true
}

// buildValues creates the compact value array ordered by bit position.
func buildValues(snap *keyTableSnap, bf uint64, m map[string]string) []uniquestr.Handle {
	vals := make([]uniquestr.Handle, bits.OnesCount64(bf))
	for k, v := range m {
		pos := snap.byHandle[uniquestr.Make(k)]
		arrayIdx := bits.OnesCount64(bf & ((uint64(1) << pos) - 1))
		vals[arrayIdx] = uniquestr.Make(v)
	}
	return vals
}

// unsafeTestOnlyReset resets the global key table and cache to their
// initial (empty) state.  It must only be called from tests and is NOT
// safe for concurrent use; the caller must ensure no other goroutine is
// calling Make or reading Maps at the same time.
//
// Maps created before a reset become invalid: their compact bitfields
// reference positions from the old key table, so read operations on those
// Maps will return incorrect results.
func unsafeTestOnlyReset() {
	globalKeyTable = keyTable{}
	globalKeyTable.snap.Store(&keyTableSnap{
		byHandle: make(map[uniquestr.Handle]uint8),
	})
	recentCache = recentMapCache{
		seed: maphash.MakeSeed(),
	}
}
