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
	"encoding/json"
	"math/bits"
	"slices"
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

// valuesOffset is the byte offset from the start of a compact struct to its
// values array.  Derived from compact1 but identical for all compactN types.
var valuesOffset = unsafe.Offsetof(compact1{}.values)

func readValueAt(ptr unsafe.Pointer, arrayIdx int) uniquestr.Handle {
	return *(*uniquestr.Handle)(unsafe.Add(ptr, valuesOffset+uintptr(arrayIdx)*handleSize))
}

// ---- compactMap: read-only view of a compact bitfield-encoded map ----

// compactMap wraps an unsafe.Pointer to a compactN allocation together with the
// pre-extracted key bitfield.  Methods on compactMap implement the read
// operations that Map dispatches to.
type compactMap struct {
	ptr     unsafe.Pointer
	keyBits uint64 // bitfield with topBit stripped
}

func (cm compactMap) len() int {
	return bits.OnesCount64(cm.keyBits)
}

func (cm compactMap) getHandle(h uniquestr.Handle) (uniquestr.Handle, bool) {
	if cm.keyBits == 0 {
		return uniquestr.Handle{}, false
	}
	snap := globalKeyTable.currentSnap()
	pos, ok := snap.byHandle[h]
	if !ok {
		return uniquestr.Handle{}, false
	}
	if cm.keyBits&(uint64(1)<<pos) == 0 {
		return uniquestr.Handle{}, false
	}
	arrayIdx := bits.OnesCount64(cm.keyBits & ((uint64(1) << pos) - 1))
	return readValueAt(cm.ptr, arrayIdx), true
}

func (cm compactMap) allHandles(yield func(uniquestr.Handle, uniquestr.Handle) bool) {
	if cm.keyBits == 0 {
		return
	}
	snap := globalKeyTable.currentSnap()
	bf := cm.keyBits
	arrayIdx := 0
	for bf != 0 {
		pos := bits.TrailingZeros64(bf)
		key := snap.byIndex[pos]
		val := readValueAt(cm.ptr, arrayIdx)
		if !yield(key, val) {
			return
		}
		bf &= bf - 1
		arrayIdx++
	}
}

// marshalJSON writes a JSON object directly from the compact bitfield.
func (cm compactMap) marshalJSON() ([]byte, error) {
	n := cm.len()
	if n == 0 {
		return []byte("{}"), nil
	}
	snap := globalKeyTable.currentSnap()
	var backing [maxKeyTableSize]kv
	pairs := backing[:n]
	bf := cm.keyBits
	for i := range pairs {
		pos := bits.TrailingZeros64(bf)
		pairs[i] = kv{
			key: snap.byIndex[pos].Value(),
			val: readValueAt(cm.ptr, i).Value(),
		}
		bf &= bf - 1
	}
	return marshalSortedPairs(pairs)
}

// marshalJSON writes a JSON object from the fallback handle map.
func (fm *fallbackMap) marshalJSON() ([]byte, error) {
	n := len(fm.m)
	if n == 0 {
		return []byte("{}"), nil
	}
	var backing [maxKeyTableSize]kv
	// Fallback maps can exceed maxKeyTableSize; heap-allocate if needed.
	var pairs []kv
	if n <= maxKeyTableSize {
		pairs = backing[:n]
	} else {
		pairs = make([]kv, n)
	}
	i := 0
	for k, v := range fm.m {
		pairs[i] = kv{key: k.Value(), val: v.Value()}
		i++
	}
	return marshalSortedPairs(pairs)
}

type kv struct{ key, val string }

// marshalSortedPairs sorts pairs by key and writes them as a JSON object.
func marshalSortedPairs(pairs []kv) ([]byte, error) {
	slices.SortFunc(pairs, func(a, b kv) int {
		if a.key < b.key {
			return -1
		}
		if a.key > b.key {
			return 1
		}
		return 0
	})
	buf := make([]byte, 0, len(pairs)*40)
	buf = append(buf, '{')
	for i, p := range pairs {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = appendJSONString(buf, p.key)
		buf = append(buf, ':')
		buf = appendJSONString(buf, p.val)
	}
	buf = append(buf, '}')
	return buf, nil
}

// appendJSONString appends a JSON-encoded string (with quotes) to buf.
// All printable ASCII except '"' and '\\' is safe to embed directly in
// a JSON string.  Falls back to json.Marshal for anything else.
//
// Fuzz-tested against encoding/json for correctness.
func appendJSONString(buf []byte, s string) []byte {
	if jsonSafe(s) {
		buf = append(buf, '"')
		buf = append(buf, s...)
		buf = append(buf, '"')
		return buf
	}
	// Slow path: delegate to encoding/json for correct escaping.
	quoted, _ := json.Marshal(s)
	return append(buf, quoted...)
}

// jsonSafe reports whether s contains only bytes that are safe to embed
// in a JSON string without escaping: printable ASCII (0x20..0x7E)
// excluding '"', '\\', and HTML-sensitive characters '&', '<', '>'
// (which json.Marshal escapes by default).
func jsonSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E || c == '"' || c == '\\' || c == '&' || c == '<' || c == '>' {
			return false
		}
	}
	return true
}

func (cm compactMap) equals(other compactMap) bool {
	if cm.keyBits != other.keyBits {
		return false
	}
	n := bits.OnesCount64(cm.keyBits)
	for i := range n {
		if readValueAt(cm.ptr, i) != readValueAt(other.ptr, i) {
			return false
		}
	}
	return true
}

// ---- fallbackMap read methods ----

func (fm *fallbackMap) len() int {
	return len(fm.m)
}

func (fm *fallbackMap) getHandle(h uniquestr.Handle) (uniquestr.Handle, bool) {
	v, ok := fm.m[h]
	return v, ok
}

func (fm *fallbackMap) allHandles(yield func(uniquestr.Handle, uniquestr.Handle) bool) {
	for k, v := range fm.m {
		if !yield(k, v) {
			return
		}
	}
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

// registerKeys attempts to build a compact map from the pre-interned
// handleMap.  On success it returns (bitfield|topBit, values, true).
// If the table is full and some keys can't be registered, it returns
// (0, nil, false).
//
// The caller must intern keys/values into a handleMap before calling
// this method so that uniquestr.Make is called at most once per key.
func (t *keyTable) registerKeys(hm handleMap) (uint64, []uniquestr.Handle, bool) {
	snap := t.snap.Load()

	// Fast path (lock-free): all keys already known.
	var bf uint64
	for k := range hm {
		if pos, found := snap.byHandle[k]; found {
			bf |= uint64(1) << pos
		} else {
			return t.registerKeysSlow(hm)
		}
	}
	return bf | topBit, buildValues(snap, bf, hm), true
}

// registerKeysSlow is the mutex-protected path for registering new keys.
func (t *keyTable) registerKeysSlow(hm handleMap) (uint64, []uniquestr.Handle, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	snap := t.snap.Load()

	// Count unknown keys.
	unknowns := 0
	for k := range hm {
		if _, found := snap.byHandle[k]; !found {
			unknowns++
		}
	}
	if unknowns == 0 {
		// All keys now known (registered by another goroutine).
		var bf uint64
		for k := range hm {
			bf |= uint64(1) << snap.byHandle[k]
		}
		return bf | topBit, buildValues(snap, bf, hm), true
	}
	if snap.len+unknowns > maxKeyTableSize {
		return 0, nil, false
	}

	// Clone and register new keys.
	snap = snap.clone()
	var bf uint64
	for k := range hm {
		if pos, found := snap.byHandle[k]; found {
			bf |= uint64(1) << pos
		} else {
			pos := uint8(snap.len)
			snap.byHandle[k] = pos
			snap.byIndex[pos] = k
			snap.len++
			bf |= uint64(1) << pos
		}
	}
	t.snap.Store(snap)
	return bf | topBit, buildValues(snap, bf, hm), true
}

// buildValues creates the compact value array ordered by bit position.
func buildValues(snap *keyTableSnap, bf uint64, hm handleMap) []uniquestr.Handle {
	vals := make([]uniquestr.Handle, bits.OnesCount64(bf))
	for k, v := range hm {
		pos := snap.byHandle[k]
		arrayIdx := bits.OnesCount64(bf & ((uint64(1) << pos) - 1))
		vals[arrayIdx] = v
	}
	return vals
}
