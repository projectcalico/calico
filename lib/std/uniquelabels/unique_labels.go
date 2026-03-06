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

//go:generate go run gen_compact.go

import (
	"encoding/json"
	"fmt"
	"iter"
	"math/bits"
	"unsafe"

	"github.com/projectcalico/calico/lib/std/uniquestr"
)

type handleMap = map[uniquestr.Handle]uniquestr.Handle

// emptyBacking is the singleton compact allocation for the Empty map.
// bitfield = topBit means "compact representation, zero keys present".
var emptyBacking = compact4{bitfield: topBit}

var (
	Nil   = Map{}
	Empty = Map{ptr: unsafe.Pointer(&emptyBacking)}
)

// Map is a *read only* string-to-string map that interns keys and values.
// When marshalled as JSON, uses the same representation as a normal
// map[string]string.  When unmarshalled, keys and values get interned/deduped.
//
// To allow drop-in replacement of a map[string]string, Map has unique
// representations of nil (Nil) and empty (Empty). The zero value of a Map is
// the Nil value; it can be detected with IsNil(). Map is a value type, which
// precludes using Go's normal nil.
//
// Internally, Map stores an unsafe.Pointer to one of two representations:
//
//   - Compact: the first uint64 has the top bit set and encodes a bitfield
//     of which keys (from a global lookup table) are present.  The values
//     follow immediately as a flat array of uniquestr.Handle.
//   - Fallback: the first uint64 has the top bit clear, followed by a
//     regular Go map[uniquestr.Handle]uniquestr.Handle.
//
// Uses uniquestr.Handle internally, so it is most efficient to query the map
// using AllHandles() and GetHandle().
type Map struct {
	_   [0]func()      // Explicitly non-comparable; must use Equals() method.
	ptr unsafe.Pointer // -> compact* or *fallbackMap; nil for Nil.
}

// compact returns the compact view if this Map uses the bitfield
// representation.  Must not be called when m.ptr is nil.
func (m Map) compact() (compactMap, bool) {
	header := *(*uint64)(m.ptr)
	if header&topBit != 0 {
		return compactMap{ptr: m.ptr, keyBits: header &^ topBit}, true
	}
	return compactMap{}, false
}

// asFallback returns the fallback view.  Must only be called when m.ptr is
// non-nil and compact() returned false.
func (m Map) asFallback() *fallbackMap {
	return (*fallbackMap)(m.ptr)
}

// isCompact reports whether this Map uses the compact bitfield representation.
func (m Map) isCompact() bool {
	if m.ptr == nil {
		return false
	}
	_, ok := m.compact()
	return ok
}

// IsNil reports whether the map is the nil representation.
func (m Map) IsNil() bool {
	return m.ptr == nil
}

// Len returns the number of entries.
func (m Map) Len() int {
	if m.ptr == nil {
		return 0
	}
	if cm, ok := m.compact(); ok {
		return cm.len()
	}
	return m.asFallback().len()
}

// Make makes an interned copy of the given map.  In order to benefit from
// interning the map, the original map must be discarded and only the interned
// copy should be kept.
//
// If passed nil, returns the zero value of Map.  If passed an empty map,
// returns the singleton Empty.
//
// Make caches recently-returned Maps so that repeated calls with the same input
// return the same Map, avoiding redundant allocations.
func Make(m map[string]string) Map {
	if m == nil {
		return Nil
	}
	if len(m) == 0 {
		return Empty
	}

	if cached, hash, ok := recentCache.Lookup(m); ok {
		return cached
	} else {
		result := makeInner(m)
		recentCache.Store(hash, result)
		return result
	}
}

// makeInner builds a Map from a non-nil, non-empty map[string]string.
// It first tries to build a compact representation directly without
// allocating a Go map; falls back to a handleMap when keys are unknown
// or the key table is full.
func makeInner(m map[string]string) Map {
	if result, ok := tryMakeCompactDirect(m); ok {
		return result
	}
	// Slow path: build a handleMap for key registration or fallback.
	hm := make(handleMap, len(m))
	for k, v := range m {
		hm[uniquestr.Make(k)] = uniquestr.Make(v)
	}
	if bf, vals, ok := globalKeyTable.registerKeys(hm); ok {
		return Map{ptr: allocCompact(bf, vals)}
	}
	return Map{ptr: unsafe.Pointer(&fallbackMap{m: hm})}
}

// tryMakeCompactDirect attempts to build a compact Map directly from
// the input map without allocating an intermediate handleMap.  Succeeds
// when all keys are already in the global key table (the common case
// after startup).
func tryMakeCompactDirect(m map[string]string) (Map, bool) {
	if len(m) > maxKeyTableSize {
		return Map{}, false
	}
	snap := globalKeyTable.currentSnap()
	var bf uint64
	var valsByPos [maxKeyTableSize]uniquestr.Handle
	for k, v := range m {
		kh := uniquestr.Make(k)
		pos, found := snap.byHandle[kh]
		if !found {
			return Map{}, false
		}
		bf |= uint64(1) << pos
		valsByPos[pos] = uniquestr.Make(v)
	}
	// Pack values in bit order.
	vals := make([]uniquestr.Handle, bits.OnesCount64(bf))
	remaining := bf
	for i := range vals {
		pos := uint(bits.TrailingZeros64(remaining))
		vals[i] = valsByPos[pos]
		remaining &= remaining - 1
	}
	return Map{ptr: allocCompact(bf|topBit, vals)}, true
}

// Equals returns true if the map contains the same key/value pairs as the
// other map.  In line with maps.Equal, Nil and Empty compare equal.
//
// When both maps use the compact representation, Equals compares the
// bitfields directly and then the value arrays element-by-element,
// avoiding any hash-table lookups.
func (m Map) Equals(other Map) bool {
	if m.ptr == other.ptr {
		return true
	}
	if m.ptr == nil || other.ptr == nil {
		// One is Nil, other is not (same-pointer handled above).
		// Nil equals Empty by contract.
		return m.Len() == 0 && other.Len() == 0
	}
	cm, mCompact := m.compact()
	co, oCompact := other.compact()
	if mCompact && oCompact {
		return cm.equals(co)
	}
	// Mixed or both fallback: generic comparison.
	if m.Len() != other.Len() {
		return false
	}
	for k, v := range m.AllHandles() {
		if ov, ok := other.GetHandle(k); !ok || ov != v {
			return false
		}
	}
	return true
}

// EquivalentTo reports whether this Map contains exactly the same entries as
// the given map[string]string.
func (m Map) EquivalentTo(other map[string]string) bool {
	if m.IsNil() != (other == nil) {
		return false
	}
	if len(other) != m.Len() {
		return false
	}
	for k, v := range m.AllStrings() {
		if mv, ok := other[k]; !ok || mv != v {
			return false
		}
	}
	return true
}

// GetString looks up key k (as a plain string).
func (m Map) GetString(k string) (string, bool) {
	v, ok := m.GetHandle(uniquestr.Make(k))
	if !ok {
		return "", false
	}
	return v.Value(), true
}

// GetHandle looks up key h using an interned handle.  This is the preferred
// lookup method for hot paths.
func (m Map) GetHandle(h uniquestr.Handle) (uniquestr.Handle, bool) {
	if m.ptr == nil {
		return uniquestr.Handle{}, false
	}
	if cm, ok := m.compact(); ok {
		return cm.getHandle(h)
	}
	return m.asFallback().getHandle(h)
}

// AllHandles returns an iterator over key/value handle pairs.
func (m Map) AllHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return func(yield func(uniquestr.Handle, uniquestr.Handle) bool) {
		if m.ptr == nil {
			return
		}
		if cm, ok := m.compact(); ok {
			cm.allHandles(yield)
		} else {
			m.asFallback().allHandles(yield)
		}
	}
}

// AllStrings returns an iterator over key/value string pairs.
func (m Map) AllStrings() iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for k, v := range m.AllHandles() {
			if !yield(k.Value(), v.Value()) {
				return
			}
		}
	}
}

// RecomputeOriginalMap converts back to a plain map[string]string.
func (m Map) RecomputeOriginalMap() map[string]string {
	if m.ptr == nil {
		return nil
	}
	result := make(map[string]string, m.Len())
	for k, v := range m.AllStrings() {
		result[k] = v
	}
	return result
}

func (m Map) String() string {
	return fmt.Sprint(m.RecomputeOriginalMap())
}

// MarshalJSON implements the json.Marshaler interface.
// Both compact and fallback maps write JSON directly with sorted keys,
// avoiding intermediate map allocations and encoding/json reflection.
func (m Map) MarshalJSON() ([]byte, error) {
	if m.ptr == nil {
		return []byte("null"), nil
	}
	if cm, ok := m.compact(); ok {
		return cm.marshalJSON()
	}
	return m.asFallback().marshalJSON()
}

// UnmarshalJSON implements the json.Unmarshaler interface.  Unmarshalling
// goes through Make so that keys are registered in the global key table
// and the cache is consulted.  This is important because UnmarshalJSON is
// the main entry point when receiving data from Typha.
func (m *Map) UnmarshalJSON(data []byte) error {
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*m = Make(raw)
	return nil
}

// IntersectAndFilter returns a Map that contains only the key/value pairs that
// are both:
//
//   - Common to both input Maps.
//   - Match the include predicate.
//
// If either map is Nil, returns Nil.  Otherwise, returns a non-Nil, but
// possibly empty Map.  May return one of the input maps.
func IntersectAndFilter(a, b Map, include func(uniquestr.Handle, uniquestr.Handle) bool) Map {
	if a.IsNil() || b.IsNil() {
		return Nil
	}

	if b.Len() < a.Len() {
		// Always iterate over the shorter map. This reduces the number of
		// iterations and, if the shorter map is a subset of the larger, we
		// can return the smaller map rather than duplicating.
		return IntersectAndFilter(b, a, include)
	}

	if include == nil {
		include = noOpFilter
	}

	// Do a pass to determine if we need to allocate a new map.
	needToFilter := false
	for k, v := range a.AllHandles() {
		if !include(k, v) {
			needToFilter = true
			break
		}
		if otherV, ok := b.GetHandle(k); !ok || otherV != v {
			needToFilter = true
			break
		}
	}
	if !needToFilter {
		// Map a _is_ the intersection.
		return a
	}

	// We _do_ need to make a new map, re-do the calculation.
	// If a is compact, build a compact result (the intersection's keys
	// are a subset of a's keys, which are all in the key table).
	if cm, ok := a.compact(); ok {
		snap := globalKeyTable.currentSnap()
		var resultBf uint64
		var vals []uniquestr.Handle
		remaining := cm.keyBits
		aIdx := 0
		for remaining != 0 {
			pos := uint(bits.TrailingZeros64(remaining))
			key := snap.byIndex[pos]
			val := readValueAt(cm.ptr, aIdx)
			if include(key, val) {
				if otherV, ok := b.GetHandle(key); ok && otherV == val {
					resultBf |= uint64(1) << pos
					vals = append(vals, val)
				}
			}
			remaining &= remaining - 1
			aIdx++
		}
		if len(vals) == 0 {
			return Empty
		}
		return Map{ptr: allocCompact(resultBf|topBit, vals)}
	}

	intersection := map[uniquestr.Handle]uniquestr.Handle{}
	for k, v := range a.AllHandles() {
		if !include(k, v) {
			continue
		}
		if otherV, ok := b.GetHandle(k); !ok || otherV != v {
			continue
		}
		intersection[k] = v
	}
	if len(intersection) == 0 {
		return Empty
	}
	// Try to produce a compact result: if every key in the intersection
	// is already in the key table, we can use the bitfield representation.
	if len(intersection) <= maxKeyTableSize {
		snap := globalKeyTable.currentSnap()
		var bf uint64
		allKnown := true
		for k := range intersection {
			pos, ok := snap.byHandle[k]
			if !ok {
				allKnown = false
				break
			}
			bf |= uint64(1) << pos
		}
		if allKnown {
			vals := make([]uniquestr.Handle, len(intersection))
			for k, v := range intersection {
				pos := snap.byHandle[k]
				arrayIdx := bits.OnesCount64(bf & ((uint64(1) << pos) - 1))
				vals[arrayIdx] = v
			}
			return Map{ptr: allocCompact(bf|topBit, vals)}
		}
	}
	return Map{ptr: unsafe.Pointer(&fallbackMap{m: intersection})}
}

func noOpFilter(uniquestr.Handle, uniquestr.Handle) bool {
	return true
}

var _ json.Marshaler = Map{}
var _ json.Unmarshaler = (*Map)(nil)
