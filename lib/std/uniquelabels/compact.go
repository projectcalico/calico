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
	"iter"
	"math/bits"
	"unsafe"

	"github.com/projectcalico/calico/lib/std/uniquestr"
)

// emptyBacking is the singleton compact allocation for the Empty map.
// bitfield = topBit means "compact representation, zero keys present".
var emptyBacking = compact4{bitfield: topBit}

// compactMap overlays the header of any compactN allocation.  Cast an
// unsafe.Pointer to *compactMap to access the bitfield and values.
//
// The zero-length values field sits at the same offset as the [N]Handle
// array in every compactN type, so &cm.values gives a pointer to the
// start of the real values without manual offset arithmetic.
//
// A *compactMap is never allocated directly — it is always obtained by
// casting an unsafe.Pointer to an existing compactN allocation.
type compactMap struct {
	bf     uint64
	values [0]uniquestr.Handle
}

func (cm *compactMap) keyBits() uint64 {
	return cm.bf &^ topBit
}

func (cm *compactMap) len() int {
	return bits.OnesCount64(cm.keyBits())
}

// slice returns the values array as a slice of the correct length.
// The caller must not append to or retain the slice beyond the
// lifetime of the compactMap allocation.
func (cm *compactMap) slice() []uniquestr.Handle {
	n := cm.len()
	if n == 0 {
		return nil
	}
	return unsafe.Slice((*uniquestr.Handle)(unsafe.Pointer(&cm.values)), n)
}

func (cm *compactMap) getHandle(h uniquestr.Handle) (uniquestr.Handle, bool) {
	kb := cm.keyBits()
	if kb == 0 {
		return uniquestr.Handle{}, false
	}
	snap := globalKeyTable.currentSnap()
	pos, ok := snap.byHandle[h]
	if !ok {
		return uniquestr.Handle{}, false
	}
	if kb&(uint64(1)<<pos) == 0 {
		return uniquestr.Handle{}, false
	}
	arrayIdx := bits.OnesCount64(kb & ((uint64(1) << pos) - 1))
	return cm.slice()[arrayIdx], true
}

// compactIter is a pull-style iterator over a compactMap's key/value pairs.
// It is a value type (~48 bytes) designed to live on the caller's stack,
// avoiding the heap escapes that range-over-function closures cause.
type compactIter struct {
	snap      *keyTableSnap
	vals      []uniquestr.Handle
	remaining uint64
	arrayIdx  int
}

func (cm *compactMap) iter() compactIter {
	kb := cm.keyBits()
	var snap *keyTableSnap
	var vals []uniquestr.Handle
	if kb != 0 {
		snap = globalKeyTable.currentSnap()
		vals = cm.slice()
	}
	return compactIter{snap: snap, vals: vals, remaining: kb}
}

// hasNext reports whether there are more pairs to iterate.
func (it *compactIter) hasNext() bool {
	return it.remaining != 0
}

// next advances to the next pair and returns it.
// Must only be called when hasNext() is true.
func (it *compactIter) next() (uniquestr.Handle, uniquestr.Handle) {
	pos := bits.TrailingZeros64(it.remaining)
	k := it.snap.byIndex[pos]
	v := it.vals[it.arrayIdx]
	it.remaining &= it.remaining - 1
	it.arrayIdx++
	return k, v
}

func (cm *compactMap) allHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return func(yield func(uniquestr.Handle, uniquestr.Handle) bool) {
		it := cm.iter()
		for it.hasNext() {
			if !yield(it.next()) {
				return
			}
		}
	}
}

// marshalJSON writes a JSON object directly from the compact bitfield.
func (cm *compactMap) marshalJSON() ([]byte, error) {
	kb := cm.keyBits()
	n := bits.OnesCount64(kb)
	if n == 0 {
		return []byte("{}"), nil
	}
	snap := globalKeyTable.currentSnap()
	vals := cm.slice()
	var backing [maxKeyTableSize]kv
	pairs := backing[:n]
	bf := kb
	for i := range pairs {
		pos := bits.TrailingZeros64(bf)
		pairs[i] = kv{
			key: snap.byIndex[pos].Value(),
			val: vals[i].Value(),
		}
		bf &= bf - 1
	}
	return marshalSortedPairs(pairs)
}

func (cm *compactMap) equals(other *compactMap) bool {
	kb := cm.keyBits()
	if kb != other.keyBits() {
		return false
	}
	a := cm.slice()
	b := other.slice()
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
