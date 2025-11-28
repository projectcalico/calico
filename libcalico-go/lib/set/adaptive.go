// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package set

import (
	"iter"
	"unsafe"
)

const (
	adaptiveSetArrayLimit = 16
	sizeStoredInMap       = -1
)

var arrCapForSize = [adaptiveSetArrayLimit + 1]int{
	0, 1, 2, 4, 4, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16,
}

// Adaptive is a set implementation that uses different underlying data
// structures depending on the size of the set.  For sets that are typically
// empty, or, have only one or two elements, it is more than twice as fast and
// it uses ~10x less memory. Above adaptiveSetArrayLimit it switches to a
// map-based implementation like set.Typed.
//
// The zero value of Adaptive is an empty set (so it may be embedded in other
// datastructures).  When embedding, the object must not be copied and then
// mutated.
type Adaptive[T comparable] struct {
	// size is either the number of elements in the set, or sizeStoredInMap
	// if the set is backed by a map.
	size int

	// p holds different types depending on size.
	// if size == 0, p is nil.
	// if size is in the range [1, adaptiveSetArrayLimit], p is a pointer to
	//   an array with length arrCapForSize[size]. We store an array, not a
	//   slice, to avoid storing the length and capacity of the slice.  The
	//   slice is recomputed on demand, based on the size of set.
	// if size == sizeStoredInMap, p is a pointer to a map[T]v
	p unsafe.Pointer
}

func NewAdaptive[T comparable]() *Adaptive[T] {
	return &Adaptive[T]{}
}

func AdaptiveFromArray[T comparable](items []T) *Adaptive[T] {
	s := NewAdaptive[T]()
	for _, t := range items {
		s.Add(t)
	}
	return s
}

func AdaptiveFrom[T comparable](items ...T) *Adaptive[T] {
	return AdaptiveFromArray(items)
}

func (a *Adaptive[T]) Len() int {
	if a.size == sizeStoredInMap {
		return len(*(*map[T]v)(a.p))
	}
	return a.size
}

func (a *Adaptive[T]) Add(item T) {
	switch a.size {
	case 0:
		// Set was empty so we don't need to check anything to add this item.
		// We directly store a pointer to the item, which can also be seen
		// as storing a single-element array.
		a.p = unsafe.Pointer(&item)
		a.size = 1
	case sizeStoredInMap:
		m := a.loadMapFromPointer()
		m[item] = emptyValue
	default:
		// Sizes 1, 2, ..., adaptiveSetArrayLimit. Stored in an array.

		// Make slice pointing at backing array with correct length/capacity.
		tSlice := a.loadSliceFromPointer()

		// First scan to see if the item is already present.
		for _, t := range tSlice {
			if t == item {
				// The element is already in the set.
				return
			}
		}

		// If we get here, need to add the element to the set.
		if a.size < adaptiveSetArrayLimit {
			// Set is still small enough to use a slice.
			if len(tSlice) == cap(tSlice) {
				// Need to grow the slice; we do it manually so we can control
				// the capacity and keep it in sync with arrCapForSize (allowing
				// us to avoid storing it).
				tSlice = growSliceCap(tSlice, arrCapForSize[a.size+1])
				a.p = unsafe.Pointer(&tSlice[0])
			}
			tSlice = append(tSlice, item)
			a.size++
			return
		}

		// Too many items to store in a slice, upgrade to a map.
		m := make(map[T]v, a.size+1)
		for _, t := range tSlice {
			m[t] = emptyValue
		}
		m[item] = emptyValue
		a.p = unsafe.Pointer(&m)
		a.size = sizeStoredInMap
	}
}

func growSliceCap[T any](in []T, newCap int) []T {
	out := make([]T, len(in), newCap)
	copy(out, in)
	return out
}

func (a *Adaptive[T]) AddAll(itemArray []T) {
	for _, v := range itemArray {
		a.Add(v)
	}
}

func (a *Adaptive[T]) AddSet(other Set[T]) {
	for item := range other.All() {
		a.Add(item)
	}
}

func (a *Adaptive[T]) Discard(item T) {
	switch a.size {
	case 0:
		// Map is empty, nothing to discard.
		return
	case 1:
		// Set has only one item, the pointer will point to that single item,
		// which is equivalent to a single-entry array.
		theOne := (*T)(a.p)
		if *theOne == item {
			a.p = nil
			a.size = 0
		}
	case sizeStoredInMap:
		m := a.loadMapFromPointer()
		delete(m, item)
		if len(m) <= adaptiveSetArrayLimit {
			// Too few items for a map, downgrade to an array.
			s := make([]T, 0, arrCapForSize[len(m)])
			for t := range m {
				s = append(s, t)
			}
			a.p = unsafe.Pointer(&s[0])
			a.size = len(m)
		}
	default:
		// Handles sizes 2, 3, ..., adaptiveSetArrayLimit. Stored in an array.

		// Make slice pointing at backing array with correct length/capacity.
		tSlice := a.loadSliceFromPointer()

		// Scan the slice to see if the item is present.
		for i, t := range tSlice {
			if t == item {
				// Found the element to remove.
				newSize := a.size - 1
				newCap := arrCapForSize[newSize]
				if newCap < cap(tSlice) {
					// Downgrade to a smaller array.  We could just shrink the
					// slice but that would leak the extra slots in the array.
					// It's not obvious that that is a good trade-off in our
					// usage so, for now, we maintain the invariant that
					// the capacity of the backing array is always
					// arrCapForSize[a.size].
					updatedSlice := make([]T, newSize, arrCapForSize[newSize])
					// Copy the elements before and after the removed element.
					copy(updatedSlice, tSlice[:i])
					copy(updatedSlice[i:], tSlice[i+1:])
					a.p = unsafe.Pointer(&updatedSlice[0])
				} else {
					// Keep the same slice.  Swap the last element into the
					// removed element's slot.
					tSlice[i] = tSlice[newSize]
					// Zero the last element to avoid keeping a reference to a
					// potentially large object.
					var zeroT T
					tSlice[newSize] = zeroT
				}
				a.size = newSize
				return
			}
		}
	}
}

func (a *Adaptive[T]) Clear() {
	a.size = 0
	a.p = nil
}

func (a *Adaptive[T]) Contains(t T) bool {
	switch a.size {
	case 0:
		return false
	case sizeStoredInMap:
		m := a.loadMapFromPointer()
		_, present := m[t]
		return present
	default:
		// Handles sizes 1, 2, ..., adaptiveSetArrayLimit. Stored in an array.

		// Make slice pointing at backing array with correct length/capacity.
		tSlice := a.loadSliceFromPointer()

		// Scan for the item.
		for _, v := range tSlice {
			if v == t {
				return true
			}
		}
		return false
	}
}

func (a *Adaptive[T]) Iter(f func(item T) error) {
	switch a.size {
	case 0:
		return
	case sizeStoredInMap:
		m := a.loadMapFromPointer()
		for v := range m {
			err := f(v)
			if err == StopIteration {
				return
			}
			if err == RemoveItem {
				// Discarding from a map is safe.  If the set did shrink and
				// get turned into an array then we'd just keep iterating
				// over the map, which would be fine.
				a.Discard(v)
			}
		}
	default:
		// Handles sizes 1, 2, ..., adaptiveSetArrayLimit. Stored in an array.

		// Make slice pointing at backing array with correct length/capacity.
		tSlice := a.loadSliceFromPointer()

		// Take a copy of the whole set so that a.Discard() does not break
		// iteration.  Since size <= adaptiveSetArrayLimit, we can use a
		// fixed-size array, which will be stack allocated.
		var tCopy [adaptiveSetArrayLimit]T
		copy(tCopy[:], tSlice)
		tSlice = tCopy[:a.size]

		for _, v := range tSlice {
			err := f(v)
			if err == StopIteration {
				return
			}
			if err == RemoveItem {
				a.Discard(v)
			}
		}
	}
}

// All returns an iterator for use with Go's range-over-func feature.
// The iterator supports discarding from the set during iteration without panicking.
func (a *Adaptive[T]) All() iter.Seq[T] {
	return func(yield func(T) bool) {
		switch a.size {
		case 0:
			return
		case sizeStoredInMap:
			// Map-backed: safe to iterate and mutate directly
			m := a.loadMapFromPointer()
			for v := range m {
				if !yield(v) {
					return
				}
			}
		default:
			// Array-backed: take a snapshot to allow safe mutation during iteration
			tSlice := a.loadSliceFromPointer()
			var tCopy [adaptiveSetArrayLimit]T
			copy(tCopy[:], tSlice)
			tSlice = tCopy[:a.size]

			for _, v := range tSlice {
				if !yield(v) {
					return
				}
			}
		}
	}
}

// loadSliceFromPointer loads the array stored in our unsafe pointer, returning
// it as a slice with len == a.size and cap == arrCapForSize[a.size].
func (a *Adaptive[T]) loadSliceFromPointer() []T {
	if a.size < 1 || a.size > adaptiveSetArrayLimit {
		panic("Adaptive set: trying to load slice but size is out of bounds")
	}
	tPtr := (*T)(a.p)
	tSlice := unsafe.Slice(tPtr, arrCapForSize[a.size])[:a.size]
	return tSlice
}

// loadMapFromPointer loads the map stored in our unsafe pointer.  Caller must
// have already checked that size == sizeStoredInMap.
func (a *Adaptive[T]) loadMapFromPointer() map[T]v {
	if a.size != sizeStoredInMap {
		panic("Adaptive set: trying to load map but size is not sizeStoredInMap")
	}
	m := *(*map[T]v)(a.p)
	return m
}

func (a *Adaptive[T]) Copy() Set[T] {
	other := NewAdaptive[T]()
	for item := range a.All() {
		other.Add(item)
	}
	return other
}

func (a *Adaptive[T]) Equals(s Set[T]) bool {
	if a.Len() != s.Len() {
		return false
	}
	equal := true
	for item := range a.All() {
		if !s.Contains(item) {
			equal = false
			break
		}
	}
	return equal
}

func (a *Adaptive[T]) ContainsAll(s Set[T]) bool {
	if s.Len() > a.Len() {
		return false
	}
	seenAll := true
	for item := range s.All() {
		if !a.Contains(item) {
			seenAll = false
			break
		}
	}
	return seenAll
}

func (a *Adaptive[T]) Slice() []T {
	s := make([]T, 0, a.Len())
	for item := range a.All() {
		s = append(s, item)
	}
	return s
}

func (a *Adaptive[T]) String() string {
	return stringify(a)
}

var _ Set[any] = &Adaptive[any]{}
