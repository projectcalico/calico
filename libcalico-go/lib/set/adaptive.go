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
// structures depending on the size of the set.  For sets that usually empty
// or have only one or two elements, it is more than twice as fast and it uses
// ~10x less memory. It gets progressively slower as the number of elements
// increases. Above adaptiveSetArrayLimit it switches to a map-based
// implementation like set.Typed (with slight overhead relative to set.Typed).
//
// The zero value of Adaptive is an empty set (so it may be embedded in other
// datastructures).
//
// Should not be copied after first use. Since the struct carries the size,
// copying by value and then mutating can result in two Adaptive instances
// sharing storage but with different sizes; this is not recommended!
type Adaptive[T comparable] struct {
	// size is either the number of elements in the set, or sizeStoredInMap
	// if the set is backed by a map.
	size int

	// p holds different types depending on size.
	// if size == 0, p is nil.
	// if size is in the range [1, adaptiveSetArrayLimit], p is a pointer to
	//    an array with length size, rounded up to next power of two.
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

func AdaptiveFrom(items ...int) *Adaptive[int] {
	return AdaptiveFromArray(items)
}

func (a *Adaptive[T]) Len() int {
	if a.size == sizeStoredInMap {
		return len(*(*map[T]v)(a.p))
	}
	return int(a.size)
}

func (a *Adaptive[T]) Add(item T) {
	switch a.size {
	case 0:
		// Array of one item is just the item.
		a.p = unsafe.Pointer(&item)
		a.size = 1
	default:
		tPtr := (*T)(a.p)
		tSlice := unsafe.Slice(tPtr, arrCapForSize[a.size])[:a.size]
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
				// the exact new capacity.
				tSlice = growSliceCap(tSlice, arrCapForSize[a.size+1])
				a.p = unsafe.Pointer(&tSlice[0])
			}
			tSlice = append(tSlice, item)
			a.size++
			return
		}

		// Need to upgrade to a map.
		m := make(map[T]v, a.size+1)
		for _, t := range tSlice {
			m[t] = emptyValue
		}
		m[item] = emptyValue
		a.p = unsafe.Pointer(&m)
		a.size = sizeStoredInMap
	case sizeStoredInMap:
		m := *(*map[T]v)(a.p)
		m[item] = emptyValue
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
	other.Iter(func(item T) error {
		a.Add(item)
		return nil
	})
}

func (a *Adaptive[T]) Discard(item T) {
	switch a.size {
	case 0:
		return
	case 1:
		theOne := (*T)(a.p)
		if *theOne == item {
			a.p = nil
			a.size = 0
		}
	case sizeStoredInMap:
		m := *(*map[T]v)(a.p)
		delete(m, item)
		if len(m) <= adaptiveSetArrayLimit {
			// Downgrade to an array.
			s := make([]T, 0, arrCapForSize[len(m)])
			for t := range m {
				s = append(s, t)
			}
			a.p = unsafe.Pointer(&s[0])
			a.size = len(m)
		}
	default:
		tPtr := (*T)(a.p)
		tSlice := unsafe.Slice(tPtr, arrCapForSize[a.size])[:a.size]
		for i, t := range tSlice {
			if t == item {
				// Found the element to remove.
				newSize := a.size - 1
				newCap := arrCapForSize[newSize]
				if newCap < cap(tSlice) {
					// Downgrade to a smaller array.
					updatedSlice := make([]T, arrCapForSize[newSize])
					// Copy the elements before and after the removed element.
					copy(updatedSlice, tSlice[:i])
					copy(updatedSlice[i:], tSlice[i+1:])
					a.p = unsafe.Pointer(&updatedSlice[0])
				} else {
					// Keep the same slice.  Swap the last element into the
					// removed element's slot.
					tSlice[i] = tSlice[newSize]
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
		m := *(*map[T]v)(a.p)
		_, present := m[t]
		return present
	default:
		tPtr := (*T)(a.p)
		tSlice := unsafe.Slice(tPtr, a.size)
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
		m := *(*map[T]v)(a.p)
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
		tPtr := (*T)(a.p)
		tSlice := unsafe.Slice(tPtr, a.size)

		// Must take a copy so that Discard doesn't break iteration. Since
		// this is a fixed size array, it should get stack allocated and be
		// very fast.
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

func (a *Adaptive[T]) Copy() Set[T] {
	other := NewAdaptive[T]()
	a.Iter(func(item T) error {
		other.Add(item)
		return nil
	})
	return other
}

func (a *Adaptive[T]) Equals(s Set[T]) bool {
	if a.Len() != s.Len() {
		return false
	}
	equal := true
	a.Iter(func(item T) error {
		if !s.Contains(item) {
			equal = false
			return StopIteration
		}
		return nil
	})
	return equal
}

func (a *Adaptive[T]) ContainsAll(s Set[T]) bool {
	if s.Len() > a.Len() {
		return false
	}
	seenAll := true
	s.Iter(func(item T) error {
		if !a.Contains(item) {
			seenAll = false
			return StopIteration
		}
		return nil
	})
	return seenAll
}

func (a *Adaptive[T]) Slice() []T {
	s := make([]T, 0, a.Len())
	a.Iter(func(item T) error {
		s = append(s, item)
		return nil
	})
	return s
}

func (a *Adaptive[T]) String() string {
	return stringify(a)
}

var _ Set[any] = &Adaptive[any]{}
