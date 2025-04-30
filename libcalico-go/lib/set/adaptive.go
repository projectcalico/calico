package set

import (
	"unsafe"
)

const (
	adaptiveSetArrayLimit = 16
	sizeStoredInMap       = -1
)

// Adaptive is a set implementation that uses different underlying data
// structures depending on the size of the set.  For sets that usually empty
// or have only one or two elements, it is more than twice as fast and it uses
// ~10x less memory. It gets progressively slower as the number of elements
// increases, but at adaptiveSetArrayLimit it switches to a map-based
// implementation like set.Typed (with slight overhead relative to set.Typed).
//
// The zero value of Adaptive is an empty set (so it may be embedded in other
// datastructures). It should not be copied after first use.
type Adaptive[T comparable] struct {
	// p holds different types depending on the size of the set.
	// if size == 0, p is nil.
	// if size is in the range [1, adaptiveSetArrayLimit], p is a pointer to
	//    an array of size elements, rounded up to power of two.
	// if size > adaptiveSetArrayLimit, p is a pointer to a map[T]v
	p unsafe.Pointer

	// size is either the number of elements in the set, or sizeStoredInMap
	// if the set is backed by a map.
	size int
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

var arrCapForSize = [adaptiveSetArrayLimit + 1]int{
	0, 1, 2, 4, 4, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16,
}

func (a *Adaptive[T]) Add(item T) {
	switch a.size {
	case 0:
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
		if len(tSlice) < cap(tSlice) {
			// Still room in existing slice.
			tSlice = append(tSlice, item)
			a.size++
			return
		}
		if a.size < adaptiveSetArrayLimit {
			// Still allowed to grow the slice.
			s2 := make([]T, a.size, arrCapForSize[a.size+1])
			copy(s2, tSlice)
			s2 = append(s2, item)
			a.p = unsafe.Pointer(&s2[0])
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
