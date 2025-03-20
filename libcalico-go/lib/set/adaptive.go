package set

import (
	"unsafe"
)

const (
	adaptiveSetArrayLimit = 16
	sizeInMap             = 0xff
)

// Adaptive is a set implementation that uses different underlying data
// structures depending on the size of the set.  For sets that usually empty
// or have only one or two elements, it is more than twice as fast and it uses
// ~10x less memory. It gets progressively slower as the number of elements
// increases, but at adaptiveSetArrayLimit it switches to a map-based
// implementation like set.Typed (with slight overhead relative to set.Typed).
//
// The zero value of Adaptive is an empty set; it should not be copied after
// first use.
type Adaptive[T comparable] struct {
	_ noCopy // Prevent copying of the set.

	// p holds different types depending on the size of the set.
	// if size == 0, p is nil.
	// if size == 1, p is a pointer to the single element of the set.
	// if size is in the range [2, adaptiveSetArrayLimit], p is a pointer to an array of size elements.
	// if size > adaptiveSetArrayLimit, p is a pointer to a map[T]v
	p unsafe.Pointer

	// size is either the number of elements in the set, or sizeInMap if the set is backed by a map.
	size uint8
}

type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

func NewAdaptive[T comparable]() *Adaptive[T] {
	return &Adaptive[T]{}
}

func (a *Adaptive[T]) Len() int {
	if a.size == sizeInMap {
		return len(*(*map[T]v)(a.p))
	}
	return int(a.size)
}

func (a *Adaptive[T]) Add(item T) {
	switch a.size {
	case 0:
		a.p = unsafe.Pointer(&item)
		a.size = 1
	case 1:
		theOne := (*T)(a.p)
		if *theOne == item {
			// The element is already in the set.
			return
		}
		// Element is different from the one already in the set.
		// Need to upgrade to an array.
		arr := [2]T{*theOne, item}
		a.p = unsafe.Pointer(&arr[0])
		a.size = 2
	case sizeInMap:
		m := *(*map[T]v)(a.p)
		m[item] = emptyValue
	default:
		tPtr := (*T)(a.p)
		tSlice := unsafe.Slice(tPtr, a.size)
		for _, t := range tSlice {
			if t == item {
				// The element is already in the set.
				return
			}
		}
		if a.size < adaptiveSetArrayLimit {
			// Still allowed to grow the slice.
			s2 := make([]T, a.size+1)
			copy(s2, tSlice)
			s2[a.size] = item
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
		a.size = sizeInMap
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
	case 2:
		tSlice := (*[2]T)(a.p)[:]
		if tSlice[0] == item {
			a.p = unsafe.Pointer(&tSlice[1])
			a.size = 1
			return
		}
		if tSlice[1] == item {
			a.p = unsafe.Pointer(&tSlice[0])
			a.size = 1
			return
		}
	case sizeInMap:
		m := *(*map[T]v)(a.p)
		delete(m, item)
		if len(m) <= adaptiveSetArrayLimit {
			// Downgrade to an array.
			s := make([]T, 0, len(m))
			for t := range m {
				s = append(s, t)
			}
			a.p = unsafe.Pointer(&s[0])
			a.size = uint8(len(m))
		}
	default:
		tPtr := (*T)(a.p)
		tSlice := unsafe.Slice(tPtr, a.size)
		updated := make([]T, 0, a.size-1)
		for _, t := range tSlice {
			if t == item {
				continue
			}
			if len(updated) == int(a.size-1) {
				return
			}
			updated = append(updated, t)
		}
		a.size--
		a.p = unsafe.Pointer(&updated[0])
	}
}

func (a *Adaptive[T]) Clear() {
	a.size = 0
	a.p = nil
}

func (a *Adaptive[T]) Contains(t T) bool {
	if a.size == 0 {
		return false
	}
	if a.size == 1 {
		return *(*T)(a.p) == t
	}
	if a.size <= adaptiveSetArrayLimit {
		tSlice := unsafe.Slice((*T)(a.p), a.size)
		for _, v := range tSlice {
			if v == t {
				return true
			}
		}
		return false
	}
	m := *(*map[T]v)(a.p)
	_, present := m[t]
	return present
}

func (a *Adaptive[T]) Iter(f func(item T) error) {
	if a.size == 0 {
		return
	}
	if a.size == 1 {
		err := f(*(*T)(a.p))
		if err == StopIteration {
			return
		}
		if err == RemoveItem {
			a.size = 0
			a.p = nil
			return
		}
		return
	}
	if a.size <= adaptiveSetArrayLimit {
		tSlice := unsafe.Slice((*T)(a.p), a.size)
		for _, v := range tSlice {
			err := f(v)
			if err == StopIteration {
				return
			}
			if err == RemoveItem {
				a.Discard(v)
			}
		}
		return
	}
	m := *(*map[T]v)(a.p)
	for v := range m {
		err := f(v)
		if err == StopIteration {
			return
		}
		if err == RemoveItem {
			a.Discard(v)
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
	s := make([]T, 0, a.size)
	a.Iter(func(item T) error {
		s = append(s, item)
		return nil
	})
	return s
}

func (a *Adaptive[T]) String() string {
	s := New[T]()
	s.AddSet(a)
	return s.String()
}

var _ Set[any] = &Adaptive[any]{}
