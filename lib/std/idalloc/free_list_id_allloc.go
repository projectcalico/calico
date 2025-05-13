package idalloc

import (
	"errors"

	"golang.org/x/exp/constraints"
)

var ErrOutOfIDs = errors.New("out of IDs")

type FreeListAlloc[T constraints.Unsigned] struct {
	usedThenFreedIDs []T
	lastMintedID     T
}

func NewFreeListAlloc[T constraints.Unsigned]() *FreeListAlloc[T] {
	return &FreeListAlloc[T]{}
}

func (f *FreeListAlloc[T]) Alloc() (T, error) {
	if len(f.usedThenFreedIDs) > 0 {
		// Prefer to re-use a previously-used ID.
		id := f.usedThenFreedIDs[len(f.usedThenFreedIDs)-1]
		f.usedThenFreedIDs = f.usedThenFreedIDs[:len(f.usedThenFreedIDs)-1]
		return id, nil
	}
	// Try to mint a new ID.
	id := f.lastMintedID + 1
	if id == 0 {
		// We wrapped, so we're out of IDs.
		return 0, ErrOutOfIDs
	}
	f.lastMintedID = id
	return id, nil
}

func (f *FreeListAlloc[T]) Free(id T) {
	f.usedThenFreedIDs = append(f.usedThenFreedIDs, id)
}

func (f *FreeListAlloc[T]) Avail() T {
	total := T(0) - 1
	num := total - f.lastMintedID
	num += T(len(f.usedThenFreedIDs))
	return num
}
