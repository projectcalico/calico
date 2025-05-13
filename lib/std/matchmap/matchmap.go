package matchmap

import (
	"iter"
	"slices"

	"golang.org/x/exp/constraints"

	"github.com/projectcalico/calico/lib/std/bimap"
	"github.com/projectcalico/calico/lib/std/bitset"
	"github.com/projectcalico/calico/lib/std/idalloc"
)

type MatchMap[A, B comparable, ID constraints.Unsigned] struct {
	aIDs *IDAllocTracker[A, ID]
	bIDs *IDAllocTracker[B, ID]

	aToB []*bitset.BitSet
}

func NewMatchMap[A, B comparable, ID constraints.Unsigned]() *MatchMap[A, B, ID] {
	return &MatchMap[A, B, ID]{
		aIDs: NewIDAllocTracker[A, ID](),
		bIDs: NewIDAllocTracker[B, ID](),
	}
}

func (mm *MatchMap[A, B, ID]) MustPut(a A, b B) {
	if err := mm.Put(a, b); err != nil {
		panic(err)
	}
}

func (mm *MatchMap[A, B, ID]) Put(a A, b B) error {
	aID, err := mm.aIDs.GetOrAllocID(a)
	if err != nil {
		return err
	}
	bID, err := mm.bIDs.GetOrAllocID(b)
	if err != nil {
		return err
	}
	mm.ensureRow(aID)
	row := mm.aToB[aID-1] // 0 ID is forbidden so we store ID-1.
	row.Add(int(bID - 1))
	return nil
}

func (mm *MatchMap[A, B, ID]) Get(a A, b B) bool {
	aID, ok := mm.aIDs.GetID(a)
	if !ok {
		return false
	}
	bID, ok := mm.bIDs.GetID(b)
	if !ok {
		return false
	}
	if ID(len(mm.aToB)) <= aID-1 {
		return false
	}
	row := mm.aToB[aID-1]
	return row != nil && row.Contains(int(bID-1))
}

func (mm *MatchMap[A, B, ID]) Delete(a A, b B) {
	aID, ok := mm.aIDs.GetID(a)
	if !ok {
		return
	}
	bID, ok := mm.bIDs.GetID(b)
	if !ok {
		return
	}
	if ID(len(mm.aToB)) <= aID-1 {
		return
	}
	row := mm.aToB[aID-1]
	if row == nil {
		return
	}
	row.Discard(int(bID - 1))
	if row.Len() == 0 {
		mm.aToB[aID-1] = nil
		mm.aIDs.Release(a)
	}
	for range mm.AllAsForB(b) {
		return // FIXME count the Bs
	}
	mm.bIDs.Release(b)
}

func (mm *MatchMap[A, B, ID]) ensureRow(aID ID) {
	if len(mm.aToB) < int(aID) {
		mm.aToB = slices.Grow(mm.aToB, int(aID))
		for len(mm.aToB) < int(aID) {
			mm.aToB = append(mm.aToB, nil)
		}
	}
	if mm.aToB[aID-1] != nil {
		return
	}
	mm.aToB[aID-1] = bitset.NewBitSet()
}

func (mm *MatchMap[A, B, ID]) AllBsForA(a A) iter.Seq[B] {
	return func(yield func(B) bool) {
		aID, ok := mm.aIDs.GetID(a)
		if !ok {
			return
		}
		row := mm.aToB[aID-1]
		if row == nil {
			return
		}
		for bIDSubOne := range row.All() {
			bID := ID(bIDSubOne + 1)
			b, ok := mm.bIDs.GetItem(bID)
			if !ok {
				panic("failed to look up item from its ID; MatchMap must be inconsistent")
			}
			if !yield(b) {
				return
			}
		}
	}
}

func (mm *MatchMap[A, B, ID]) AllAsForB(b B) iter.Seq[A] {
	return func(yield func(A) bool) {
		bID, ok := mm.bIDs.GetID(b)
		if !ok {
			return
		}
		bBit := int(bID - 1)
		for aIDSubOne, row := range mm.aToB {
			if row == nil {
				continue
			}
			if row.Contains(bBit) {
				a, ok := mm.aIDs.GetItem(ID(aIDSubOne + 1))
				if !ok {
					panic("failed to look up item from its ID; MatchMap must be inconsistent")
				}
				if !yield(a) {
					return
				}
			}
		}
	}
}

func (mm *MatchMap[A, B, ID]) ContainsKey(key A) bool {
	_, ok := mm.aIDs.GetID(key)
	return ok
}

func (mm *MatchMap[A, B, ID]) LenA() int {
	return mm.aIDs.NumAllocated()
}

func (mm *MatchMap[A, B, ID]) AllBs() iter.Seq[B] {
	return mm.bIDs.AllItems()
}

type IDAllocTracker[T comparable, ID constraints.Unsigned] struct {
	allocatedIDs *bimap.BiMap[T, ID]
	allocator    *idalloc.FreeListAlloc[ID]
}

func NewIDAllocTracker[T comparable, ID constraints.Unsigned]() *IDAllocTracker[T, ID] {
	return &IDAllocTracker[T, ID]{
		allocatedIDs: bimap.NewBiMap[T, ID](),
		allocator:    idalloc.NewFreeListAlloc[ID](),
	}
}

func (at *IDAllocTracker[T, ID]) GetID(item T) (ID, bool) {
	return at.allocatedIDs.GetB(item)
}

func (at *IDAllocTracker[T, ID]) GetItem(id ID) (T, bool) {
	return at.allocatedIDs.GetA(id)
}

func (at *IDAllocTracker[T, ID]) GetOrAllocID(item T) (ID, error) {
	id, ok := at.allocatedIDs.GetB(item)
	if !ok {
		var err error
		id, err = at.allocator.Alloc()
		if err != nil {
			return 0, err
		}
		at.allocatedIDs.Put(item, id)
	}
	return id, nil
}

func (at *IDAllocTracker[T, ID]) Release(item T) {
	id, ok := at.allocatedIDs.GetB(item)
	if !ok {
		return
	}
	at.allocatedIDs.DeleteA(item)
	at.allocator.Free(id)
}

func (at *IDAllocTracker[T, ID]) NumAllocated() int {
	return at.allocatedIDs.Len()
}

func (at *IDAllocTracker[T, ID]) AllItems() iter.Seq[T] {
	return func(yield func(T) bool) {
		for a, _ := range at.allocatedIDs.All() {
			if !yield(a) {
				return
			}
		}
	}
}
