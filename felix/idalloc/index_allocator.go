// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package idalloc

import (
	"errors"
	"sort"

	"github.com/golang-collections/collections/stack"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type IndexRange struct {
	Min, Max int
}

// ByIndex sorts collections of IndexRange structs in order of their starting/lower index
type ByLowerIndex []IndexRange

// Len is the number of indexranges in the collection
func (i ByLowerIndex) Len() int { return len(i) }

// Less reports whether the element with index a
// must sort before the element with index b.
func (i ByLowerIndex) Less(a, b int) bool { return i[a].Min < i[b].Min }

// Swap swaps the elements with indexes a and b.
func (i ByLowerIndex) Swap(a, b int) { i[a], i[b] = i[b], i[a] }

// hasOverlap checks whether any adjacent indexRanges have overlapping indexes
func (a IndexRange) Overlaps(b IndexRange) bool {
	if a.Max > b.Max {
		return a.Min <= b.Max
	} else {
		return b.Min <= a.Max
	}
}

type IndexAllocator struct {
	indexStack *stack.Stack
}

func NewIndexAllocator(indexRanges ...IndexRange) *IndexAllocator {
	// sort index ranges in descending order of their Min bound
	if len(indexRanges) > 1 {
		sort.Sort(sort.Reverse(ByLowerIndex(indexRanges)))
	}

	r := &IndexAllocator{
		indexStack: stack.New(),
	}

	for j, indexRange := range indexRanges {
		// ensure no adjacent ranges overlap
		if j > 0 {
			lastIndexRange := indexRanges[j-1]
			if lastIndexRange.Overlaps(indexRange) {
				// truncate the current range if it overlaps with the preceding (higher) range
				indexRange.Max = lastIndexRange.Min - 1 //TODO - are range bounds inclusive or exclusive?
			}
		}

		// Push in reverse order so that the lowest index will come out first.
		for i := indexRange.Max; i >= indexRange.Min; i-- {
			r.indexStack.Push(i)
		}
	}
	return r
}

func (r *IndexAllocator) GrabIndex() (int, error) {
	if r.indexStack.Len() == 0 {
		return 0, errors.New("No more indices available")
	}
	return r.indexStack.Pop().(int), nil
}

func (r *IndexAllocator) ReleaseIndex(index int) {
	r.indexStack.Push(index)
}

func (r *IndexAllocator) GrabAllRemainingIndices() set.Set {
	remainingIndices := set.New()
	idx, err := r.GrabIndex()
	for err == nil {
		remainingIndices.Add(idx)
		idx, err = r.GrabIndex()
	}
	return remainingIndices
}
