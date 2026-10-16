// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intervals

import (
	"cmp"
	"fmt"
	"iter"
	"slices"
)

// Unsigned is restricted to unsigned types so that ^T(0) is the type's maximum.
type Unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// Set is a set of integers stored as closed intervals.  The zero value is
// empty.
type Set[T Unsigned] struct {
	intervals []interval[T]
	dirty     bool
}

type interval[T Unsigned] struct {
	min, max T
}

// Grow ensures space for another n calls to Add without reallocating.
func (s *Set[T]) Grow(n int) {
	s.intervals = slices.Grow(s.intervals, n)
}

// Add adds the closed interval [min, max] to the set.  Panics if min > max.
func (s *Set[T]) Add(min, max T) {
	if min > max {
		panic(fmt.Sprintf("intervals: invalid interval [%v, %v]", min, max))
	}
	s.intervals = append(s.intervals, interval[T]{min, max})
	s.dirty = true
}

// Coalesced returns the minimal set of disjoint, non-adjacent intervals
// covering the set, in ascending order.  It must not be called concurrently
// with Add, and Add must not be called while ranging over the result.
func (s *Set[T]) Coalesced() iter.Seq2[T, T] {
	s.coalesce()
	return func(yield func(T, T) bool) {
		for _, iv := range s.intervals {
			if !yield(iv.min, iv.max) {
				return
			}
		}
	}
}

// NumIntervals returns the number of intervals that Coalesced yields.
func (s *Set[T]) NumIntervals() int {
	s.coalesce()
	return len(s.intervals)
}

// coalesce sorts and merges the intervals in place.
func (s *Set[T]) coalesce() {
	if !s.dirty {
		return
	}
	s.dirty = false
	if len(s.intervals) <= 1 {
		return
	}
	slices.SortFunc(s.intervals, func(a, b interval[T]) int {
		return cmp.Compare(a.min, b.min)
	})

	// Intervals are sorted by min so, once cur reaches the type's max, it
	// covers everything after it.  This also means cur.max+1 never overflows.
	typeMax := ^T(0)
	w := 0
	for _, next := range s.intervals[1:] {
		cur := &s.intervals[w]
		if cur.max == typeMax {
			break
		}
		if next.min <= cur.max+1 {
			cur.max = max(cur.max, next.max)
			continue
		}
		w++
		s.intervals[w] = next
	}
	s.intervals = s.intervals[:w+1]
}
