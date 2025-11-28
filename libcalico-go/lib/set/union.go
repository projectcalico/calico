// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package set

import (
	"sort"
)

// IterUnion iterates over the values in the union of the given sets.  For
// small numbers of sets, it can avoid allocating an actual union set.
// Iteration continues while the passed in func returns true.
func IterUnion[T comparable](sets []Set[T], f func(item T) bool) {
	if len(sets) == 0 {
		return
	}

	if len(sets) == 1 {
		for item := range sets[0].All() {
			if !f(item) {
				break
			}
		}
		return
	}

	if len(sets) < 5 {
		// We only have a few sets, avoid allocating a "seen" set, which
		// could end up being large if the largest set is large.
		sort.Slice(sets, func(i, j int) bool {
			// Sort biggest set first so that we have fewer callbacks from the
			// later sets.
			return sets[j].Len() < sets[i].Len()
		})
		stop := false
	setsLoop:
		for i, s1 := range sets {
			for item := range s1.All() {
				// To check if we've seen this item before, look for it in
				// the sets we've already scanned.
				for j := 0; j < i; j++ {
					if sets[j].Contains(item) {
						continue setsLoop
					}
				}
				if !f(item) {
					stop = true
					break
				}
			}
			if stop {
				return
			}
		}
		return
	}

	// We have a lot of sets, allocate a set to keep track of what we've seen.
	seen := New[T]()
	stop := false
	for i, s := range sets {
		for item := range s.All() {
			if i != 0 && seen.Contains(item) {
				continue
			}
			if !f(item) {
				stop = true
				break
			}
			if i < len(sets)-1 {
				seen.Add(item)
			}
		}
		if stop {
			return
		}
	}
}
