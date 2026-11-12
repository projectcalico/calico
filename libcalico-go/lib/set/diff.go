// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.
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

// Difference returns a new set containing the items that are in a but not in b.
func Difference[T comparable](a, b Set[T]) Set[T] {
	result := New[T]()
	for item := range a.All() {
		if !b.Contains(item) {
			result.Add(item)
		}
	}
	return result
}

// IterDifferences iterates through the set of items that are in A but not in B, and the set that are in B but not in A.
func IterDifferences[T comparable](a, b Set[T], aNotB, bNotA func(item T) error) {
	a.Iter(func(item T) error {
		if !b.Contains(item) {
			return aNotB(item)
		}
		return nil
	})
	b.Iter(func(item T) error {
		if !a.Contains(item) {
			return bNotA(item)
		}
		return nil
	})
}
