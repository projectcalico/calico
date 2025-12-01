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

package set_test

import (
	"sort"
	"testing"

	. "github.com/onsi/ginkgo"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("Adaptive set", func() {
	describeSetTests(
		func() set.Set[int] {
			return set.NewAdaptive[int]()
		},
		func(is []int) set.Set[int] { return set.AdaptiveFromArray(is) },
		func(is ...int) set.Set[int] { return set.AdaptiveFrom(is...) },
	)

	It("should be constructable via FromAdaptive[int]", func() {
		s1 := set.AdaptiveFrom(1, 2, 3)
		s2 := set.From(1, 2, 3)
		if !s1.Equals(s2) || !s2.Equals(s1) {
			Fail("Sets are not equal")
		}
	})

	It("should be constructable via FromAdaptive[string]", func() {
		s1 := set.AdaptiveFrom("1", "2", "3")
		s2 := set.From("1", "2", "3")
		if !s1.Equals(s2) || !s2.Equals(s1) {
			Fail("Sets are not equal")
		}
	})

	Describe("Adaptive.All() iterator", func() {
		It("should iterate over small array-backed set", func() {
			s := set.AdaptiveFrom(1, 2, 3)
			seen := make(map[int]bool)
			for item := range s.All() {
				seen[item] = true
			}
			if len(seen) != 3 {
				Fail("Did not see all items")
			}
		})

		It("should allow discarding during iteration of array-backed set", func() {
			s := set.AdaptiveFrom(1, 2, 3, 4, 5)
			for item := range s.All() {
				if item%2 == 0 {
					s.Discard(item)
				}
			}
			if s.Len() != 3 {
				Fail("Expected 3 items remaining")
			}
			if !s.Contains(1) || !s.Contains(3) || !s.Contains(5) {
				Fail("Expected odd numbers to remain")
			}
		})

		It("should iterate over large map-backed set", func() {
			// Create a set large enough to trigger map backing (>16 items)
			items := make([]int, 20)
			for i := range items {
				items[i] = i
			}
			s := set.AdaptiveFromArray(items)
			seen := make(map[int]bool)
			for item := range s.All() {
				seen[item] = true
			}
			if len(seen) != 20 {
				Fail("Did not see all items")
			}
		})

		It("should allow discarding during iteration of map-backed set", func() {
			// Create a set large enough to trigger map backing (>16 items)
			items := make([]int, 20)
			for i := range items {
				items[i] = i
			}
			s := set.AdaptiveFromArray(items)
			for item := range s.All() {
				if item%2 == 0 {
					s.Discard(item)
				}
			}
			if s.Len() != 10 {
				Fail("Expected 10 items remaining")
			}
		})

		It("should support early termination", func() {
			s := set.AdaptiveFrom(1, 2, 3, 4, 5)
			count := 0
			for range s.All() {
				count++
				if count >= 2 {
					break
				}
			}
			if count != 2 {
				Fail("Expected to stop after 2 iterations")
			}
		})
	})
})

func FuzzAdaptiveSet(f *testing.F) {
	f.Add("a", "ab")
	f.Add("aa", "ab")
	f.Add("ab", "d")
	f.Add("abb", "ab")
	f.Add("aaabc", "abbbbc")
	f.Add("aaabc", "g")
	f.Add("abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz")
	f.Fuzz(func(t *testing.T, itemsToAdd, itemsToDel string) {
		s1 := set.NewAdaptive[string]()
		s2 := set.New[string]()
		for i := 0; i < len(itemsToAdd); i++ {
			item := itemsToAdd[i : i+1]
			s1.Add(item)
			s2.Add(item)

			if !s1.Equals(s2) || !s2.Equals(s1) {
				t.Fatal("Sets are not equal")
			}
			for item := range s1.All() {
				if !s2.Contains(item) {
					t.Fatal("Set 2 does not contain item")
				}
			}
			if !s1.Contains(item) {
				t.Fatal("Set does not contain item")
			}
			if !s1.ContainsAll(s2) {
				t.Fatal("Set does not contain all items")
			}

			sl1 := s1.Slice()
			sl2 := s2.Slice()
			if len(sl1) != len(sl2) {
				t.Fatal("Slices are not the same length")
			}
			sort.Strings(sl1)
			sort.Strings(sl2)
			for i := 0; i < len(sl1); i++ {
				if sl1[i] != sl2[i] {
					t.Fatal("Slices are not the same")
				}
			}
		}
		stopped := false
		s1.Iter(func(item string) error {
			if stopped {
				t.Fatal("Iteration continued after stop")
			}
			stopped = true
			if !s2.Contains(item) {
				t.Fatal("Set 2 does not contain item")
			}
			return set.StopIteration
		})
		for i := 0; i < len(itemsToDel); i++ {
			item := itemsToDel[i : i+1]
			s1.Discard(item)
			s2.Discard(item)

			if !s1.Equals(s2) || !s2.Equals(s1) {
				t.Fatal("Sets are not equal")
			}
			if s1.Contains(item) {
				t.Fatal("Set still contained item")
			}
		}
	})
}
