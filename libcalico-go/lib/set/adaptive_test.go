// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"runtime"
	"sort"
	"testing"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func BenchmarkAdaptive1Items(b *testing.B) {
	benchmarkSet(b, makeAdaptive, 1)
}

func BenchmarkAdaptive2Items(b *testing.B) {
	benchmarkSet(b, makeAdaptive, 2)
}

func BenchmarkAdaptive10Items(b *testing.B) {
	benchmarkSet(b, makeAdaptive, 10)
}

func BenchmarkAdaptive100Items(b *testing.B) {
	benchmarkSet(b, makeAdaptive, 100)
}

func BenchmarkMap1Items(b *testing.B) {
	benchmarkSet(b, makeMap, 1)
}

func BenchmarkMap2Items(b *testing.B) {
	benchmarkSet(b, makeMap, 2)
}

func BenchmarkMap10Items(b *testing.B) {
	benchmarkSet(b, makeMap, 10)
}

func BenchmarkMap100Items(b *testing.B) {
	benchmarkSet(b, makeMap, 100)
}

func makeAdaptive() set.Set[int] {
	return set.NewAdaptive[int]()
}

func makeMap() set.Set[int] {
	return set.New[int]()
}

func benchmarkSet(b *testing.B, factory func() set.Set[int], items int) {
	b.Run("Add", func(b *testing.B) {
		b.ReportAllocs()
		var s set.Set[int]
		for i := 0; i < b.N; i++ {
			s = factory()
			for j := 0; j < items; j++ {
				s.Add(j)
			}
		}
		runtime.KeepAlive(s)
	})
	b.Run("Contains", func(b *testing.B) {
		b.ReportAllocs()
		s := factory()
		for j := 0; j < items; j++ {
			s.Add(j)
		}
		var x bool
		for i := 0; i < b.N; i++ {
			x = s.Contains(i % items)
		}
		runtime.KeepAlive(x)
	})
}

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
			s1.Iter(func(item string) error {
				if !s2.Contains(item) {
					t.Fatal("Set 2 does not contain item")
				}
				return nil
			})
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

var _ = Describe("Adaptive set", func() {
	var s set.Set[int]
	BeforeEach(func() {
		s = set.NewAdaptive[int]()
	})

	It("should be empty", func() {
		Expect(s.Len()).To(BeZero())
	})
	It("should stringify", func() {
		Expect(s.String()).To(Equal("set.Set{}"))
	})
	It("should iterate over no items", func() {
		called := false
		s.Iter(func(item int) error {
			called = true
			return nil
		})
		Expect(called).To(BeFalse())
	})
	It("should do nothing on clear", func() {
		s.Clear()
		Expect(s.Len()).To(BeZero())
	})

	Describe("Set created by FromArray", func() {
		BeforeEach(func() {
			s = set.FromArray([]int{1, 2})
		})
		It("should contain 1", func() {
			Expect(s.Contains(1)).To(BeTrue())
		})
		It("should contain 2", func() {
			Expect(s.Contains(2)).To(BeTrue())
		})
		It("should not contain 3", func() {
			Expect(s.Contains(3)).To(BeFalse())
		})
		It("should stringify", func() {
			Expect(s.String()).To(Or(
				Equal("set.Set{1,2}"),
				Equal("set.Set{2,1}")))
		})
	})

	Describe("Set created by From", func() {
		BeforeEach(func() {
			s = set.From([]int{1, 2}...)
		})
		It("should contain 1", func() {
			Expect(s.Contains(1)).To(BeTrue())
		})
		It("should contain 2", func() {
			Expect(s.Contains(2)).To(BeTrue())
		})
		It("should not contain 3", func() {
			Expect(s.Contains(3)).To(BeFalse())
		})
		It("should contain all of {1, 2}", func() {
			Expect(s.ContainsAll(set.From(1, 2))).To(BeTrue())
		})
		It("should not contain all of {1, 2, 3}", func() {
			Expect(s.ContainsAll(set.From(1, 2, 3))).To(BeFalse())
		})
	})

	Describe("after adding 1 and 2", func() {
		BeforeEach(func() {
			s.Add(1)
			s.Add(2)
			s.Add(2) // Duplicate should have no effect
		})
		It("should contain 1", func() {
			Expect(s.Contains(1)).To(BeTrue())
		})
		It("should contain 2", func() {
			Expect(s.Contains(2)).To(BeTrue())
		})
		It("should not contain 3", func() {
			Expect(s.Contains(3)).To(BeFalse())
		})
		It("should iterate over 1 and 2 in some order", func() {
			seen1 := false
			seen2 := false
			s.Iter(func(item int) error {
				if item == 1 {
					Expect(seen1).To(BeFalse())
					seen1 = true
				} else if item == 2 {
					Expect(seen2).To(BeFalse())
					seen2 = true
				} else {
					Fail("Unexpected item")
				}
				return nil
			})
			Expect(seen1).To(BeTrue())
			Expect(seen2).To(BeTrue())
		})
		It("should allow remove during iteration", func() {
			s.Iter(func(item int) error {
				if item == 1 {
					return set.RemoveItem
				}
				return nil
			})
			Expect(s.Contains(1)).To(BeFalse())
			Expect(s.Contains(2)).To(BeTrue())
		})
		It("should support stopping iteration", func() {
			iterationStarted := false
			s.Iter(func(item int) error {
				if iterationStarted {
					Fail("Iteration continued after stop")
				}
				iterationStarted = true
				return set.StopIteration
			})
			Expect(s.Contains(1)).To(BeTrue())
			Expect(s.Contains(2)).To(BeTrue())
		})
		It("can copy a Set", func() {
			c := s.Copy()
			Expect(c.Len()).To(Equal(s.Len()))
			Expect(c).NotTo(BeIdenticalTo(s)) // Check they're not the same object.
			Expect(c.ContainsAll(s)).To(BeTrue())
			Expect(s.ContainsAll(c)).To(BeTrue())
		})
		It("should correctly determine set equality", func() {
			c := s.Copy()
			Expect(c.Equals(s)).To(BeTrue())
			Expect(s.Equals(c)).To(BeTrue())
			c.Add(3)
			Expect(c.Equals(s)).To(BeFalse())
			Expect(s.Equals(c)).To(BeFalse())
			c.Discard(2)
			Expect(c.Equals(s)).To(BeFalse())
			Expect(s.Equals(c)).To(BeFalse())
			c.Add(2)
			c.Discard(3)
			Expect(c.Equals(s)).To(BeTrue(), fmt.Sprintf("%s != %s", c, s))
			Expect(s.Equals(c)).To(BeTrue())
		})

		Describe("after removing 2", func() {
			BeforeEach(func() {
				s.Discard(2)
			})
			It("should contain 1", func() {
				Expect(s.Contains(1)).To(BeTrue())
			})
			It("should not contain 2", func() {
				Expect(s.Contains(2)).To(BeFalse())
			})
			It("should not contain 3", func() {
				Expect(s.Contains(3)).To(BeFalse())
			})
		})
		Describe("after using AddAll to add 2, 3, 4", func() {
			BeforeEach(func() {
				s.AddAll([]int{2, 3, 4})
			})
			It("should contain 1", func() {
				Expect(s.Contains(1)).To(BeTrue())
			})
			It("should contain 2", func() {
				Expect(s.Contains(2)).To(BeTrue())
			})
			It("should contain 3", func() {
				Expect(s.Contains(3)).To(BeTrue())
			})
			It("should contain 4", func() {
				Expect(s.Contains(4)).To(BeTrue())
			})
		})

		Describe("after Clear()", func() {
			BeforeEach(func() {
				s.Clear()
			})
			It("should be empty", func() {
				Expect(s.Len()).To(BeZero())
			})
		})
	})
})
