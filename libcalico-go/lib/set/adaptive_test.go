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
	"runtime"
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
})

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
