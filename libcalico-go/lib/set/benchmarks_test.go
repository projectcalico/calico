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
	"runtime"
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
