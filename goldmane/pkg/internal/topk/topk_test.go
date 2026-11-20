// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package topk_test

import (
	"cmp"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/internal/topk"
)

// TestKeeperMatchesFullSort checks that a Keeper holds the same values as the head of a full
// sort, across limits below, at and above the number of values offered, with duplicates.
func TestKeeperMatchesFullSort(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for _, n := range []int{0, 1, 2, 7, 100, 1000} {
		values := make([]int, n)
		for i := range values {
			values[i] = rng.IntN(n/2 + 1)
		}
		want := append([]int{}, values...)
		slices.Sort(want)

		for _, limit := range []int{0, 1, 2, 5, n - 1, n, n + 3} {
			if limit < 0 {
				continue
			}
			k := topk.New(limit, cmp.Compare[int], n)
			for _, v := range values {
				k.Offer(v)
			}
			require.Equal(t, want[:min(limit, n)], k.Sorted(), "n %d, limit %d", n, limit)
		}
	}
}

// TestKeeperKeepsEarliestOfTies checks that once full, a Keeper drops a value that ties with its
// last kept value, so of equal values the earliest offered is kept, while a value that sorts
// before the last still replaces it.
func TestKeeperKeepsEarliestOfTies(t *testing.T) {
	byKey := func(a, b keyed) int { return cmp.Compare(a.key, b.key) }

	k := topk.New(2, byKey, 0)
	for i, key := range []int{1, 2, 2, 0} {
		k.Offer(keyed{key: key, order: i})
	}
	require.Equal(t, []keyed{{key: 0, order: 3}, {key: 1, order: 0}}, k.Sorted())

	k = topk.New(2, byKey, 0)
	for i, key := range []int{1, 2, 2} {
		k.Offer(keyed{key: key, order: i})
	}
	require.Equal(t, []keyed{{key: 1, order: 0}, {key: 2, order: 1}}, k.Sorted())
}

// keyed is a value that sorts on key, with order recording when it was offered.
type keyed struct {
	key   int
	order int
}

func ExampleKeeper() {
	k := topk.New(3, cmp.Compare[int], 0)
	for _, v := range []int{9, 4, 7, 1, 8, 3} {
		k.Offer(v)
	}
	fmt.Println(k.Sorted())

	// Output: [1 3 4]
}

func BenchmarkKeeper(b *testing.B) {
	rng := rand.New(rand.NewPCG(1, 2))
	values := make([]int, 200_000)
	for i := range values {
		values[i] = rng.Int()
	}
	b.ReportAllocs()
	for b.Loop() {
		k := topk.New(20, cmp.Compare[int], 20)
		for _, v := range values {
			k.Offer(v)
		}
		k.Sorted()
	}
}
