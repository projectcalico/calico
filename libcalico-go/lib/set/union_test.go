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
	"fmt"
	"testing"

	. "github.com/onsi/gomega"
)

func TestIterUnion(t *testing.T) {
	RegisterTestingT(t)
	for _, testSets := range [][][]int{
		nil,
		{},
		{nil},
		{{}},
		{{1}},
		{{1}, {2}},
		{{1, 2}, {2}},
		{{1, 2}, {2}, {1, 2, 3}},
		{{1, 2}, {2}, {1, 2, 3}, {2, 3, 4, 5}},
		{{1, 2}, {2}, {1, 2, 3}, {2, 3, 4, 5}, {2, 6}},
		{{1, 2}, {2}, {1, 2, 3}, {2, 3, 4, 5}, {2, 6}, {2, 3}},
	} {
		testSets := testSets

		// First sub-test verifies the actual union is correct.
		t.Run(fmt.Sprint(testSets), func(t *testing.T) {
			for i := 0; i < 100; i++ {
				expected := New[int]()
				var sets []Set[int]
				for _, i := range testSets {
					// We trust FromArray in this test; it is tested elsewhere...
					sets = append(sets, FromArray(i))
					// Trivial implementation of union for us to compare against.
					for _, item := range i {
						expected.Add(item)
					}
				}
				actual := New[int]()
				IterUnion(sets, func(item int) bool {
					Expect(actual.Contains(item)).To(BeFalse(), fmt.Sprintf("IterUnion produced duplicate value: %v", item))
					actual.Add(item)
					return true
				})
				Expect(actual).To(Equal(expected), fmt.Sprintf("Union of %v was incorrect", sets))
			}
		})

		// Second sub-test verifies that we can stop by returning false.
		t.Run(fmt.Sprint("Stop", testSets), func(t *testing.T) {
			var sets []Set[int]
			for _, i := range testSets {
				// We trust FromArray in this test; it is tested elsewhere...
				sets = append(sets, FromArray(i))
			}
			actual := New[int]()
			IterUnion(sets, func(item int) bool {
				Expect(actual.Len()).To(BeZero(), "IterUnion failed to stop after first item")
				actual.Add(item)
				return false
			})
		})
	}
}
