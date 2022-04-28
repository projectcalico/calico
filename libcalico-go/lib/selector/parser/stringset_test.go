// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package parser_test

import (
	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"

	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("StringSet contains tests",
	func(input []string) {
		// Making a StringSet is destructive so start with a copy.
		var cpy []string
		if input != nil {
			cpy = make([]string, len(input))
			copy(cpy, input)
		}
		stringSet := parser.ConvertToStringSetInPlace(cpy)

		By("containing all the input values", func() {
			for _, s := range input {
				Expect(stringSet.Contains(s)).To(BeTrue(),
					fmt.Sprintf("input %v == %v didn't contain %v", input, stringSet, s))
			}
		})

		By("not containing unexpected values", func() {
			for _, s := range input {
				Expect(stringSet.Contains(s+"bogus")).To(BeFalse(),
					fmt.Sprintf("input %v == %v contained %vbogus", input, stringSet, s))
			}
		})

		By("Containing at most the number of input elements", func() {
			Expect(len(stringSet)).To(BeNumerically("<=", len(input)))
		})
	},
	Entry("nil", nil),
	Entry("Empty", []string{}),
	Entry("a", []string{"a"}),
	Entry("a, b", []string{"a", "b"}),
	Entry("a, b, c", []string{"a", "b", "c"}),
	Entry("a, b, c, d", []string{"a", "b", "c", "d"}),
	Entry("foo, bar, baz, baz", []string{"foo", "bar", "baz", "baz"}),
	Entry("foo, foo, baz, baz", []string{"foo", "foo", "baz", "baz"}),
)

var _ = DescribeTable("StringSet dedupe",
	func(input, expected []string) {
		// Making a StringSet is destructive so start with a copy.
		var cpy []string
		if input != nil {
			cpy = make([]string, len(input))
			copy(cpy, input)
		}
		stringSet := parser.ConvertToStringSetInPlace(cpy)
		Expect([]string(stringSet)).To(Equal(expected))
	},
	Entry("empty", []string{}, []string{}),
	Entry("without dupes", []string{"a", "b"}, []string{"a", "b"}),
	Entry("with dupes", []string{"b", "a", "b", "a"}, []string{"a", "b"}),
)
