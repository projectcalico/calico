// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package stringutils_test

import (
	"sort"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/stringutils"
)

var _ = DescribeTable("CommonPrefix tests",
	func(input []string, expected string) {
		By("giving correct result in input order")
		Expect(CommonPrefix(input)).To(Equal(expected))

		By("giving correct result in reverse order")
		for i := 0; i < len(input)/2; i++ {
			temp := input[i]
			input[i] = input[len(input)-i-1]
			input[len(input)-i-1] = temp
		}
		Expect(CommonPrefix(input)).To(Equal(expected))

		By("giving correct result in sorted order")
		sort.Strings(input)
		Expect(CommonPrefix(input)).To(Equal(expected))
	},
	Entry("nil array", []string(nil), ""),
	Entry("Empty array", []string{}, ""),
	Entry("Empty string", []string{""}, ""),
	Entry("Empty strings", []string{"", ""}, ""),
	Entry("Empty string and another string", []string{"", "a"}, ""),
	Entry("Empty string and another string", []string{"", "abcdef"}, ""),
	Entry("Empty string in middle", []string{"abcd", "", "abcdef"}, ""),
	Entry("No common prefix", []string{"a", "b"}, ""),
	Entry("No common prefix multiple", []string{"a", "a", "b"}, ""),
	Entry("No common prefix multiple", []string{"a", "b", "b"}, ""),
	Entry("Common prefix equal to string", []string{"a", "a"}, "a"),
	Entry("Common prefix not equal to string", []string{"a", "ab"}, "a"),
	Entry("Common prefix not equal to string", []string{"abc", "abcdef", "abdef"}, "ab"),
	Entry("Common prefix shared between first and last", []string{"abd", "abcdef", "abcef"}, "ab"),
)
