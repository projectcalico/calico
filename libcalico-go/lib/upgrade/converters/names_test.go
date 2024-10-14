// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package converters

import (
	"net"
	"strings"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var namesTable = []TableEntry{
	Entry("Convert name abcdef", "abcdef", "abcdef", false),
	Entry("Convert name Abcdef", "Abcdef", "abcdef", true),
	Entry("Convert name abc-def", "abc-def", "abc-def", false),
	Entry("Convert name abc---def", "abc---def", "abc---def", false),
	Entry("Convert name abc/def", "abc/def", "abc.def", true),
	Entry("Convert name abc$$def", "abc$$def", "abc-def", true),
	Entry("Convert name abc$!$def", "abc$!$def", "abc-def", true),
	Entry("Convert name abc..def", "abc..def", "abc.def", true),
	Entry("Convert name abc...def", "abc...def", "abc.def", true),
	Entry("Convert name abc.-def", "abc.-def", "abc.def", true),
	Entry("Convert name abc.-.def", "abc.-.def", "abc.def", true),
	Entry("Convert name abc-.def", "abc-.def", "abc.def", true),
	Entry("Convert name abc-.-def", "abc-.-def", "abc.def", true),
	Entry("Convert name aBcDe019", "aBcDe019", "abcde019", true),
	Entry("Convert name abc$def", "abc$def", "abc-def", true),
	Entry("Convert name -abc.def", "-abc.def", "abc.def", true),
	Entry("Convert name abc.def-", "abc.def-", "abc.def", true),
	Entry("Convert name .abc.def", ".abc.def", "abc.def", true),
	Entry("Convert name abc.def.", "abc.def.", "abc.def", true),
	Entry("Convert name -.abc.def", "-.abc.def", "abc.def", true),
	Entry("Convert name abc.def.-", "abc.def.-", "abc.def", true),
	Entry("Convert name $ABC/DeF-123.-456!", "$ABC/DeF-123.-456!", "abc.def-123.456", true),
}

var _ = DescribeTable("v1->v3 name conversion tests",
	func(v1Name string, v3Name string, expectQualifier bool) {
		// Get the converted name.
		c1 := convertName(v1Name)
		if !expectQualifier {
			// No qualifier is expected, the names should match exactly.
			Expect(c1).To(Equal(v3Name))
		} else {
			// A qualifier is expected, the first part of the name should match and the
			// last 9 chars should be the qualifier.
			Expect(c1[:len(c1)-9]).To(Equal(v3Name))
			Expect(c1[len(c1)-9:]).To(MatchRegexp("[-][0-9a-f]{8}"))

			// Convert an upper case variant of the input.  The first part of the name should
			// match and the last 9 chars should be the qualifier - however the two converted
			// names should be different.
			c2 := convertName(strings.ToUpper(v1Name))
			Expect(c2[:len(c2)-9]).To(Equal(v3Name))
			Expect(c2[len(c2)-9:]).To(MatchRegexp("[-][0-9a-f]{8}"))
			Expect(c2).NotTo(Equal(c1))
		}
	},

	namesTable...,
)

var namesNoDotsTable = []TableEntry{
	Entry("Convert name abcdef", "abcdef", "abcdef", false),
	Entry("Convert name Abcdef", "Abcdef", "abcdef", true),
	Entry("Convert name abc-def", "abc-def", "abc-def", false),
	Entry("Convert name abc---def", "abc---def", "abc---def", false),
	Entry("Convert name abc/def", "abc/def", "abc-def", true),
	Entry("Convert name abc..def", "abc..def", "abc-def", true),
	Entry("Convert name abc...def", "abc...def", "abc-def", true),
	Entry("Convert name abc.-def", "abc.-def", "abc-def", true),
	Entry("Convert name abc.-.def", "abc.-.def", "abc-def", true),
	Entry("Convert name abc-.def", "abc-.def", "abc-def", true),
	Entry("Convert name abc-.-def", "abc-.-def", "abc-def", true),
	Entry("Convert name aBcDe019", "aBcDe019", "abcde019", true),
	Entry("Convert name abc$def", "abc$def", "abc-def", true),
	Entry("Convert name -abc.def", "-abc.def", "abc-def", true),
	Entry("Convert name abc.def-", "abc.def-", "abc-def", true),
	Entry("Convert name .abc.def", ".abc.def", "abc-def", true),
	Entry("Convert name abc.def.", "abc.def.", "abc-def", true),
	Entry("Convert name -.abc.def", "-.abc.def", "abc-def", true),
	Entry("Convert name abc.def.-", "abc.def.-", "abc-def", true),
	Entry("Convert name $ABC/DeF-123.-456!", "$ABC/DeF-123.-456!", "abc-def-123-456", true),
}

var _ = DescribeTable("v1->v3 name conversion tests (no dots)",
	func(v1Name, v3Name string, expectQualifier bool) {
		// Get the converted name.
		c1 := convertNameNoDots(v1Name)
		if !expectQualifier {
			// No qualifier is expected, the names should match exactly.
			Expect(c1).To(Equal(v3Name))
		} else {
			// A qualifier is expected, the first part of the name should match and the
			// last 9 chars should be the qualifier.
			Expect(c1[:len(c1)-9]).To(Equal(v3Name))
			Expect(c1[len(c1)-9:]).To(MatchRegexp("[-][0-9a-f]{8}"))

			// Convert an upper case variant of the input.  The first part of the name should
			// match and the last 9 chars should be the qualifier - however the two converted
			// names should be different.
			c2 := convertNameNoDots(strings.ToUpper(v1Name))
			Expect(c2[:len(c2)-9]).To(Equal(v3Name))
			Expect(c2[len(c2)-9:]).To(MatchRegexp("[-][0-9a-f]{8}"))
			Expect(c2).NotTo(Equal(c1))
		}
	},

	namesNoDotsTable...,
)

var ipToNameTable = []TableEntry{
	Entry("Parse IP 192.168.0.1", net.ParseIP("192.168.0.1"), "192-168-0-1"),
	Entry("Parse IP Aa:Bb::", net.ParseIP("Aa:bb::"), "00aa-00bb-0000-0000-0000-0000-0000-0000"),
	Entry("Parse IP 0Aa:bb::50", net.ParseIP("0Aa:bb::50"), "00aa-00bb-0000-0000-0000-0000-0000-0050"),
}

var _ = DescribeTable("v1->v3 IP to name conversion tests",
	func(ip net.IP, name string) {
		Expect(convertIpToName(ip)).To(Equal(name), ip.String())
	},
	ipToNameTable...,
)

var nodeNamesTable = []TableEntry{
	Entry("Convert abc-def", "abc-def", "abc-def"),
	Entry("Convert abc---def", "abc---def", "abc---def"),
	Entry("Convert abc/def", "abc/def", "abc.def"),
	Entry("Convert abc$$def", "abc$$def", "abc-def"),
	Entry("Convert abc$!$def", "abc$!$def", "abc-def"),
	Entry("Convert abc..def", "abc..def", "abc.def"),
	Entry("Convert abc...def", "abc...def", "abc.def"),
	Entry("Convert abc.-def", "abc.-def", "abc.def"),
	Entry("Convert abc.-.def", "abc.-.def", "abc.def"),
	Entry("Convert abc-.def", "abc-.def", "abc.def"),
	Entry("Convert abc-.-def", "abc-.-def", "abc.def"),
	Entry("Convert aBcDe019", "aBcDe019", "abcde019"),
	Entry("Convert abc$def", "abc$def", "abc-def"),
	Entry("Convert -abc.def", "-abc.def", "abc.def"),
	Entry("Convert abc.def-", "abc.def-", "abc.def"),
	Entry("Convert .abc.def", ".abc.def", "abc.def"),
	Entry("Convert abc.def.", "abc.def.", "abc.def"),
	Entry("Convert -.abc.def", "-.abc.def", "abc.def"),
	Entry("Convert abc.def.-", "abc.def.-", "abc.def"),
	Entry("Convert $ABC/DEF-123.-456!", "$ABC/DEF-123.-456!", "abc.def-123.456"),
}

var _ = DescribeTable("v1->v3 node name conversion tests",
	func(before, after string) {
		Expect(ConvertNodeName(before)).To(Equal(after), before)
	},
	nodeNamesTable...,
)
