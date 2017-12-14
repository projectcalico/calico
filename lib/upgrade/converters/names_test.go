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
	"testing"

	"strings"

	. "github.com/onsi/gomega"
)

var namesTable = []struct {
	v1Name          string
	v3Name          string
	expectQualifier bool
}{
	{"abcdef", "abcdef", false},
	{"Abcdef", "abcdef", true},
	{"abc-def", "abc-def", false},
	{"abc---def", "abc---def", false},
	{"abc/def", "abc.def", true},
	{"abc$$def", "abc-def", true},
	{"abc$!$def", "abc-def", true},
	{"abc..def", "abc.def", true},
	{"abc...def", "abc.def", true},
	{"abc.-def", "abc.def", true},
	{"abc.-.def", "abc.def", true},
	{"abc-.def", "abc.def", true},
	{"abc-.-def", "abc.def", true},
	{"aBcDe019", "abcde019", true},
	{"abc$def", "abc-def", true},
	{"-abc.def", "abc.def", true},
	{"abc.def-", "abc.def", true},
	{".abc.def", "abc.def", true},
	{"abc.def.", "abc.def", true},
	{"-.abc.def", "abc.def", true},
	{"abc.def.-", "abc.def", true},
	{"$ABC/DeF-123.-456!", "abc.def-123.456", true},
}

func TestCanConvertV1ToV3Name(t *testing.T) {
	for _, entry := range namesTable {
		t.Run(entry.v1Name, func(t *testing.T) {
			RegisterTestingT(t)

			// Get the converted name.
			c1 := convertName(entry.v1Name)
			if !entry.expectQualifier {
				// No qualifier is expected, the names should match exactly.
				Expect(c1).To(Equal(entry.v3Name))
			} else {
				// A qualifier is expected, the first part of the name should match and the
				// last 9 chars should be the qualifier.
				Expect(c1[:len(c1)-9]).To(Equal(entry.v3Name))
				Expect(c1[len(c1)-9:]).To(MatchRegexp("[-][0-9a-f]{8}"))

				// Convert an upper case variant of the input.  The first part of the name should
				// match and the last 9 chars should be the qualifier - however the two converted
				// names should be different.
				c2 := convertName(strings.ToUpper(entry.v1Name))
				Expect(c2[:len(c2)-9]).To(Equal(entry.v3Name))
				Expect(c2[len(c2)-9:]).To(MatchRegexp("[-][0-9a-f]{8}"))
				Expect(c2).NotTo(Equal(c1))
			}
		})
	}
}

var namesNoDotsTable = []struct {
	v1Name          string
	v3Name          string
	expectQualifier bool
}{
	{"abcdef", "abcdef", false},
	{"Abcdef", "abcdef", true},
	{"abc-def", "abc-def", false},
	{"abc---def", "abc---def", false},
	{"abc/def", "abc-def", true},
	{"abc..def", "abc-def", true},
	{"abc...def", "abc-def", true},
	{"abc.-def", "abc-def", true},
	{"abc.-.def", "abc-def", true},
	{"abc-.def", "abc-def", true},
	{"abc-.-def", "abc-def", true},
	{"aBcDe019", "abcde019", true},
	{"abc$def", "abc-def", true},
	{"-abc.def", "abc-def", true},
	{"abc.def-", "abc-def", true},
	{".abc.def", "abc-def", true},
	{"abc.def.", "abc-def", true},
	{"-.abc.def", "abc-def", true},
	{"abc.def.-", "abc-def", true},
	{"$ABC/DeF-123.-456!", "abc-def-123-456", true},
}

func TestCanConvertV1ToV3NameNoDots(t *testing.T) {
	for _, entry := range namesNoDotsTable {
		t.Run(entry.v1Name, func(t *testing.T) {
			RegisterTestingT(t)

			// Get the converted name.
			c1 := convertNameNoDots(entry.v1Name)
			if !entry.expectQualifier {
				// No qualifier is expected, the names should match exactly.
				Expect(c1).To(Equal(entry.v3Name))
			} else {
				// A qualifier is expected, the first part of the name should match and the
				// last 9 chars should be the qualifier.
				Expect(c1[:len(c1)-9]).To(Equal(entry.v3Name))
				Expect(c1[len(c1)-9:]).To(MatchRegexp("[-][0-9a-f]{8}"))

				// Convert an upper case variant of the input.  The first part of the name should
				// match and the last 9 chars should be the qualifier - however the two converted
				// names should be different.
				c2 := convertNameNoDots(strings.ToUpper(entry.v1Name))
				Expect(c2[:len(c2)-9]).To(Equal(entry.v3Name))
				Expect(c2[len(c2)-9:]).To(MatchRegexp("[-][0-9a-f]{8}"))
				Expect(c2).NotTo(Equal(c1))
			}
		})
	}
}

var ipToNameTable = []struct {
	ip   net.IP
	name string
}{
	{net.ParseIP("192.168.0.1"), "192-168-0-1"},
	{net.ParseIP("Aa:bb::"), "00aa-00bb-0000-0000-0000-0000-0000-0000"},
	{net.ParseIP("0Aa:bb::50"), "00aa-00bb-0000-0000-0000-0000-0000-0050"},
}

func TestCanConvertIpToName(t *testing.T) {
	for _, entry := range ipToNameTable {
		t.Run(entry.ip.String(), func(t *testing.T) {
			RegisterTestingT(t)
			Expect(convertIpToName(entry.ip)).To(Equal(entry.name), entry.ip.String())
		})
	}
}

var nodeNamesTable = []struct {
	before string
	after  string
}{
	{"abc-def", "abc-def"},
	{"abc---def", "abc---def"},
	{"abc/def", "abc.def"},
	{"abc$$def", "abc-def"},
	{"abc$!$def", "abc-def"},
	{"abc..def", "abc.def"},
	{"abc...def", "abc.def"},
	{"abc.-def", "abc.def"},
	{"abc.-.def", "abc.def"},
	{"abc-.def", "abc.def"},
	{"abc-.-def", "abc.def"},
	{"aBcDe019", "abcde019"},
	{"abc$def", "abc-def"},
	{"-abc.def", "abc.def"},
	{"abc.def-", "abc.def"},
	{".abc.def", "abc.def"},
	{"abc.def.", "abc.def"},
	{"-.abc.def", "abc.def"},
	{"abc.def.-", "abc.def"},
	{"$ABC/DEF-123.-456!", "abc.def-123.456"},
}

func TestCanConvertV1ToV3NodeName(t *testing.T) {
	for _, entry := range nodeNamesTable {
		t.Run(entry.before, func(t *testing.T) {
			RegisterTestingT(t)
			Expect(ConvertNodeName(entry.before)).To(Equal(entry.after), entry.before)
		})
	}
}
