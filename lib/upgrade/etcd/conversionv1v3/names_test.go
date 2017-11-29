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

package conversionv1v3

import (
	"testing"

	. "github.com/onsi/gomega"
)

var namesTable = []struct {
	v1Name string
	v3Name string
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

func TestCanConvertV1ToV3Name(t *testing.T) {
	for _, entry := range namesTable {
		t.Run(entry.v1Name, func(t *testing.T) {
			RegisterTestingT(t)
			Expect(convertName(entry.v1Name)).To(Equal(entry.v3Name), entry.v1Name)
		})
	}
}

var namesNoDotsTable = []struct {
	v1Name string
	v3Name string
}{
	{"abc-def", "abc-def"},
	{"abc---def", "abc---def"},
	{"abc/def", "abc-def"},
	{"abc..def", "abc-def"},
	{"abc...def", "abc-def"},
	{"abc.-def", "abc--def"},
	{"abc.-.def", "abc---def"},
	{"abc-.def", "abc--def"},
	{"abc-.-def", "abc---def"},
	{"aBcDe019", "abcde019"},
	{"abc$def", "abc-def"},
	{"-abc.def", "abc-def"},
	{"abc.def-", "abc-def"},
	{".abc.def", "abc-def"},
	{"abc.def.", "abc-def"},
	{"-.abc.def", "abc-def"},
	{"abc.def.-", "abc-def"},
	{"$ABC/DEF-123.-456!", "abc-def-123--456"},
}

func TestCanConvertV1ToV3NameNoDots(t *testing.T) {
	for _, entry := range namesNoDotsTable {
		t.Run(entry.v1Name, func(t *testing.T) {
			RegisterTestingT(t)
			Expect(convertNameNoDots(entry.v1Name)).To(Equal(entry.v3Name), entry.v1Name)
		})
	}
}
