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

package parser

import (
	"fmt"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
)

var labelRestrictionsTests = []struct {
	Sel string
	Res map[string]LabelRestriction
}{
	// Base cases.
	{"", nil},
	{"all()", nil},
	{"global()", nil},
	{"a == 'value'", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: []string{"value"}},
	}},
	{"has(a)", map[string]LabelRestriction{
		"a": {MustBePresent: true},
	}},
	{"!has(a)", map[string]LabelRestriction{
		"a": {MustBeAbsent: true},
	}},
	{"!!has(a)", map[string]LabelRestriction{
		"a": {MustBePresent: true},
	}},
	{"a in {'v1','v2'}", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: []string{"v1", "v2"}},
	}},
	{"a not in {'v1','v2'}", nil},
	{"a contains 'foo'", map[string]LabelRestriction{
		"a": {MustBePresent: true},
	}},
	{"a ends with 'foo'", map[string]LabelRestriction{
		"a": {MustBePresent: true},
	}},
	{"a starts with 'foo'", map[string]LabelRestriction{
		"a": {MustBePresent: true},
	}},
	{"a != 'value'", nil},

	// AND
	{"a == 'v1' && a == 'v1'", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: []string{"v1"}},
	}},
	{"a == 'v1' && a == 'v2'", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: []string{}},
	}},
	{"a == 'v1' && has(a)", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: []string{"v1"}},
	}},
	{"a in {'v1','v2'} && a in {'v2','v3'} ", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: []string{"v2"}},
	}},
	{"a in {'v1','v2', 'v3'} && a in {'v2','v3'} ", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: []string{"v2", "v3"}},
	}},
	{"has(a) && a == 'v1'", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: []string{"v1"}},
	}},
	{"has(a) && !has(a)", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustBeAbsent: true},
	}},
	{"a == 'v1' && b == 'v2'", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: []string{"v1"}},
		"b": {MustBePresent: true, MustHaveOneOfValues: []string{"v2"}},
	}},

	// OR
}

func TestLabelRestrictions(t *testing.T) {
	for _, test := range labelRestrictionsTests {
		t.Run(strings.Replace(test.Sel, " ", "", -1), func(t *testing.T) {
			RegisterTestingT(t)
			sel, err := Parse(test.Sel)
			Expect(err).NotTo(HaveOccurred())
			lrs := sel.LabelRestrictions()
			Expect(lrs).To(Equal(test.Res), fmt.Sprintf("Selector %s should produce restrictions: %v", test.Sel, test.Res))

			if test.Sel == "" {
				return
			}
			// Adding an extra "all() &&" to the selector should have no effect.
			s := fmt.Sprintf("all() && (%s)", test.Sel)
			t.Run("WithAllPrefix", func(t *testing.T) {
				RegisterTestingT(t)
				sel, err := Parse(s)
				Expect(err).NotTo(HaveOccurred())
				lrs := sel.LabelRestrictions()
				Expect(lrs).To(Equal(test.Res), fmt.Sprintf("Selector %s should produce restrictions: %v", s, test.Res))
			})
		})
	}
}
