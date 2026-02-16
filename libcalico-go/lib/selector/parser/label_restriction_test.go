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

	"github.com/projectcalico/calico/lib/std/uniquestr"
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
		"a": {MustBePresent: true, MustHaveOneOfValues: handleSlice("value")},
	}},
	{"has(a)", map[string]LabelRestriction{
		"a": {MustBePresent: true},
	}},
	{"a in {'v1','v2'}", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: handleSlice("v1", "v2")},
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
		"a": {MustBePresent: true, MustHaveOneOfValues: handleSlice("v1")},
	}},
	{"a == 'v1' && a == 'v2'", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: handleSlice()},
	}},
	{"a == 'v1' && has(a)", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: handleSlice("v1")},
	}},
	{"a in {'v1','v2'} && a in {'v2','v3'} ", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: handleSlice("v2")},
	}},
	{"a in {'v1','v2', 'v3'} && a in {'v2','v3'} ", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: handleSlice("v2", "v3")},
	}},
	{"has(a) && a == 'v1'", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: handleSlice("v1")},
	}},
	{"has(a) && !has(a)", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustBeAbsent: true},
	}},
	{"a == 'v1' && b == 'v2'", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: handleSlice("v1")},
		"b": {MustBePresent: true, MustHaveOneOfValues: handleSlice("v2")},
	}},
	{"a == 'v1' && all()", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: handleSlice("v1")},
	}},
	{"all() && a == 'v1'", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: handleSlice("v1")},
	}},

	// OR
	{"a == 'v1' || a == 'v2'", map[string]LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: handleSlice("v1", "v2")},
	}},
	{"has(a) || a == 'v2'", map[string]LabelRestriction{
		"a": {MustBePresent: true},
	}},
	{"a=='v2' || has(a)", map[string]LabelRestriction{
		"a": {MustBePresent: true},
	}},
	{"a=='v2' || has(b)", nil},
	{"a=='v2' || (has(b) && has(a))", map[string]LabelRestriction{
		"a": {MustBePresent: true},
	}},
	{"a == 'v1' || b == 'v2'", nil},
	{"a == 'v1' || all()", nil},
	{"all() || b == 'v2'", nil},

	// NOT
	{"!(a == 'value')", nil},
	{"!has(a)", map[string]LabelRestriction{
		"a": {MustBeAbsent: true},
	}},
	{"!!has(a)", map[string]LabelRestriction{
		"a": {MustBePresent: true},
	}},
}

func TestLabelRestrictions(t *testing.T) {
	for _, test := range labelRestrictionsTests {
		t.Run(strings.Replace(test.Sel, " ", "", -1), func(t *testing.T) {
			RegisterTestingT(t)
			sel, err := Parse(test.Sel)
			Expect(err).NotTo(HaveOccurred())
			lrs := sel.LabelRestrictions()
			var res LabelRestrictions
			if test.Res != nil {
				m := map[uniquestr.Handle]LabelRestriction{}
				for k, v := range test.Res {
					m[uniquestr.Make(k)] = v
				}
				res = MakeLabelRestrictions(m)
			}
			Expect(lrs).To(Equal(res), fmt.Sprintf("Selector %s should produce restrictions: %v", test.Sel, test.Res))
			lrs = sel.LabelRestrictions()
			Expect(lrs).To(Equal(res), fmt.Sprintf("Selector %s should produce same restrictions on second call: %v",
				test.Sel, test.Res))

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
				Expect(lrs).To(Equal(res), fmt.Sprintf("Selector %s should produce restrictions: %v", s, test.Res))
			})
		})
	}
}

func TestLabelRestrictionsCache(t *testing.T) {
	RegisterTestingT(t)

	selA, err := Parse("has(a)")
	Expect(err).NotTo(HaveOccurred())
	selB, err := Parse("has(b)")
	Expect(err).NotTo(HaveOccurred())

	// Clear cache.
	lastRestrictionSelector = nil
	lastLabelRestrictions = nil

	// First call should populate the cache.
	lrsA1 := selA.LabelRestrictions()
	Expect(lastRestrictionSelector).To(BeIdenticalTo(selA))

	// Second call to the same selector should be a cache hit;
	// the cached selector pointer should not change.
	lrsA2 := selA.LabelRestrictions()
	Expect(lastRestrictionSelector).To(BeIdenticalTo(selA),
		"cache hit should not change the cached selector")
	Expect(lrsA2).To(Equal(lrsA1))

	// Calling on a different selector should update the cache.
	lrsB := selB.LabelRestrictions()
	Expect(lastRestrictionSelector).To(BeIdenticalTo(selB),
		"cache miss should update the cached selector")
	Expect(lrsB).NotTo(Equal(lrsA1))

	// Going back to selA should update the cache again.
	lrsA3 := selA.LabelRestrictions()
	Expect(lastRestrictionSelector).To(BeIdenticalTo(selA),
		"cache should update when switching back to first selector")
	Expect(lrsA3).To(Equal(lrsA1))
}

func handleSlice(ss ...string) []uniquestr.Handle {
	var hs = make([]uniquestr.Handle, len(ss))
	for i, s := range ss {
		hs[i] = uniquestr.Make(s)
	}
	return hs
}
