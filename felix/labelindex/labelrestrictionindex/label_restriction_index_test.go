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

package labelrestrictionindex

import (
	"fmt"
	"iter"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/uniquestr"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
)

type dummyGauge float64

func (d *dummyGauge) Set(f float64) {
	*d = dummyGauge(f)
}

func TestLabelRestrictionIndex(t *testing.T) {
	RegisterTestingT(t)
	logrus.SetLevel(logrus.DebugLevel)

	var optGauge, unoptGauge dummyGauge
	idx := New[string](WithGauges[string](&optGauge, &unoptGauge))

	// Add a variety of selectors to the index.  These should all be optimised.
	t.Log("Adding selectors to the index...")
	hasA := mustParseSelector("has(a)")
	idx.AddSelector("hasA", hasA)
	aEqualsA := mustParseSelector("a == 'A'")
	idx.AddSelector("aEqualsA", aEqualsA)
	aAndB := mustParseSelector("a == 'A' && b == 'B'")
	idx.AddSelector("aAndB", aAndB)
	aIn := mustParseSelector("a in {'A1','A2'}")
	idx.AddSelector("aIn", aIn)
	bIn := mustParseSelector("b in {'B1','B2'}")
	idx.AddSelector("bIn", bIn)
	impossible := mustParseSelector("a == 'A' && a == 'B'")
	idx.AddSelector("impossible", impossible)

	Expect(optGauge).To(BeNumerically("==", 6),
		"All selectors added so far should be optimised")
	Expect(unoptGauge).To(BeNumerically("==", 0),
		"All selectors added so far should be optimised")

	// Add a selector that cannot be optimised.
	allSel := mustParseSelector("all()")
	idx.AddSelector("all", allSel)
	Expect(optGauge).To(BeNumerically("==", 6))
	Expect(unoptGauge).To(BeNumerically("==", 1),
		"Expected all() selector to show up as unoptimised")

	// Verify that the index produces the correct selectors for a variety
	// of labels.
	t.Log("Checking that the correct selectors are found...")
	potentialMatches := func(labels map[string]string) []string {
		var out []string
		for s, s2 := range idx.AllPotentialMatches(labeledAdapter(labels)) {
			Expect(out).NotTo(ContainElement(s), "AllPotentialMatches produced duplicate: "+s)
			out = append(out, s)
			Expect(s2).NotTo(BeNil())
		}
		// Sanity check that all selectors that match the labels are returned.
		// This is basically a cross-check on the caller's Expect().
		for selID, sel := range idx.selectorsByID {
			if sel.Evaluate(labels) {
				Expect(out).To(ContainElement(selID), fmt.Sprintf(
					"Selector %s (%s) matches %v but IterPotentialMatches didn't produce it", selID, sel, labels))
			}
		}
		return out
	}

	Expect(potentialMatches(map[string]string{"a": "A"})).To(ConsistOf("hasA", "aEqualsA", "all"),
		"a:A should match expected selectors")
	Expect(potentialMatches(map[string]string{"a": "A1"})).To(ConsistOf("hasA", "aIn", "all"),
		"a:A1 should match expected selectors")
	Expect(potentialMatches(map[string]string{"a": "A2"})).To(ConsistOf("hasA", "aIn", "all"),
		"a:A2 should match expected selectors")

	Expect(potentialMatches(map[string]string{"b": "B"})).To(ConsistOf("all", "aAndB"),
		"b:B should match expected selectors")
	Expect(potentialMatches(map[string]string{"b": "B1"})).To(ConsistOf("bIn", "all"),
		"b:B1 should match expected selectors")
	Expect(potentialMatches(map[string]string{"b": "B2"})).To(ConsistOf("bIn", "all"),
		"b:B2 should match expected selectors")

	Expect(potentialMatches(map[string]string{"a": "A", "b": "B"})).To(ConsistOf("hasA", "aEqualsA", "aAndB", "all"),
		"a:A, b:B should match a and b selectors")
	Expect(potentialMatches(map[string]string{"a": "A1", "b": "B1"})).To(ConsistOf("hasA", "aIn", "bIn", "all"),
		"a:A1, b:B1 should match a and b selectors")
	Expect(potentialMatches(map[string]string{"a": "A1", "b": "B1", "c": "C"})).To(ConsistOf("hasA", "aIn", "bIn", "all"),
		"adding c:C shouldn't have any effect")

	// Delete the selectors and verify cleanup...
	idx.DeleteSelector("aIn")
	Expect(optGauge).To(BeNumerically("==", 5),
		"Gauge incorrect after deleting selector")
	Expect(potentialMatches(map[string]string{"a": "A1"})).To(ConsistOf("hasA", "all"),
		"a:A1 should match expected selectors")

	idx.DeleteSelector("all")
	Expect(unoptGauge).To(BeNumerically("==", 0),
		"Gauge incorrect after deleting selector")
	Expect(potentialMatches(map[string]string{"a": "A1"})).To(ConsistOf("hasA"),
		"a:A1 should match expected selectors")

	idx.DeleteSelector("aEqualsA")
	idx.DeleteSelector("hasA")
	Expect(optGauge).To(BeNumerically("==", 3),
		"Gauge incorrect after deleting selectors")
	Expect(potentialMatches(map[string]string{"a": "A1"})).To(ConsistOf(),
		"a:A1 should match nothing once selectors are removed")

	idx.DeleteSelector("impossible")
	idx.DeleteSelector("aAndB")
	idx.DeleteSelector("bIn")
	Expect(optGauge).To(BeNumerically("==", 0),
		"Gauge incorrect after deleting selectors")
	Expect(potentialMatches(map[string]string{"b": "B1"})).To(ConsistOf(),
		"b:B should match nothing once selectors are removed")

	Expect(idx.labelToValueToIDs).To(BeEmpty())
}

type labeledAdapter map[string]string

func (l labeledAdapter) AllOwnAndParentLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return func(yield func(uniquestr.Handle, uniquestr.Handle) bool) {
		for k, v := range l {
			if !yield(uniquestr.Make(k), uniquestr.Make(v)) {
				return
			}
		}
	}
}

var _ Labeled = labeledAdapter(nil)

func TestFindMostRestrictedLabel(t *testing.T) {
	RegisterTestingT(t)

	Expect(mostRestricted(nil)).To(Equal(""),
		"findMostRestrictedLabel should return '' for nil map")

	Expect(mostRestricted(map[string]parser.LabelRestriction{})).To(Equal(""),
		"findMostRestrictedLabel should return '' for empty map")

	Expect(mostRestricted(map[string]parser.LabelRestriction{
		"a": {},
	})).To(Equal("a"),
		"findMostRestrictedLabel should return the only option")

	Expect(mostRestricted(map[string]parser.LabelRestriction{
		"a": {},
		"b": {},
		"c": {},
	})).To(Equal("c"),
		"findMostRestrictedLabel should tie break on name")

	Expect(mostRestricted(map[string]parser.LabelRestriction{
		"a": {},
		"b": {MustBePresent: true},
		"c": {},
	})).To(Equal("b"),
		"findMostRestrictedLabel should prefer 'present' labels")

	Expect(mostRestricted(map[string]parser.LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: stringSliceToHandle([]string{"A"})},
		"b": {MustBePresent: true},
		"c": {},
	})).To(Equal("a"),
		"findMostRestrictedLabel should prefer 'value' labels")

	Expect(mostRestricted(map[string]parser.LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: stringSliceToHandle([]string{"A1", "A2"})},
		"b": {MustBePresent: true, MustHaveOneOfValues: stringSliceToHandle([]string{"B1"})},
		"c": {},
	})).To(Equal("b"),
		"findMostRestrictedLabel should prefer fewer values")

	Expect(mostRestricted(map[string]parser.LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: stringSliceToHandle([]string{})},
		"b": {MustBePresent: true},
		"c": {},
	})).To(Equal("a"),
		"findMostRestrictedLabel should prefer impossible selector (no values)")

	Expect(mostRestricted(map[string]parser.LabelRestriction{
		"a": {MustBePresent: true, MustBeAbsent: true},
		"b": {MustBePresent: true},
		"c": {},
	})).To(Equal("a"),
		"findMostRestrictedLabel should prefer impossible selector (present and absent)")

	var manyVals []uniquestr.Handle
	for i := range 15000 {
		manyVals = append(manyVals, uniquestr.Make(fmt.Sprint(i)))
	}
	Expect(mostRestricted(map[string]parser.LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: manyVals},
		"b": {MustBePresent: true, MustHaveOneOfValues: stringSliceToHandle([]string{"B1"})},
		"c": {},
	})).To(Equal("b"),
		"findMostRestrictedLabel should handle >10k values (edge case)")
	Expect(mostRestricted(map[string]parser.LabelRestriction{
		"a": {MustBePresent: true, MustHaveOneOfValues: manyVals},
		"b": {MustBePresent: true, MustHaveOneOfValues: manyVals},
		"c": {},
	})).To(Equal("b"),
		"findMostRestrictedLabel should handle >10k values (edge case)")
	Expect(mostRestricted(map[string]parser.LabelRestriction{
		"a": {MustBePresent: true},
		"b": {MustBePresent: true, MustHaveOneOfValues: manyVals},
		"c": {},
	})).To(Equal("b"),
		"findMostRestrictedLabel should handle >10k values when comparing to MustBePresent (edge case)")
}

func mostRestricted(m map[string]parser.LabelRestriction) string {
	var lrs map[uniquestr.Handle]parser.LabelRestriction
	if m != nil {
		lrs = map[uniquestr.Handle]parser.LabelRestriction{}
		for k, v := range m {
			lrs[uniquestr.Make(k)] = v
		}
	}
	handle, found := findMostRestrictedLabel(parser.MakeLabelRestrictions(lrs))
	if found {
		return handle.Value()
	}
	return ""
}

func stringSliceToHandle(s []string) (out []uniquestr.Handle) {
	if s == nil {
		return nil
	}
	out = make([]uniquestr.Handle, len(s))
	for _, s := range s {
		out = append(out, uniquestr.Make(s))
	}
	return
}

func mustParseSelector(s string) *selector.Selector {
	sel, err := selector.Parse(s)
	Expect(err).NotTo(HaveOccurred())
	return sel
}
