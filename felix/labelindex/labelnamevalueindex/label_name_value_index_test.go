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

package labelnamevalueindex

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
)

func TestLabelValueIndexCRUD(t *testing.T) {
	RegisterTestingT(t)
	idx := New[string, labels]("item")
	x, ok := idx.Get("a")
	Expect(x).To(BeNil(), "Get shouldn't return anything for nonexistent key")
	Expect(ok).To(BeFalse(), "Get should return false for a nonexistent key")
	Expect(idx.Len()).To(Equal(0), "Len should start at 0")

	item := labels{"a": "A"}
	idx.Add("a", item)
	x, ok = idx.Get("a")
	Expect(x).To(Equal(item), "Get should return items")
	Expect(ok).To(BeTrue(), "Get should return true for existing key")
	Expect(idx.Len()).To(Equal(1), "Len should reflect added key")

	item2 := labels{"a": "A2"}
	idx.Add("a2", item2)
	x, ok = idx.Get("a2")
	Expect(x).To(Equal(item2), "Get should return items")
	Expect(ok).To(BeTrue(), "Get should return true for existing key")
	Expect(idx.Len()).To(Equal(2), "Len should reflect added key")

	Expect(func() {
		idx.Add("a", item)
	}).To(Panic())

	idx.Remove("a")
	x, ok = idx.Get("a")
	Expect(x).To(BeNil(), "Get shouldn't return anything for removed key")
	Expect(ok).To(BeFalse(), "Get should return false for a removed key")
	Expect(idx.Len()).To(Equal(1), "Len should return to 1")

	idx.Remove("a2")
	Expect(idx.Len()).To(Equal(0), "Len should return to 0")

	Expect(idx.labelNameToValueToIDs).To(HaveLen(0), "labelNameToValueToIDs should be cleaned up")
	Expect(idx.Len()).To(BeZero())
}

func TestLabelValueIndexStrategies(t *testing.T) {
	RegisterTestingT(t)
	idx := New[string, labels]("item")

	idx.Add("a1", labels{"a": "a1"})
	idx.Add("a2", labels{"a": "a2"})
	idx.Add("a3", labels{"a": "a3"})

	idx.Add("b1", labels{"b": "b1"})
	idx.Add("b2", labels{"b": "b2"})
	idx.Add("b3", labels{"b": "b3"})

	idx.Add("c1", labels{"a": "a1", "b": "b1"})
	idx.Add("c2", labels{"a": "a2", "b": "b2"})
	idx.Add("c3", labels{"a": "a3", "b": "b3"})

	t.Log("Full-scan strategy...")
	strat := idx.StrategyFor("a", parser.LabelRestriction{})
	Expect(strat).To(BeAssignableToTypeOf(FullScanStrategy[string, labels]{}))
	Expect(scan(strat)).To(ConsistOf("a1", "a2", "a3", "b1", "b2", "b3", "c1", "c2", "c3"))
	Expect(strat.EstimatedItemsToScan()).To(Equal(9))
	Expect(strat.Name()).To(Equal("full-scan"))

	t.Log("Label name strategy...")
	strat = idx.StrategyFor("a", parser.LabelRestriction{MustBePresent: true})
	Expect(strat).To(BeAssignableToTypeOf(LabelNameStrategy[string]{}))
	Expect(scan(strat)).To(ConsistOf("a1", "a2", "a3", "c1", "c2", "c3"))
	Expect(strat.EstimatedItemsToScan()).To(Equal(6))
	Expect(strat.Name()).To(Equal("label-name"))

	t.Log("Label name with no matches...")
	strat = idx.StrategyFor("nomatch", parser.LabelRestriction{MustBePresent: true})
	Expect(strat).To(BeAssignableToTypeOf(NoMatchStrategy[string]{}))
	Expect(scan(strat)).To(BeEmpty())
	Expect(strat.EstimatedItemsToScan()).To(Equal(0))
	Expect(strat.Name()).To(Equal("no-match"))

	t.Log("Label name and value (single)")
	strat = idx.StrategyFor("a", parser.LabelRestriction{
		MustBePresent:       true,
		MustHaveOneOfValues: []string{"a1"},
	})
	Expect(strat).To(BeAssignableToTypeOf(LabelNameSingleValueStrategy[string]{}))
	Expect(scan(strat)).To(ConsistOf("a1", "c1"))
	Expect(strat.EstimatedItemsToScan()).To(Equal(2))
	Expect(strat.Name()).To(Equal("single-value"))

	t.Log("Label name and value (filtered to single)")
	strat = idx.StrategyFor("a", parser.LabelRestriction{
		MustBePresent:       true,
		MustHaveOneOfValues: []string{"a1", "a4"},
	})
	Expect(strat).To(BeAssignableToTypeOf(LabelNameSingleValueStrategy[string]{}))
	Expect(scan(strat)).To(ConsistOf("a1", "c1"))
	Expect(strat.EstimatedItemsToScan()).To(Equal(2))
	Expect(strat.Name()).To(Equal("single-value"))

	t.Log("Label name and value (multi)")
	strat = idx.StrategyFor("a", parser.LabelRestriction{
		MustBePresent:       true,
		MustHaveOneOfValues: []string{"a1", "a2"},
	})
	Expect(strat).To(BeAssignableToTypeOf(LabelNameMultiValueStrategy[string]{}))
	Expect(scan(strat)).To(ConsistOf("a1", "c1", "a2", "c2"))
	Expect(strat.EstimatedItemsToScan()).To(Equal(4))
	Expect(strat.Name()).To(Equal("multi-value"))

	t.Log("Label name and value (filtered to nothing)")
	strat = idx.StrategyFor("a", parser.LabelRestriction{
		MustBePresent:       true,
		MustHaveOneOfValues: []string{"a4"},
	})
	Expect(strat).To(BeAssignableToTypeOf(NoMatchStrategy[string]{}))
	Expect(scan(strat)).To(ConsistOf())
	Expect(strat.EstimatedItemsToScan()).To(Equal(0))
	Expect(strat.Name()).To(Equal("no-match"))
}

func scan(s ScanStrategy[string]) []string {
	{
		// Check that we can stop...
		var out []string
		s.Scan(func(id string) bool {
			out = append(out, id)
			return false
		})
		Expect(out).To(Or(HaveLen(1), HaveLen(0)))
	}
	Expect(s.String()).NotTo(BeEmpty())
	var out []string
	s.Scan(func(id string) bool {
		out = append(out, id)
		return true
	})
	return out
}

type labels map[string]string

func (l labels) OwnLabels() map[string]string {
	return l
}
