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
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// LabelRestrictionIndex indexes Selectors themselves, based on their label
// restrictions such that, given a Labeled resource, it can (hopefully)
// find a small subset of selectors that are candidate matches.
type LabelRestrictionIndex[SelID comparable] struct {
	// selectorsByID stores all selectors that we know about by their ID.
	selectorsByID map[SelID]selector.Selector
	// labelRestrictions stores a copy of the calculated LabelRestrictions
	// for each selector.
	labelRestrictions map[SelID]map[string]parser.LabelRestriction

	// labelToValueToIDs stores a sub-index for each label name that occurs in
	// a selector.  This is the main lookup datastructure.  The valuesSubIndex
	// contains a map from label value to set of selectors that require that
	// value along with a set of selectors that require that label be present
	// (for some unspecified values).
	labelToValueToIDs map[string]*valuesSubIndex[SelID]

	// unoptimizedIDs contains an entry for any selectors that have no
	// valid label restrictions (and hence no entries in labelToValueToIDs).
	unoptimizedIDs set.Set[SelID]

	// scratchSet provides a scratch area for IterPotentialMatches to use
	// to avoid allocation.
	scratchSet set.Set[SelID]

	gaugeOptimizedSelectors   Gauge
	gaugeUnoptimizedSelectors Gauge
}

type Option[SelID comparable] func(index *LabelRestrictionIndex[SelID])

func WithGauges[SelID comparable](optimizedSelectors, unoptimisedSelectors Gauge) Option[SelID] {
	return func(index *LabelRestrictionIndex[SelID]) {
		index.gaugeOptimizedSelectors = optimizedSelectors
		index.gaugeUnoptimizedSelectors = unoptimisedSelectors
	}
}

var _ = WithGauges[any]

// Gauge is the sub-interface of prometheus.Gauge that we use.
type Gauge interface {
	Set(float64)
}

func New[SelID comparable](opts ...Option[SelID]) *LabelRestrictionIndex[SelID] {
	idx := &LabelRestrictionIndex[SelID]{
		selectorsByID:     map[SelID]selector.Selector{},
		labelRestrictions: map[SelID]map[string]parser.LabelRestriction{},
		labelToValueToIDs: map[string]*valuesSubIndex[SelID]{},
		unoptimizedIDs:    set.New[SelID](),
		scratchSet:        set.New[SelID](),
	}
	for _, o := range opts {
		o(idx)
	}
	return idx
}

func (s *LabelRestrictionIndex[SelID]) AddSelector(id SelID, selector selector.Selector) {
	// In case of changes with the same ID, delete it first to clean up the
	// index.
	s.DeleteSelector(id)

	// Store off the selector itself.
	s.selectorsByID[id] = selector
	lr := selector.LabelRestrictions()
	s.labelRestrictions[id] = lr

	// Add it to the main "optimized" index, if possible.
	optimized := false
	for label, res := range lr {
		if res.MustHaveOneOfValues != nil {
			optimized = true
			for _, v := range res.MustHaveOneOfValues {
				values, ok := s.labelToValueToIDs[label]
				if !ok {
					values = &valuesSubIndex[SelID]{}
					s.labelToValueToIDs[label] = values
				}
				values.Add(v, id)
			}
		} else if res.MustBePresent {
			optimized = true
			values, ok := s.labelToValueToIDs[label]
			if !ok {
				values = &valuesSubIndex[SelID]{}
				s.labelToValueToIDs[label] = values
			}
			values.AddWildcard(id)
		}
		// TODO instead of adding all KVs to the index we could just pick one
		//  using some heuristic (e.g. one with the highest specificity).
		//  Would need a refactor to handle DeleteSelector too.
	}
	if !optimized {
		// We weren't able to optimise the selector
		logrus.Debugf("Unable to optimise selector: %q", selector)
		s.unoptimizedIDs.Add(id)
	}
	s.updateGauges()
}

func (s *LabelRestrictionIndex[SelID]) DeleteSelector(id SelID) {
	sel := s.selectorsByID[id]
	if sel == nil {
		return
	}
	lr := s.labelRestrictions[id]
	optimized := false
	for label, res := range lr {
		if res.MustHaveOneOfValues != nil {
			optimized = true
			values := s.labelToValueToIDs[label]
			for _, v := range res.MustHaveOneOfValues {
				values.Remove(v, id)
				if values.Empty() {
					delete(s.labelToValueToIDs, label)
				}
			}
		} else if res.MustBePresent {
			optimized = true
			values := s.labelToValueToIDs[label]
			values.RemoveWildcard(id)
			if values.Empty() {
				delete(s.labelToValueToIDs, label)
			}
		}
	}
	if !optimized {
		s.unoptimizedIDs.Discard(id)
	}

	delete(s.selectorsByID, id)
	delete(s.labelRestrictions, id)
	s.updateGauges()
}

// Labeled provides an interface for iterating over a resource's labels
// including any that are inherited from its parents.
type Labeled interface {
	// IterOwnAndParentLabels should produce each KV that applies to the
	// resource exactly once, accounting for inheritance.  I.e.  if
	// the resource and its parent have different values for the same label,
	// it should produce the final applicable value.
	IterOwnAndParentLabels(func(k, v string))
}

func (s *LabelRestrictionIndex[SelID]) IterPotentialMatches(labels Labeled, f func(SelID, selector.Selector)) {
	seenIDs := s.scratchSet
	defer seenIDs.Clear()

	maybeEmit := func(id SelID) error {
		if seenIDs.Contains(id) {
			return nil
		}
		seenIDs.Add(id)
		f(id, s.selectorsByID[id])
		return nil
	}

	labels.IterOwnAndParentLabels(func(k, v string) {
		values, ok := s.labelToValueToIDs[k]
		if !ok {
			return
		}
		if values.selsMatchingWildcard != nil {
			values.selsMatchingWildcard.Iter(maybeEmit)
		}
		if ids := values.selsMatchingSpecificValues[v]; ids != nil {
			ids.Iter(maybeEmit)
		}
	})

	// Finally, emit the unoptimized selectors.  We don't need to go through
	// maybeEmit because these cannot overlap with optimized selectors.
	s.unoptimizedIDs.Iter(func(id SelID) error {
		f(id, s.selectorsByID[id])
		return nil
	})
}

func (s *LabelRestrictionIndex[SelID]) updateGauges() {
	if s.gaugeOptimizedSelectors != nil {
		s.gaugeOptimizedSelectors.Set(float64(len(s.selectorsByID) - s.unoptimizedIDs.Len()))
	}
	if s.gaugeUnoptimizedSelectors != nil {
		s.gaugeUnoptimizedSelectors.Set(float64(s.unoptimizedIDs.Len()))
	}
}

// valuesSubIndex keeps track of the selectors that match a particular
// label, either matching particular values or a wildcard (such as
// "has(labelName)").
type valuesSubIndex[SelID comparable] struct {
	selsMatchingSpecificValues map[string]set.Set[SelID]
	selsMatchingWildcard       set.Set[SelID]

	count int
}

func (t *valuesSubIndex[SelID]) Add(value string, id SelID) {
	if t.selsMatchingSpecificValues == nil {
		t.selsMatchingSpecificValues = map[string]set.Set[SelID]{}
	}
	values, ok := t.selsMatchingSpecificValues[value]
	if !ok {
		// Not tracking this value yet, create the set.
		values = set.New[SelID]()
		t.selsMatchingSpecificValues[value] = values
	} else if values.Contains(id) {
		return // Defensive, shouldn't be adding the same ID twice.
	}
	values.Add(id)
	t.count++

}

func (t *valuesSubIndex[SelID]) Remove(value string, id SelID) {
	values, ok := t.selsMatchingSpecificValues[value]
	if !ok || !values.Contains(id) {
		return
	}
	values.Discard(id)
	if values.Len() == 0 {
		delete(t.selsMatchingSpecificValues, value)
		if len(t.selsMatchingSpecificValues) == 0 {
			// For symmetry with Add, we clean up the map when no longer in use.
			t.selsMatchingSpecificValues = nil
		}
	}
	t.count--
}

func (t *valuesSubIndex[SelID]) AddWildcard(id SelID) {
	if t.selsMatchingWildcard == nil {
		t.selsMatchingWildcard = set.New[SelID]()
	} else if t.selsMatchingWildcard.Contains(id) {
		return
	}
	t.selsMatchingWildcard.Add(id)
	t.count++
}

func (t *valuesSubIndex[SelID]) RemoveWildcard(id SelID) {
	if t.selsMatchingWildcard == nil || !t.selsMatchingWildcard.Contains(id) {
		return
	}
	t.selsMatchingWildcard.Discard(id)
	if t.selsMatchingWildcard.Len() == 0 {
		// For symmetry with AddWildcard, we clean up the map when no longer in use.
		t.selsMatchingWildcard = nil
	}
}

func (t *valuesSubIndex[SelID]) Empty() bool {
	return len(t.selsMatchingSpecificValues) == 0 && t.selsMatchingWildcard == nil
}
