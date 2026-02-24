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
	"iter"
	"math"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/uniquestr"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// LabelRestrictionIndex indexes Selectors themselves, based on their label
// restrictions such that, given a Labeled resource, it can (hopefully)
// find a small subset of selectors that are candidate matches.
type LabelRestrictionIndex[SelID comparable] struct {
	// selectorsByID stores all selectors that we know about by their ID.
	selectorsByID map[SelID]*selector.Selector

	// labelToValueToIDs stores a sub-index for each label name that occurs in
	// a selector.  This is the main lookup datastructure.  The valuesSubIndex
	// contains a map from label value to set of selectors that require that
	// value along with a set of selectors that require that label be present
	// (for some unspecified values).
	labelToValueToIDs map[uniquestr.Handle]*valuesSubIndex[SelID]

	// unoptimizedIDs contains an entry for any selectors that have no
	// valid label restrictions (and hence no entries in labelToValueToIDs).
	unoptimizedIDs set.Typed[SelID]

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

// Gauge is the sub-interface of prometheus.Gauge that we use.
type Gauge interface {
	Set(float64)
}

func New[SelID comparable](opts ...Option[SelID]) *LabelRestrictionIndex[SelID] {
	idx := &LabelRestrictionIndex[SelID]{
		selectorsByID:     map[SelID]*selector.Selector{},
		labelToValueToIDs: map[uniquestr.Handle]*valuesSubIndex[SelID]{},
		unoptimizedIDs:    set.New[SelID](),
	}
	for _, o := range opts {
		o(idx)
	}
	return idx
}

func (s *LabelRestrictionIndex[SelID]) AddSelector(id SelID, selector *selector.Selector) {
	defer s.updateGauges()

	// In case of changes with the same ID, delete it first to clean up the
	// index.
	s.DeleteSelector(id)

	// Store off the selector itself.
	s.selectorsByID[id] = selector
	lrs := selector.LabelRestrictions()

	// Add it to the main "optimized" index, if possible.  We only need to
	// add one label since _all_ LabelRestrictions must be satisfied.  Try
	// to pick the most restrictive.
	labelName, found := findMostRestrictedLabel(lrs)
	optimized := false
	debug := logrus.IsLevelEnabled(logrus.DebugLevel)
	if found {
		res, _ := lrs.Get(labelName)
		if !res.PossibleToSatisfy() {
			// Selector is impossible to satisfy, we don't even need to
			// add it to the index(!)
			if debug {
				logrus.WithField("selector", selector.String()).Debug(
					"Selector is not possible to satisfy.")
			}
			optimized = true
		} else if res.MustHaveOneOfValues != nil {
			// Selector requires one of a few specific values for this
			// label, add it to the individual values index.
			if debug {
				logrus.WithFields(logrus.Fields{
					"selector": selector.String(),
					"label":    labelName.Value(),
					"values":   uniquestr.HandleSliceStringer(res.MustHaveOneOfValues),
				}).Debug("Optimising selector on must-have values.")
			}
			optimized = true
			for _, v := range res.MustHaveOneOfValues {
				values, ok := s.labelToValueToIDs[labelName]
				if !ok {
					values = &valuesSubIndex[SelID]{}
					s.labelToValueToIDs[labelName] = values
				}
				values.Add(v, id)
			}
		} else if res.MustBePresent {
			// Selector requires that this label is present, add it to the
			// wildcards.
			if debug {
				logrus.WithFields(logrus.Fields{
					"selector": selector.String(),
					"label":    labelName.Value(),
				}).Debug("Optimising selector on wildcard.")
			}
			optimized = true
			values, ok := s.labelToValueToIDs[labelName]
			if !ok {
				values = &valuesSubIndex[SelID]{}
				s.labelToValueToIDs[labelName] = values
			}
			values.AddWildcard(id)
		}
	}

	if !optimized {
		// We weren't able to optimise the selector
		logrus.Debugf("Unable to optimise selector: %q", selector)
		s.unoptimizedIDs.Add(id)
	}
}

func (s *LabelRestrictionIndex[SelID]) DeleteSelector(id SelID) {
	defer s.updateGauges()

	sel := s.selectorsByID[id]
	if sel == nil {
		return
	}
	lrs := sel.LabelRestrictions()

	labelName, found := findMostRestrictedLabel(lrs)
	optimized := false
	if found {
		res, _ := lrs.Get(labelName)
		if !res.PossibleToSatisfy() {
			optimized = true
		} else if res.MustHaveOneOfValues != nil {
			optimized = true
			values := s.labelToValueToIDs[labelName]
			for _, v := range res.MustHaveOneOfValues {
				values.Remove(v, id)
				if values.Empty() {
					delete(s.labelToValueToIDs, labelName)
				}
			}
		} else if res.MustBePresent {
			optimized = true
			values := s.labelToValueToIDs[labelName]
			values.RemoveWildcard(id)
			if values.Empty() {
				delete(s.labelToValueToIDs, labelName)
			}
		}
	}

	if !optimized {
		s.unoptimizedIDs.Discard(id)
	}

	delete(s.selectorsByID, id)
}

func findMostRestrictedLabel(lrs parser.LabelRestrictions) (uniquestr.Handle, bool) {
	var zeroHandle uniquestr.Handle
	var bestLabel uniquestr.Handle
	var bestScore = -1
	for label, res := range lrs.All() {
		score := scoreLabelRestriction(res)
		if bestLabel == zeroHandle ||
			score > bestScore ||
			score == bestScore && label.Value() > bestLabel.Value() {
			bestLabel = label
			bestScore = score
		}
	}
	return bestLabel, bestLabel != zeroHandle
}

func scoreLabelRestriction(lr parser.LabelRestriction) int {
	if !lr.PossibleToSatisfy() {
		// Best possible case, we've proven that this selector can't match
		// anything at all (so we don't even need to index it).
		return math.MaxInt
	}
	score := 0
	if lr.MustBePresent {
		score += 10
	}
	if lr.MustHaveOneOfValues != nil {
		s := max(10000-len(lr.MustHaveOneOfValues), 100)
		score += s
	}
	return score
}

// Labeled provides an interface for iterating over a resource's labels
// including any that are inherited from its parents.
type Labeled interface {
	// AllOwnAndParentLabelHandles should produce each KV that applies to the
	// resource exactly once, accounting for inheritance.  I.e.  if
	// the resource and its parent have different values for the same label,
	// it should produce the final applicable value.
	AllOwnAndParentLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle]
}

func (s *LabelRestrictionIndex[SelID]) AllPotentialMatches(item Labeled) iter.Seq2[SelID, *selector.Selector] {
	return func(yield func(SelID, *selector.Selector) bool) {
		emit := func(id SelID) bool {
			return yield(id, s.selectorsByID[id])
		}

		for k, v := range item.AllOwnAndParentLabelHandles() {
			values, ok := s.labelToValueToIDs[k]
			if !ok {
				continue
			}
			if values.selsMatchingWildcard != nil {
				for id := range values.selsMatchingWildcard.All() {
					if !emit(id) {
						return
					}
				}
			}
			if ids := values.selsMatchingSpecificValues[v]; ids != nil {
				for id := range ids.All() {
					if !emit(id) {
						return
					}
				}
			}
		}

		// Finally, emit the unoptimized selectors.
		for id := range s.unoptimizedIDs.All() {
			if !emit(id) {
				return
			}
		}
	}
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
	selsMatchingSpecificValues map[uniquestr.Handle]set.Typed[SelID]
	selsMatchingWildcard       set.Typed[SelID]
}

func (t *valuesSubIndex[SelID]) Add(value uniquestr.Handle, id SelID) {
	if t.selsMatchingSpecificValues == nil {
		t.selsMatchingSpecificValues = map[uniquestr.Handle]set.Typed[SelID]{}
	}
	values, ok := t.selsMatchingSpecificValues[value]
	if !ok {
		// Not tracking this value yet, create the set.
		values = set.New[SelID]()
		t.selsMatchingSpecificValues[value] = values
	}
	values.Add(id)
}

func (t *valuesSubIndex[SelID]) Remove(value uniquestr.Handle, id SelID) {
	values, ok := t.selsMatchingSpecificValues[value]
	if !ok {
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
}

func (t *valuesSubIndex[SelID]) AddWildcard(id SelID) {
	if t.selsMatchingWildcard == nil {
		t.selsMatchingWildcard = set.New[SelID]()
	}
	t.selsMatchingWildcard.Add(id)
}

func (t *valuesSubIndex[SelID]) RemoveWildcard(id SelID) {
	if t.selsMatchingWildcard == nil {
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
