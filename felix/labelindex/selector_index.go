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

package labelindex

import (
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type FuzzySelectorIndex[T comparable] struct {
	selectorsByID     map[T]selector.Selector
	labelRestrictions map[T]map[string]parser.LabelRestriction

	labelToValueToIDs map[string]*fuzzyValues[T]

	unoptimizedIDs set.Set[T]
	scratchSet     set.Set[T]
}

func NewFuzzySelectorIndex[T comparable]() *FuzzySelectorIndex[T] {
	return &FuzzySelectorIndex[T]{
		selectorsByID:     map[T]selector.Selector{},
		labelRestrictions: map[T]map[string]parser.LabelRestriction{},
		labelToValueToIDs: map[string]*fuzzyValues[T]{},
		unoptimizedIDs:    set.New[T](),
		scratchSet:        set.New[T](),
	}
}

type fuzzyValues[T comparable] struct {
	values    map[string]set.Set[T]
	anyValues set.Set[T]
	count     int
}

func (t *fuzzyValues[T]) Add(value string, id T) {
	if values, ok := t.values[value]; !ok {
		t.values[value] = set.From(id)
		t.count++
	} else {
		if values.Contains(id) {
			return
		}
		values.Add(id)
		t.count++
	}
}

func (t *fuzzyValues[T]) Remove(value string, id T) {
	values, ok := t.values[value]
	if !ok {
		return
	}
	if !values.Contains(id) {
		return
	}
	values.Discard(id)
	if values.Len() == 0 {
		delete(t.values, value)
	}
	t.count--
}

func (t *fuzzyValues[T]) Empty() bool {
	return len(t.values) == 0 && t.anyValues == nil
}

func (t *fuzzyValues[T]) AddAny(id T) {
	if t.anyValues == nil {
		t.anyValues = set.New[T]()
	}
	if t.anyValues.Contains(id) {
		return
	}
	t.count++
	t.anyValues.Add(id)
}

func (t *fuzzyValues[T]) RemoveAny(id T) {
	if t.anyValues == nil {
		return
	}
	if !t.anyValues.Contains(id) {
		return
	}
	t.anyValues.Discard(id)
	if t.anyValues.Len() == 0 {
		t.anyValues = nil
	}
}

func (s *FuzzySelectorIndex[T]) AddSelector(id T, selector selector.Selector) {
	s.selectorsByID[id] = selector
	lr := selector.LabelRestrictions()
	s.labelRestrictions[id] = lr
	optimized := false
	for label, res := range lr {
		if res.MustHaveValue != "" {
			optimized = true
			values, ok := s.labelToValueToIDs[label]
			if !ok {
				values = &fuzzyValues[T]{
					values: map[string]set.Set[T]{},
				}
				s.labelToValueToIDs[label] = values
			}
			values.Add(res.MustHaveValue, id)
		} else if res.MustBePresent {
			optimized = true
			values, ok := s.labelToValueToIDs[label]
			if !ok {
				values = &fuzzyValues[T]{
					values: map[string]set.Set[T]{},
				}
				s.labelToValueToIDs[label] = values
			}
			values.AddAny(id)
		}
	}
	if !optimized {
		s.unoptimizedIDs.Add(id)
	}
}

func (s *FuzzySelectorIndex[T]) RemoveSelector(id T) {
	sel := s.selectorsByID[id]
	if sel == nil {
		return
	}
	lr := s.labelRestrictions[id]
	optimized := false
	for label, res := range lr {
		if res.MustHaveValue != "" {
			optimized = true
			values := s.labelToValueToIDs[label]
			values.Remove(res.MustHaveValue, id)
			if values.Empty() {
				delete(s.labelToValueToIDs, label)
			}
		} else if res.MustBePresent {
			optimized = true
			values := s.labelToValueToIDs[label]
			values.RemoveAny(id)
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
}

func (s *FuzzySelectorIndex[T]) IterPotentialMatchingSelectors(labels kvSource, f func(T, selector.Selector)) {
	seenIDs := s.scratchSet
	defer seenIDs.Clear()

	maybeEmit := func(id T) error {
		if seenIDs.Contains(id) {
			return nil
		}
		seenIDs.Add(id)
		f(id, s.selectorsByID[id])
		return nil
	}

	labels.IterKVs(func(k, v string) {
		values, ok := s.labelToValueToIDs[k]
		if !ok {
			return
		}
		if values.anyValues != nil {
			values.anyValues.Iter(maybeEmit)
		}
		if ids := values.values[v]; ids != nil {
			ids.Iter(maybeEmit)
		}
	})
	s.unoptimizedIDs.Iter(maybeEmit)
}

type kvSource interface {
	Get(labelName string) (value string, present bool)
	IterKVs(func(k, v string))
}
