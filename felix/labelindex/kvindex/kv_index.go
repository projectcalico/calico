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

package kvindex

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type KeyValueIndex[T comparable, V Labeled] struct {
	nameOfTrackedItems   string
	allValues            map[T]V
	labelKeyToValueToIDs map[string]values[T]
}

type Labeled interface {
	OwnLabels() map[string]string
}

func New[T comparable, V Labeled](nameOfTrackedItems string) *KeyValueIndex[T, V] {
	return &KeyValueIndex[T, V]{
		nameOfTrackedItems:   nameOfTrackedItems,
		allValues:            map[T]V{},
		labelKeyToValueToIDs: map[string]values[T]{},
	}
}

type values[T comparable] struct {
	m     map[string]set.Set[T]
	count int
}

func (idx *KeyValueIndex[T, V]) Add(id T, v V) {
	idx.allValues[id] = v
	for k, v := range v.OwnLabels() {
		vals, ok := idx.labelKeyToValueToIDs[k]
		if !ok {
			vals = values[T]{
				m: map[string]set.Set[T]{},
			}
			idx.labelKeyToValueToIDs[k] = vals
		}
		setOfIDs := vals.m[v]
		if setOfIDs == nil {
			setOfIDs = set.New[T]()
			vals.m[v] = setOfIDs
		}
		setOfIDs.Add(id)
		vals.count++
		idx.labelKeyToValueToIDs[k] = vals
	}
}

func (idx *KeyValueIndex[T, V]) Remove(id T) {
	v := idx.allValues[id]
	for k, v := range v.OwnLabels() {
		vals := idx.labelKeyToValueToIDs[k]
		setOfIDs := vals.m[v]
		setOfIDs.Discard(id)
		if setOfIDs.Len() == 0 {
			delete(vals.m, v)
			if len(vals.m) == 0 {
				delete(idx.labelKeyToValueToIDs, k)
				continue
			}
		}
		vals.count--
		idx.labelKeyToValueToIDs[k] = vals
	}
	delete(idx.allValues, id)
}

func (idx *KeyValueIndex[T, V]) StrategyFor(k string, r parser.LabelRestriction) ScanStrategy[T] {
	if r.MustHaveValue != "" {
		// FIXME this assumes "" is not a valid label value but it is
		idsSet := idx.labelKeyToValueToIDs[k].m[r.MustHaveValue]
		if idsSet == nil {
			// Short circuit. Selector requires label=='some value'
			// but there are no matching endpoints!
			logrus.Debugf("No %s with %s=%q", idx.nameOfTrackedItems, k, r.MustHaveValue)
			return NoMatchStrategy[T]{}
		} else {
			// Best case, we have a precise match on key and value, only
			// need to scan endpoints with exactly that key/value.
			logrus.Debugf("Found %d %s with %s=%q", idsSet.Len(), idx.nameOfTrackedItems, k, r.MustHaveValue)
			return KeyValueStrategy[T]{
				label:  k,
				value:  r.MustHaveValue,
				idsSet: idsSet,
			}
		}
	} else if r.MustBePresent {
		logrus.Debugf("Found %d %s with %s=<any>", idx.labelKeyToValueToIDs[k].count, idx.nameOfTrackedItems, k)
		return KeyOnlyStrategy[T]{label: k, values: idx.labelKeyToValueToIDs[k]}
	}
	return idx.FullScanStrategy()
}

func (idx *KeyValueIndex[T, V]) FullScanStrategy() ScanStrategy[T] {
	return AllStrategy[T, V]{allValues: idx.allValues}
}

func (idx *KeyValueIndex[T, V]) Get(id T) (V, bool) {
	v, ok := idx.allValues[id]
	return v, ok
}

type NoMatchStrategy[T any] struct {
}

func (n NoMatchStrategy[T]) String() string {
	return "no match"
}

func (n NoMatchStrategy[T]) EstimatedItemsToScan() int {
	return 0
}

func (n NoMatchStrategy[T]) Scan(f func(id T) bool) {
}

type KeyValueStrategy[T any] struct {
	label, value string
	idsSet       set.Set[T]
}

func (k KeyValueStrategy[T]) String() string {
	return fmt.Sprintf("scan exact label %s=%q", k.label, k.value)
}

func (k KeyValueStrategy[T]) EstimatedItemsToScan() int {
	return k.idsSet.Len()
}

func (k KeyValueStrategy[T]) Scan(f func(id T) bool) {
	k.idsSet.Iter(func(item T) error {
		f(item)
		return nil
	})
}

type KeyOnlyStrategy[T comparable] struct {
	label  string
	values values[T]
}

func (k KeyOnlyStrategy[T]) String() string {
	return fmt.Sprintf("scan all values of label %s", k.label)
}

func (k KeyOnlyStrategy[T]) EstimatedItemsToScan() int {
	return k.values.count
}

func (k KeyOnlyStrategy[T]) Scan(f func(id T) bool) {
	for _, epIDs := range k.values.m {
		epIDs.Iter(func(id T) error {
			f(id)
			return nil
		})
	}
}

type AllStrategy[T comparable, V Labeled] struct {
	allValues map[T]V
}

func (a AllStrategy[T, V]) String() string {
	return "full scan"
}

func (a AllStrategy[T, V]) EstimatedItemsToScan() int {
	return len(a.allValues)
}

func (a AllStrategy[T, V]) Scan(f func(id T) bool) {
	for id := range a.allValues {
		f(id)
	}
}

type ScanStrategy[T any] interface {
	EstimatedItemsToScan() int
	Scan(func(id T) bool)
	String() string
}
