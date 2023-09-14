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
	"sort"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type KeyValueIndex[K comparable, V Labeled] struct {
	nameOfTrackedItems   string
	allValues            map[K]V
	labelKeyToValueToIDs map[string]values[K]
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

func (idx *KeyValueIndex[K, V]) Add(id K, v V) {
	idx.allValues[id] = v
	for k, v := range v.OwnLabels() {
		vals, ok := idx.labelKeyToValueToIDs[k]
		if !ok {
			vals = values[K]{
				m: map[string]set.Set[K]{},
			}
			idx.labelKeyToValueToIDs[k] = vals
		}
		setOfIDs := vals.m[v]
		if setOfIDs == nil {
			setOfIDs = set.New[K]()
			vals.m[v] = setOfIDs
		}
		setOfIDs.Add(id)
		vals.count++
		idx.labelKeyToValueToIDs[k] = vals
	}
}

func (idx *KeyValueIndex[K, V]) Remove(id K) {
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

func (idx *KeyValueIndex[K, V]) StrategyFor(k string, r parser.LabelRestriction) ScanStrategy[K] {
	if !r.MustBePresent {
		return idx.FullScanStrategy()
	}
	if r.MustHaveOneOfValues == nil {
		logrus.Debugf("Found %d %s with %s=<any>", idx.labelKeyToValueToIDs[k].count, idx.nameOfTrackedItems, k)
		return KeyOnlyStrategy[K]{label: k, values: idx.labelKeyToValueToIDs[k]}
	}

	var filteredMustHaves []string
	var idSets []set.Set[K]
	for _, v := range r.MustHaveOneOfValues {
		if idsSet := idx.labelKeyToValueToIDs[k].m[v]; idsSet != nil {
			filteredMustHaves = append(filteredMustHaves, v)
			idSets = append(idSets, idsSet)
		}
	}

	if len(filteredMustHaves) == 0 {
		// 0 but not nil: cannot match anything.
		logrus.Debugf("No %s with %s=%v", idx.nameOfTrackedItems, k, r.MustHaveOneOfValues)
		return NoMatchStrategy[K]{}
	}

	// We have more than one possible value.  For example, a selector like
	// "a == 'Z' || a == 'X'".
	return KeyValueStrategy[K]{
		label:  k,
		values: filteredMustHaves,
		idSets: idSets,
	}
}

func (idx *KeyValueIndex[K, V]) FullScanStrategy() ScanStrategy[K] {
	return AllStrategy[K, V]{allValues: idx.allValues}
}

func (idx *KeyValueIndex[K, V]) Get(id K) (V, bool) {
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

type KeyValueStrategy[T comparable] struct {
	label  string
	values []string
	idSets []set.Set[T]
}

func (k KeyValueStrategy[T]) String() string {
	return fmt.Sprintf("scan multi label %s=%v", k.label, k.values)
}

func (k KeyValueStrategy[T]) EstimatedItemsToScan() int {
	count := 0
	for _, s := range k.idSets {
		// Over counts if one object is in multiple sets, but we have to
		// scan/discard the dupe anyway.
		count += s.Len()
	}
	return count
}

func (k KeyValueStrategy[T]) Scan(f func(id T) bool) {
	if len(k.idSets) == 1 {
		// Mainline case, we have one set to scan.
		k.idSets[0].Iter(func(id T) error {
			f(id)
			return nil
		})
		return
	}

	if len(k.idSets) < 5 {
		// We only have a few sets, avoid allocating a "seen" set, which
		// could end up being large if the largest set is large.
		sort.Slice(k.idSets, func(i, j int) bool {
			// Sort biggest set first so that we have fewer callbacks from the
			// later sets.
			return k.idSets[j].Len() < k.idSets[i].Len()
		})
		for i, s1 := range k.idSets {
			s1.Iter(func(item T) error {
				// To check if we've seen this item before, look for it in
				// the sets we've already scanned.
				for j := 0; j < i; j++ {
					if k.idSets[j].Contains(item) {
						return nil
					}
				}
				f(item)
				return nil
			})
		}
		return
	}

	// We have a lot of sets, allocate a set to keep track of what we've seen.
	seen := set.New[T]()
	for i, s := range k.idSets {
		s.Iter(func(item T) error {
			if i != 0 && seen.Contains(item) {
				return nil
			}
			f(item)
			seen.Add(item)
			return nil
		})
	}
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
