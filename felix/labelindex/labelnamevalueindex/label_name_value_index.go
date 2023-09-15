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
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// LabelNameValueIndex stores a set of Labeled objects by ID, and it indexes
// them according to their own (not inherited) labels/label values for
// efficient scans based on selector LabelRestrictions.  The StrategyFor
// method returns the most efficient strategy for a particular restriction.
// Returning strategies allows the caller to compare different available
// strategies against each other without executing them.
//
// Note: LabelNameValueIndex is not inheritance-aware, it indexes items
// solely on their own labels without taking parents into account.  This avoids
// needing to reindex every item when a parent changes, allowing that to be
// handled more efficiently at the layer above.
type LabelNameValueIndex[ItemID comparable, Item Labeled] struct {
	nameOfTrackedItems    string
	allValues             map[ItemID]Item
	labelNameToValueToIDs map[string]values[ItemID]
}

type Labeled interface {
	OwnLabels() map[string]string
}

func New[ItemID comparable, Item Labeled](nameOfTrackedItems string) *LabelNameValueIndex[ItemID, Item] {
	return &LabelNameValueIndex[ItemID, Item]{
		nameOfTrackedItems:    nameOfTrackedItems,
		allValues:             map[ItemID]Item{},
		labelNameToValueToIDs: map[string]values[ItemID]{},
	}
}

type values[T comparable] struct {
	m     map[string]set.Set[T]
	count int
}

// Add an item to the index.  Note: its labels will be captured at this
// time, so if the objects labels are mutated, it is important to remove the
// item before changing its labels and then re-Add the updated item.
func (idx *LabelNameValueIndex[ItemID, Item]) Add(id ItemID, item Item) {
	idx.allValues[id] = item
	for k, v := range item.OwnLabels() {
		vals, ok := idx.labelNameToValueToIDs[k]
		if !ok {
			vals = values[ItemID]{
				m: map[string]set.Set[ItemID]{},
			}
			idx.labelNameToValueToIDs[k] = vals
		}
		setOfIDs := vals.m[v]
		if setOfIDs == nil {
			setOfIDs = set.New[ItemID]()
			vals.m[v] = setOfIDs
		}
		setOfIDs.Add(id)
		vals.count++
		idx.labelNameToValueToIDs[k] = vals
	}
}

// Remove an item from the index.  Note that it is important that the labels
// are not mutated between Add and Remove calls.
func (idx *LabelNameValueIndex[ItemID, Item]) Remove(id ItemID) {
	v := idx.allValues[id]
	for k, v := range v.OwnLabels() {
		vals := idx.labelNameToValueToIDs[k]
		setOfIDs := vals.m[v]
		setOfIDs.Discard(id)
		if setOfIDs.Len() == 0 {
			delete(vals.m, v)
			if len(vals.m) == 0 {
				delete(idx.labelNameToValueToIDs, k)
				continue
			}
		}
		vals.count--
		idx.labelNameToValueToIDs[k] = vals
	}
	delete(idx.allValues, id)
}

// StrategyFor returns the best available ScanStrategy for the given
// label name and selector LabelRestriction (which should be the restriction
// for that label).  If the LabelRestriction is not "useful", returns
// FullScanStrategy().
func (idx *LabelNameValueIndex[ItemID, Item]) StrategyFor(labelName string, r parser.LabelRestriction) ScanStrategy[ItemID] {
	if !r.MustBePresent {
		// Not much we can do if the selector doesn't match on this label.
		return idx.FullScanStrategy()
	}

	if r.MustHaveOneOfValues == nil {
		// A selector such as "has(labelName)", which matches the label but
		// not any particular value.
		logrus.Debugf("Found %d %s with %s=<any>", idx.labelNameToValueToIDs[labelName].count, idx.nameOfTrackedItems, labelName)
		return LabelNameStrategy[ItemID]{label: labelName, values: idx.labelNameToValueToIDs[labelName]}
	}

	// If we get here, then the selector does match on this label and it cares
	// about specific values. Whittle down the list of values to the ones that
	// match objects that we're tracking.
	var filteredMustHaves []string
	var idSets []set.Set[ItemID]
	for _, v := range r.MustHaveOneOfValues {
		if idsSet := idx.labelNameToValueToIDs[labelName].m[v]; idsSet != nil {
			filteredMustHaves = append(filteredMustHaves, v)
			idSets = append(idSets, idsSet)
		}
	}

	if len(filteredMustHaves) == 0 {
		// We filtered all values out!  That means that the selector cannot
		// match anything.  If it could match something, we'd have found it
		// in the index.
		logrus.Debugf("No %s with %s=%v", idx.nameOfTrackedItems, labelName, r.MustHaveOneOfValues)
		return NoMatchStrategy[ItemID]{}
	}

	if len(filteredMustHaves) == 1 {
		// Best case: we got exactly one label value.
		return LabelNameSingleValueStrategy[ItemID]{
			label: labelName,
			value: filteredMustHaves[0],
			idSet: idSets[0],
		}
	}

	// We have matches on label and more than one value.
	return LabelNameMultiValueStrategy[ItemID]{
		label:  labelName,
		values: filteredMustHaves,
		idSets: idSets,
	}
}

// FullScanStrategy returns a scan strategy that scans all items.
func (idx *LabelNameValueIndex[ItemID, Item]) FullScanStrategy() ScanStrategy[ItemID] {
	return AllStrategy[ItemID, Item]{allValues: idx.allValues}
}

// Get looks up an item by its ID.  (Allows this object to be the primary
// map datastructure for storing the items.)
func (idx *LabelNameValueIndex[ItemID, Item]) Get(id ItemID) (Item, bool) {
	v, ok := idx.allValues[id]
	return v, ok
}

// ScanStrategy abstracts over particular types of scans of the index, allowing
// them to be compared/scored without actually executing the scan until ready
// to do so.
type ScanStrategy[T any] interface {
	// EstimatedItemsToScan returns an estimate for how many items this scan
	// strategy would produce if Scan() was called.  Some strategies return
	// an approximate value because calculating the real value would require
	// executing the scan.
	EstimatedItemsToScan() int

	// Scan executes the scan. It calls the given func once with each ID
	// produced by the scan.  Each ID is only emitted once (the strategy is
	// responsible for any deduplication).  Scanning continues while the func
	// returns true.
	Scan(func(id T) bool)

	fmt.Stringer
}

// NoMatchStrategy is a ScanStrategy that produces no items, it is returned
// when the index can prove that there are no matching items.
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

// LabelNameSingleValueStrategy is a ScanStrategy that scans over items that have
// a specific value for a certain label.  It is the narrowest, most optimized
// strategy.
type LabelNameSingleValueStrategy[T comparable] struct {
	label string
	value string
	idSet set.Set[T]
}

func (k LabelNameSingleValueStrategy[T]) String() string {
	return fmt.Sprintf("scan single label %s=%v", k.label, k.value)
}

func (k LabelNameSingleValueStrategy[T]) EstimatedItemsToScan() int {
	return k.idSet.Len()
}

func (k LabelNameSingleValueStrategy[T]) Scan(f func(id T) bool) {
	// Ideal case, we have one set to scan.
	k.idSet.Iter(func(id T) error {
		if !f(id) {
			return set.StopIteration
		}
		return nil
	})
}

// LabelNameMultiValueStrategy is a ScanStrategy that scans over items that have
// specific, values for a certain label.
type LabelNameMultiValueStrategy[T comparable] struct {
	label  string
	values []string
	idSets []set.Set[T]
}

func (k LabelNameMultiValueStrategy[T]) String() string {
	return fmt.Sprintf("scan multi label %s=%v", k.label, k.values)
}

func (k LabelNameMultiValueStrategy[T]) EstimatedItemsToScan() int {
	count := 0
	for _, s := range k.idSets {
		// Over counts if one object is in multiple sets, but Scan() needs
		// to do a bit of work per object to dedupe.
		count += s.Len()
	}
	return count
}

func (k LabelNameMultiValueStrategy[T]) Scan(f func(id T) bool) {
	set.IterUnion(k.idSets, f)
}

// LabelNameStrategy is a ScanStrategy that scans all object that have a
// particular label, no matter the value of that label.  It is used for
// selectors such as "has(labelName)".
type LabelNameStrategy[T comparable] struct {
	label  string
	values values[T]
}

func (k LabelNameStrategy[T]) String() string {
	return fmt.Sprintf("scan all values of label %s", k.label)
}

func (k LabelNameStrategy[T]) EstimatedItemsToScan() int {
	return k.values.count
}

func (k LabelNameStrategy[T]) Scan(f func(id T) bool) {
	for _, epIDs := range k.values.m {
		stop := false
		epIDs.Iter(func(id T) error {
			if !f(id) {
				stop = true
				return set.StopIteration
			}
			return nil
		})
		if stop {
			return
		}
	}
}

// AllStrategy is a ScanStrategy that scans all items in a completely
// unoptimized way.  It is returned if the selector cannot be optimized.
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
		if !f(id) {
			return
		}
	}
}
