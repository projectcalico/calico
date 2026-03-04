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
	"iter"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/uniquestr"
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
	allItems              map[ItemID]Item
	labelNameToValueToIDs map[uniquestr.Handle]values[ItemID]
}

type Labeled interface {
	OwnLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle]
}

func New[ItemID comparable, Item Labeled](nameOfTrackedItems string) *LabelNameValueIndex[ItemID, Item] {
	return &LabelNameValueIndex[ItemID, Item]{
		nameOfTrackedItems:    nameOfTrackedItems,
		allItems:              map[ItemID]Item{},
		labelNameToValueToIDs: map[uniquestr.Handle]values[ItemID]{},
	}
}

type values[ItemID comparable] struct {
	m     map[uniquestr.Handle]*set.Adaptive[ItemID]
	count int
}

// Add an item to the index.  Note: its labels will be captured at this
// time, so if the objects labels are mutated, it is important to remove the
// item before changing its labels and then re-Add the updated item.
//
// To avoid the above bug, panics if the same ID is added twice.
func (idx *LabelNameValueIndex[ItemID, Item]) Add(id ItemID, item Item) {
	if _, ok := idx.allItems[id]; ok {
		logrus.WithFields(logrus.Fields{
			"id":    id,
			"item":  item,
			"index": idx.nameOfTrackedItems,
		}).Panic("Add called for ID that is already in the index.")
	}
	idx.allItems[id] = item
	for k, v := range item.OwnLabelHandles() {
		vals, ok := idx.labelNameToValueToIDs[k]
		if !ok {
			vals = values[ItemID]{
				m: map[uniquestr.Handle]*set.Adaptive[ItemID]{},
			}
			idx.labelNameToValueToIDs[k] = vals
		}
		setOfIDs := vals.m[v]
		if setOfIDs == nil {
			setOfIDs = set.NewAdaptive[ItemID]()
			vals.m[v] = setOfIDs
		}
		setOfIDs.Add(id)
		vals.count++
		// Map stores the value type (not pointer); write back the update.
		idx.labelNameToValueToIDs[k] = vals
	}
}

// Remove an item from the index.  Note that it is important that the labels
// are not mutated between Add and Remove calls.
func (idx *LabelNameValueIndex[ItemID, Item]) Remove(id ItemID) {
	v := idx.allItems[id]
	for k, v := range v.OwnLabelHandles() {
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
	delete(idx.allItems, id)
}

// StrategyFor returns the best available ScanStrategy for the given
// label name and selector LabelRestriction (which should be the restriction
// for that label).  If the LabelRestriction is not "useful", returns
// FullScanStrategy().
func (idx *LabelNameValueIndex[ItemID, Item]) StrategyFor(labelName uniquestr.Handle, r parser.LabelRestriction) ScanStrategy[ItemID] {
	if !r.MustBePresent {
		// Not much we can do if the selector doesn't match on this label.
		return FullScanStrategy[ItemID, Item]{allItems: idx.allItems}
	}

	if r.MustHaveOneOfValues == nil {
		// A selector such as "has(labelName)", which matches the label but
		// not any particular value.
		if vals, ok := idx.labelNameToValueToIDs[labelName]; !ok {
			logrus.Debugf("Found no matches for %s with %s=<any>", idx.nameOfTrackedItems, labelName.Value())
			return NoMatchStrategy[ItemID]{}
		} else {
			logrus.Debugf("Found %d %s with %s=<any>", vals.count, idx.nameOfTrackedItems, labelName.Value())
			return LabelNameStrategy[ItemID]{label: labelName, values: vals}
		}
	}

	// If we get here, then the selector does match on this label, and it cares
	// about specific values. Whittle down the list of values to the ones that
	// match objects that we're tracking.
	var filteredMustHaves []uniquestr.Handle
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
		logrus.Debugf("No %s with %s=%v", idx.nameOfTrackedItems, labelName.Value(), uniquestr.HandleSliceStringer(r.MustHaveOneOfValues))
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
	return FullScanStrategy[ItemID, Item]{allItems: idx.allItems}
}

// Get looks up an item by its ID.  (Allows this object to be the primary
// map datastructure for storing the items.)
func (idx *LabelNameValueIndex[ItemID, Item]) Get(id ItemID) (Item, bool) {
	v, ok := idx.allItems[id]
	return v, ok
}

func (idx *LabelNameValueIndex[ItemID, Item]) Len() int {
	return len(idx.allItems)
}

// ScanStrategy abstracts over particular types of scans of the index, allowing
// them to be compared/scored without actually executing the scan until ready
// to do so.
type ScanStrategy[ItemID any] interface {
	// EstimatedItemsToScan returns an estimate for how many items this scan
	// strategy would produce if Scan() was called.  Some strategies return
	// an approximate value because calculating the real value would require
	// executing the scan.
	EstimatedItemsToScan() int

	// Scan executes the scan. It calls the given func once with each ID
	// produced by the scan.  Each ID is only emitted once (the strategy is
	// responsible for any deduplication).  Scanning continues while the func
	// returns true.
	Scan(func(id ItemID) bool)

	// Name of the strategy (used in prometheus metrics).
	Name() string

	fmt.Stringer
}

// NoMatchStrategy is a ScanStrategy that produces no items, it is returned
// when the index can prove that there are no matching items.
type NoMatchStrategy[ItemID any] struct {
}

func (n NoMatchStrategy[ItemID]) String() string {
	return "no match"
}

func (n NoMatchStrategy[ItemID]) EstimatedItemsToScan() int {
	return 0
}

func (n NoMatchStrategy[ItemID]) Scan(func(id ItemID) bool) {
}

func (n NoMatchStrategy[ItemID]) Name() string {
	return "no-match"
}

// LabelNameSingleValueStrategy is a ScanStrategy that scans over items that have
// a specific value for a certain label.  It is the narrowest, most optimized
// strategy.
type LabelNameSingleValueStrategy[ItemID comparable] struct {
	label uniquestr.Handle
	value uniquestr.Handle
	idSet set.Set[ItemID]
}

func (s LabelNameSingleValueStrategy[ItemID]) String() string {
	return fmt.Sprintf("scan single label %s=%v", s.label.Value(), s.value.Value())
}

func (s LabelNameSingleValueStrategy[ItemID]) EstimatedItemsToScan() int {
	return s.idSet.Len()
}

func (s LabelNameSingleValueStrategy[ItemID]) Scan(f func(id ItemID) bool) {
	// Ideal case, we have one set to scan.
	for id := range s.idSet.All() {
		if !f(id) {
			break
		}
	}
}

func (s LabelNameSingleValueStrategy[ItemID]) Name() string {
	return "single-value"
}

// LabelNameMultiValueStrategy is a ScanStrategy that scans over items that have
// specific, values for a certain label.
type LabelNameMultiValueStrategy[ItemID comparable] struct {
	label  uniquestr.Handle
	values []uniquestr.Handle
	idSets []set.Set[ItemID]
}

func (s LabelNameMultiValueStrategy[ItemID]) String() string {
	return fmt.Sprintf("scan multi label %s=%v", s.label.Value(), uniquestr.HandleSliceStringer(s.values))
}

func (s LabelNameMultiValueStrategy[ItemID]) EstimatedItemsToScan() int {
	count := 0
	for _, s := range s.idSets {
		// Over counts if one object is in multiple sets, but Scan() needs
		// to do a bit of work per object to dedupe.
		count += s.Len()
	}
	return count
}

func (s LabelNameMultiValueStrategy[ItemID]) Scan(f func(id ItemID) bool) {
	set.IterUnion(s.idSets, f)
}

func (s LabelNameMultiValueStrategy[ItemID]) Name() string {
	return "multi-value"
}

// LabelNameStrategy is a ScanStrategy that scans all object that have a
// particular label, no matter the value of that label.  It is used for
// selectors such as "has(labelName)".
type LabelNameStrategy[ItemID comparable] struct {
	label  uniquestr.Handle
	values values[ItemID]
}

func (s LabelNameStrategy[ItemID]) String() string {
	return fmt.Sprintf("scan all values of label %s", s.label.Value())
}

func (s LabelNameStrategy[ItemID]) EstimatedItemsToScan() int {
	return s.values.count
}

func (s LabelNameStrategy[ItemID]) Scan(f func(id ItemID) bool) {
	for _, epIDs := range s.values.m {
		stop := false
		for id := range epIDs.All() {
			if !f(id) {
				stop = true
				break
			}
		}
		if stop {
			return
		}
	}
}

func (s LabelNameStrategy[ItemID]) Name() string {
	return "label-name"
}

// FullScanStrategy is a ScanStrategy that scans all items in a completely
// unoptimized way.  It is returned if the selector cannot be optimized.
type FullScanStrategy[ItemID comparable, Item Labeled] struct {
	allItems map[ItemID]Item
}

func (s FullScanStrategy[ItemID, Item]) String() string {
	return "full-scan"
}

func (s FullScanStrategy[ItemID, Item]) EstimatedItemsToScan() int {
	return len(s.allItems)
}

func (s FullScanStrategy[ItemID, Item]) Scan(f func(id ItemID) bool) {
	for id := range s.allItems {
		if !f(id) {
			return
		}
	}
}

func (s FullScanStrategy[ItemID, Item]) Name() string {
	return "full-scan"
}
