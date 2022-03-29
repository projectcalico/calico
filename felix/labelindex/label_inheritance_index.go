// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The labelindex package provides the InheritIndex type, which emits events as the set of
// items (currently WorkloadEndpoints/HostEndpoint) it has been told about start (or stop) matching
// the label selectors (which are extracted from the active policy rules) it has been told about.
//
// Label inheritance
//
// As the name suggests, the InheritIndex supports the notion of label inheritance.  In our
// data-model:
//
//     - endpoints have their own labels; these take priority over any inherited labels
//     - endpoints also inherit labels from any explicitly-named profiles in their data
//     - profiles have explicit labels
//
// For example, suppose an endpoint had labels
//
//     {"a": "ep-a", "b": "ep-b"}
//
// and it explicitly referenced profile "profile-A", which had these labels:
//
//     {"a": "prof-a", "c": "prof-c", "d": "prof-d"}
//
// then the resulting labels for the endpoint after considering inheritance would be:
//
//     {
//         "a": "ep-a",    // Explicit endpoint label "wins" over profile labels.
//         "b": "ep-b",
//         "c": "prof-c",  // Profile label gets inherited.
//         "d": "prof-d",
//     }
package labelindex

import (
	"github.com/projectcalico/calico/felix/multidict"
	"reflect"

	log "github.com/sirupsen/logrus"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// itemData holds the data that we know about a particular item (i.e. a workload or host endpoint).
// In particular, it holds it current explicitly-assigned labels and a pointer to the parent data
// for each of its parents.
type itemData struct {
	labels  map[string]string
	parents []*parentData
}

// Get implements the Labels interface for itemData.  Combines the item's own labels with those
// of its parents on the fly.
func (itemData *itemData) Get(labelName string) (value string, present bool) {
	if value, present = itemData.labels[labelName]; present {
		return
	}
	for _, parent := range itemData.parents {
		if value, present = parent.labels[labelName]; present {
			return
		}
	}
	return
}

// parentData holds the data that we know about each parent (i.e. each security profile).  Since,
// profiles consist of multiple resources in our data-model, any of the fields may be nil if we
// have partial information.
type parentData struct {
	id      string
	labels  map[string]string
	itemIDs set.Set
}

type MatchCallback func(selId, labelId interface{})

type InheritIndex struct {
	itemDataByID              map[interface{}]*itemData
	labelIdByVauewithEMLabels map[string]multidict.StringToIface
	parentDataByParentID      map[string]*parentData
	selectorsById             map[interface{}]selector.Selector
	selIdsByValueWithEMLabels map[string]multidict.StringToIface

	// Current matches.
	selIdsByLabelId map[interface{}]set.Set
	labelIdsBySelId map[interface{}]set.Set

	// Callback functions
	OnMatchStarted MatchCallback
	OnMatchStopped MatchCallback

	dirtyItemIDs set.Set
}

/*
	This should be passed in with config option.
	Ordered by potential match number.
 */
var (
	ExactMatchLabels = []string{v3.LabelNamespace}
)

func NewInheritIndex(onMatchStarted, onMatchStopped MatchCallback) *InheritIndex {
	itemData := map[interface{}]*itemData{}
	inheritIDx := InheritIndex{
		itemDataByID:              itemData,
		labelIdByVauewithEMLabels: map[string]multidict.StringToIface{},
		parentDataByParentID:      map[string]*parentData{},
		selectorsById:             map[interface{}]selector.Selector{},
		selIdsByValueWithEMLabels: map[string]multidict.StringToIface{},
		selIdsByLabelId: map[interface{}]set.Set{},
		labelIdsBySelId: map[interface{}]set.Set{},

		// Callback functions
		OnMatchStarted: onMatchStarted,
		OnMatchStopped: onMatchStopped,

		dirtyItemIDs: set.New(),
	}
	for _, em := range ExactMatchLabels {
		inheritIDx.labelIdByVauewithEMLabels[em] = multidict.NewStringToIface()
		inheritIDx.selIdsByValueWithEMLabels[em] = multidict.NewStringToIface()
	}
	return &inheritIDx
}

// OnUpdate makes LabelInheritanceIndex compatible with the UpdateHandler interface
// allowing it to be used in a calculation graph more easily.
func (l *InheritIndex) OnUpdate(update api.Update) (_ bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		if update.Value != nil {
			log.Debugf("Updating InheritIndex with endpoint %v", key)
			endpoint := update.Value.(*model.WorkloadEndpoint)
			profileIDs := endpoint.ProfileIDs
			l.UpdateLabels(key, endpoint.Labels, profileIDs)
		} else {
			log.Debugf("Deleting endpoint %v from InheritIndex", key)
			l.DeleteLabels(key)
		}
	case model.HostEndpointKey:
		if update.Value != nil {
			// Figure out what's changed and update the cache.
			log.Infof("Updating InheritIndex for host endpoint %v", key)
			endpoint := update.Value.(*model.HostEndpoint)
			profileIDs := endpoint.ProfileIDs
			l.UpdateLabels(key, endpoint.Labels, profileIDs)
		} else {
			log.Debugf("Deleting host endpoint %v from InheritIndex", key)
			l.DeleteLabels(key)
		}
	case model.ResourceKey:
		if key.Kind != v3.KindProfile {
			return
		}
		if update.Value != nil {
			log.Debugf("Updating InheritIndex for profile labels %v", key)
			labels := update.Value.(*v3.Profile).Spec.LabelsToApply
			l.UpdateParentLabels(key.Name, labels)
		} else {
			log.Debugf("Removing profile labels %v from InheritIndex", key)
			l.DeleteParentLabels(key.Name)
		}
	}
	return
}

func (idx *InheritIndex) UpdateSelector(id interface{}, sel selector.Selector) {
	if sel == nil {
		log.WithField("id", id).Panic("Selector should not be nil")
	}
	oldSel := idx.selectorsById[id]
	// Since the selectorRoot struct has cache fields, the easiest way to compare two
	// selectors is to compare their IDs.
	if oldSel != nil && oldSel.UniqueID() == sel.UniqueID() {
		log.WithField("selID", id).Debug("Skipping unchanged selector")
		return
	}

	log.WithField("selID", id).Info("Updating selector")
	sem := sel.GetExactMatch()
	for _, emk := range ExactMatchLabels {
		// Use empty to indicate not-specified
		v := sem[emk]
		idx.selIdsByValueWithEMLabels[emk].Put(v, id)
	}
	idx.scanAllLabels(id, sel)
	idx.selectorsById[id] = sel
}

func (idx *InheritIndex) DeleteSelector(id interface{}) {
	log.Infof("Deleting selector %v", id)
	matchSet := idx.labelIdsBySelId[id]
	if matchSet != nil {
		matchSet.Iter(func(labelId interface{}) error {
			// This modifies the set we're iterating over, but that's safe in Go.
			idx.deleteMatch(id, labelId)
			return nil
		})
	}
	sel := idx.selectorsById[id]
	if sel != nil {
		sem := sel.GetExactMatch()
		for _, e := range ExactMatchLabels {
			v := sem[e]
			idx.selIdsByValueWithEMLabels[e].Discard(v, id)
		}
	}
	delete(idx.selectorsById, id)
}

func (idx *InheritIndex) UpdateLabels(id interface{}, labels map[string]string, parentIDs []string) {
	log.Debug("Inherit index updating labels for ", id)
	log.Debug("Num dirty items ", idx.dirtyItemIDs.Len(), " items")

	oldItemData := idx.itemDataByID[id]
	var oldParents []*parentData
	if oldItemData != nil {
		oldParents = oldItemData.parents
		oldLabels := oldItemData.labels
		if reflect.DeepEqual(oldLabels, labels) &&
			reflect.DeepEqual(oldParents, parentIDs) {
			log.Debug("No change to labels or parentIDs, ignoring.")
			return
		}
	}
	newItemData := &itemData{}
	if len(labels) > 0 {
		newItemData.labels = labels
		for _, em := range ExactMatchLabels{
			v := labels[em]
			idx.labelIdByVauewithEMLabels[em].Put(v, id)
		}
	}
	if len(parentIDs) > 0 {
		parents := make([]*parentData, len(parentIDs))
		for i, pID := range parentIDs {
			parents[i] = idx.getOrCreateParent(pID)
		}
		newItemData.parents = parents
	}
	idx.itemDataByID[id] = newItemData

	idx.onItemParentsUpdate(id, oldParents, newItemData.parents)

	idx.dirtyItemIDs.Add(id)
	idx.flushUpdates()
	log.Debug("Num ending dirty items ", idx.dirtyItemIDs.Len(), " items")
}

func (idx *InheritIndex) DeleteLabels(id interface{}) {
	log.Debug("Inherit index deleting labels for ", id)
	oldItemData := idx.itemDataByID[id]
	var oldParents []*parentData
	if oldItemData != nil {
		oldParents = oldItemData.parents
	}
	for _, em := range ExactMatchLabels{
		v := ""
		if oldItemData!= nil && oldItemData.labels != nil {
			v = oldItemData.labels[em]
		}
		idx.labelIdByVauewithEMLabels[em].Discard(v, id)
	}
	delete(idx.itemDataByID, id)
	idx.onItemParentsUpdate(id, oldParents, nil)
	idx.dirtyItemIDs.Add(id)
	idx.flushUpdates()
}

func (idx *InheritIndex) getOrCreateParent(id string) *parentData {
	parent := idx.parentDataByParentID[id]
	if parent == nil {
		parent = &parentData{
			id: id,
		}
		idx.parentDataByParentID[id] = parent
	}
	return parent
}

func (idx *InheritIndex) discardParentIfEmpty(id string) {
	parent := idx.parentDataByParentID[id]
	if parent == nil {
		return
	}
	if parent.itemIDs == nil && parent.labels == nil {
		delete(idx.parentDataByParentID, id)
	}
}

func (idx *InheritIndex) onItemParentsUpdate(id interface{}, oldParents, newParents []*parentData) {
	log.WithFields(log.Fields{
		"oldParents": oldParents,
		"newParents": newParents,
		"id":         id,
	}).Debug("Updating parents")
	// Calculate the current set of parent IDs so we can skip deletion of parents that are still
	// present.  We need to do this to avoid removing a still-current parent via
	// discardParentIfEmpty().
	currentParentIDs := set.New()
	for _, parentData := range newParents {
		currentParentIDs.Add(parentData.id)
	}

	for _, parent := range oldParents {
		if currentParentIDs.Contains(parent.id) {
			// Make sure we don't delete current parents from the index.
			continue
		}
		parent.itemIDs.Discard(id)
		if parent.itemIDs.Len() == 0 {
			parent.itemIDs = nil
		}
		idx.discardParentIfEmpty(parent.id)
	}

	for _, parent := range newParents {
		if parent.itemIDs == nil {
			parent.itemIDs = set.New()
		}
		parent.itemIDs.Add(id)
	}
}

func (idx *InheritIndex) UpdateParentLabels(parentID string, labels map[string]string) {
	parent := idx.getOrCreateParent(parentID)
	parent.labels = labels
	idx.flushChildren(parentID)
}

func (idx *InheritIndex) DeleteParentLabels(parentID string) {
	parent := idx.parentDataByParentID[parentID]
	if parent == nil {
		return
	}
	parent.labels = nil
	idx.discardParentIfEmpty(parentID)
	idx.flushChildren(parentID)
}

func (idx *InheritIndex) flushChildren(parentID string) {
	parentData := idx.parentDataByParentID[parentID]
	if parentData != nil && parentData.itemIDs != nil {
		parentData.itemIDs.Iter(func(itemID interface{}) error {
			log.Debug("Marking child ", itemID, " dirty")
			idx.dirtyItemIDs.Add(itemID)
			return nil
		})
	}
	idx.flushUpdates()
}

func (idx *InheritIndex) flushUpdates() {
	idx.dirtyItemIDs.Iter(func(itemID interface{}) error {
		log.Debugf("Flushing %#v", itemID)
		_, ok := idx.itemDataByID[itemID]
		if !ok {
			// Item deleted.
			log.Debugf("Flushing delete of item %v", itemID)
			matchSet := idx.selIdsByLabelId[itemID]
			if matchSet != nil {
				matchSet.Iter(func(selId interface{}) error {
					// This modifies the set we're iterating over, but that's safe in Go.
					idx.deleteMatch(selId, itemID)
					return nil
				})
			}
		} else {
			// Item updated/created, re-evaluate labels.
			log.Debugf("Flushing update of item %v", itemID)
			idx.scanAllSelectors(itemID)
		}
		return set.RemoveItem
	})
}

func (idx *InheritIndex) scanAllLabels(selId interface{}, sel selector.Selector) {
	log.Debugf("Scanning all (%v) labels against selector %v",
		len(idx.itemDataByID), selId)

	sem := sel.GetExactMatch()
	emk := ""
	emv := ""
	for _, e := range ExactMatchLabels{
		if _, ok := sem[e]; ok {
			emk = e
			emv =sem[e]
			break
		}
	}
	//We get the exact match
	if emk != "" {
		count := 0
		idx.labelIdByVauewithEMLabels[emk].Iter(emv, func(labelId interface{}){
			labels := idx.itemDataByID[labelId]
			idx.updateMatches(selId, sel, labelId, labels)
			count ++
		})
		if count != 0 {
			log.WithField("sel", sel).Infof("scanAllLabels: emk %s emv %s count %d with total %d", emk, emv, count, len(idx.itemDataByID))
		}
	} else {
		for labelId, labels := range idx.itemDataByID {
			idx.updateMatches(selId, sel, labelId, labels)
		}
		log.WithField("sel", sel).Infof("scanAllLabels: hit global search %d", len(idx.itemDataByID))
	}
}

func (idx *InheritIndex) scanAllSelectors(labelId interface{}) {
	log.Debugf("Scanning all (%v) selectors against labels %v",
		len(idx.selectorsById), labelId)
	labels := idx.itemDataByID[labelId]

	emk := ""
	emv := ""
	for _, e := range ExactMatchLabels{
		if _, ok := labels.labels[e]; ok {
			emk = e
			emv =labels.labels[e]
			break
		}
	}
	if emk != "" {
		count := 0
		emptyCount := 0
		idx.selIdsByValueWithEMLabels[emk].Iter(emv, func(selId interface{}){
			sel := idx.selectorsById[selId]
			idx.updateMatches(selId, sel, labelId, labels)
			count++
		})
		// Check selector without corresponding match
		idx.selIdsByValueWithEMLabels[emk].Iter("", func(selId interface{}){
			sel := idx.selectorsById[selId]
			idx.updateMatches(selId, sel, labelId, labels)
			emptyCount++
		})
		if count != 0 || emptyCount != 0 {
			log.WithField("label", labelId).Infof("scanAllSelectors: emk %s emv %s count %d emptyCount %d with total %d", emk, emv, count, emptyCount, len(idx.selectorsById))
		}
	} else {
		for selId, sel := range idx.selectorsById {
			idx.updateMatches(selId, sel, labelId, labels)
		}
		log.WithField("label", labelId).Infof("scanAllSelectors: hit global search %d", len(idx.selectorsById))
	}
}

func (idx *InheritIndex) updateMatches(
	selId interface{},
	sel selector.Selector,
	labelId interface{},
	labels parser.Labels,
) {
	nowMatches := sel.EvaluateLabels(labels)
	if nowMatches {
		idx.storeMatch(selId, labelId)
	} else {
		idx.deleteMatch(selId, labelId)
	}
}

func (idx *InheritIndex) storeMatch(selId, labelId interface{}) {
	labelIds := idx.labelIdsBySelId[selId]
	if labelIds == nil {
		labelIds = set.New()
		idx.labelIdsBySelId[selId] = labelIds
	}
	previouslyMatched := labelIds.Contains(labelId)
	if !previouslyMatched {
		log.Debugf("Selector %v now matches labels %v", selId, labelId)
		labelIds.Add(labelId)

		selIDs, ok := idx.selIdsByLabelId[labelId]
		if !ok {
			selIDs = set.New()
			idx.selIdsByLabelId[labelId] = selIDs
		}
		selIDs.Add(selId)

		idx.OnMatchStarted(selId, labelId)
	}
}

func (idx *InheritIndex) deleteMatch(selId, labelId interface{}) {
	labelIds := idx.labelIdsBySelId[selId]
	if labelIds == nil {
		return
	}
	previouslyMatched := labelIds.Contains(labelId)
	if previouslyMatched {
		log.Debugf("Selector %v no longer matches labels %v",
			selId, labelId)

		labelIds.Discard(labelId)
		if labelIds.Len() == 0 {
			delete(idx.labelIdsBySelId, selId)
		}

		idx.selIdsByLabelId[labelId].Discard(selId)
		if idx.selIdsByLabelId[labelId].Len() == 0 {
			delete(idx.selIdsByLabelId, labelId)
		}

		idx.OnMatchStopped(selId, labelId)
	}
}
