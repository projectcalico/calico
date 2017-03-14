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
//     - profiles also have (now deprecated) tags, which we now treat as implicit <tagName>=""
//       labels; explicit profile labels take precidence over implicit tag labels.
//
// For example, suppose an endpoint had labels
//
//     {"a": "ep-a", "b": "ep-b"}
//
// and it explicitly referenced profile "profile-A", which had these labels and tags:
//
//     {"a": "prof-a", "c": "prof-c", "d": "prof-d"}
//     ["a", "tag-x", "d"]
//
// then the resulting labels for the endpoint after considering inheritance would be:
//
//     {
//         "a": "ep-a",    // Explicit endpoint label "wins" over profile labels/tags.
//         "b": "ep-b",
//         "c": "prof-c",  // Profile label gets inherited.
//         "d": "prof-d",  // Profile label "wins" over profile tag with same name.
//         "tag-x": "",    // Profile tag inherited as empty label.
//     }
package labelindex

import (
	log "github.com/Sirupsen/logrus"

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/set"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/selector"
)

// itemData holds the data that we know about a particular item (i.e. a workload or host endpoint).
// In particular, it holds it current explicitly-assigned labels and a pointer to the parent data
// for each of its parents.
type itemData struct {
	labels  map[string]string
	parents []*parentData
}

// Get implements the Labels interface for itemData.  Combines the item's own labels with that
// of its parents on the fly.
func (itemData *itemData) Get(labelName string) (value string, present bool) {
	if value, present = itemData.labels[labelName]; present {
		return
	}
	for _, parent := range itemData.parents {
		if value, present = parent.labels[labelName]; present {
			return
		}
		for _, tag := range parent.tags {
			if tag == labelName {
				present = true
				return
			}
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
	tags    []string
	itemIDs set.Set
}

type InheritIndex struct {
	index Index

	itemDataByID         map[interface{}]*itemData
	parentDataByParentID map[string]*parentData

	dirtyItemIDs set.Set
}

func NewInheritIndex(onMatchStarted, onMatchStopped MatchCallback) *InheritIndex {
	index := NewIndex(onMatchStarted, onMatchStopped)
	inheritIDx := InheritIndex{
		index: index,

		itemDataByID:         map[interface{}]*itemData{},
		parentDataByParentID: map[string]*parentData{},

		dirtyItemIDs: set.New(),
	}
	return &inheritIDx
}

func (l *InheritIndex) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.ProfileTagsKey{}, l.OnUpdate)
	allUpdDispatcher.Register(model.ProfileLabelsKey{}, l.OnUpdate)
	allUpdDispatcher.Register(model.WorkloadEndpointKey{}, l.OnUpdate)
	allUpdDispatcher.Register(model.HostEndpointKey{}, l.OnUpdate)
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
			log.Debugf("Updating InheritIndex for host endpoint %v", key)
			endpoint := update.Value.(*model.HostEndpoint)
			profileIDs := endpoint.ProfileIDs
			l.UpdateLabels(key, endpoint.Labels, profileIDs)
		} else {
			log.Debugf("Deleting host endpoint %v from InheritIndex", key)
			l.DeleteLabels(key)
		}
	case model.ProfileLabelsKey:
		if update.Value != nil {
			log.Debugf("Updating InheritIndex for profile labels %v", key)
			labels := update.Value.(map[string]string)
			l.UpdateParentLabels(key.Name, labels)
		} else {
			log.Debugf("Removing profile labels %v from InheritIndex", key)
			l.DeleteParentLabels(key.Name)
		}
	case model.ProfileTagsKey:
		if update.Value != nil {
			log.Debugf("Updating InheritIndex for profile tags %v", key)
			labels := update.Value.([]string)
			l.UpdateParentTags(key.Name, labels)
		} else {
			log.Debugf("Removing profile tags %v from InheritIndex", key)
			l.DeleteParentTags(key.Name)
		}
	}
	return
}

func (idx *InheritIndex) UpdateSelector(id interface{}, sel selector.Selector) {
	idx.index.UpdateSelector(id, sel)
}

func (idx *InheritIndex) DeleteSelector(id interface{}) {
	idx.index.DeleteSelector(id)
}

func (idx *InheritIndex) UpdateLabels(id interface{}, labels map[string]string, parentIDs []string) {
	log.Debug("Inherit index updating labels for ", id)
	log.Debug("Num dirty items ", idx.dirtyItemIDs.Len(), " items")

	oldItemData := idx.itemDataByID[id]
	var oldParents []*parentData
	if oldItemData != nil {
		oldParents = oldItemData.parents
	}
	newItemData := &itemData{}
	if len(labels) > 0 {
		newItemData.labels = labels
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
	if parent.itemIDs == nil && parent.labels == nil && parent.tags == nil {
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

func (idx *InheritIndex) UpdateParentTags(parentID string, tags []string) {
	parent := idx.getOrCreateParent(parentID)
	parent.tags = tags
	idx.flushChildren(parentID)
}

func (idx *InheritIndex) DeleteParentTags(parentID string) {
	parentData := idx.parentDataByParentID[parentID]
	if parentData == nil {
		return
	}
	parentData.tags = nil
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
		itemData, ok := idx.itemDataByID[itemID]
		if !ok {
			// Item deleted.
			log.Debugf("Flushing delete of item %v", itemID)
			idx.index.DeleteLabels(itemID)
		} else {
			// Item updated/created, re-evaluate labels.
			log.Debugf("Flushing update of item %v", itemID)

			idx.index.UpdateLabels(itemID, itemData)
		}
		return set.RemoveItem
	})
}
