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

package labelindex

import (
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/multidict"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/selector"
)

type InheritIndex struct {
	index             Index
	labelsByItemID    map[interface{}]map[string]string
	labelsByParentID  map[interface{}]map[string]string
	tagsByParentID    map[interface{}][]string
	parentIDsByItemID map[interface{}][]string
	itemIDsByParentID multidict.IfaceToIface
	dirtyItemIDs      map[interface{}]bool
}

func NewInheritIndex(onMatchStarted, onMatchStopped MatchCallback) *InheritIndex {
	index := NewIndex(onMatchStarted, onMatchStopped)
	inheritIDx := InheritIndex{
		index:             index,
		labelsByItemID:    make(map[interface{}]map[string]string),
		labelsByParentID:  make(map[interface{}]map[string]string),
		tagsByParentID:    make(map[interface{}][]string),
		parentIDsByItemID: make(map[interface{}][]string),
		itemIDsByParentID: multidict.NewIfaceToIface(),
		dirtyItemIDs:      make(map[interface{}]bool),
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
func (l *InheritIndex) OnUpdate(update api.Update) (filterOut bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		if update.Value != nil {
			log.Debugf("Updating ARC with endpoint %v", key)
			endpoint := update.Value.(*model.WorkloadEndpoint)
			profileIDs := endpoint.ProfileIDs
			l.UpdateLabels(key, endpoint.Labels, profileIDs)
		} else {
			log.Debugf("Deleting endpoint %v from ARC", key)
			l.DeleteLabels(key)
		}
	case model.HostEndpointKey:
		if update.Value != nil {
			// Figure out what's changed and update the cache.
			log.Debugf("Updating ARC for host endpoint %v", key)
			endpoint := update.Value.(*model.HostEndpoint)
			profileIDs := endpoint.ProfileIDs
			l.UpdateLabels(key, endpoint.Labels, profileIDs)
		} else {
			log.Debugf("Deleting host endpoint %v from ARC", key)
			l.DeleteLabels(key)
		}
	case model.ProfileLabelsKey:
		if update.Value != nil {
			log.Debugf("Updating ARC for profile labels %v", key)
			labels := update.Value.(map[string]string)
			l.UpdateParentLabels(key.Name, labels)
		} else {
			log.Debugf("Removing profile labels %v from ARC", key)
			l.DeleteParentLabels(key.Name)
		}
	case model.ProfileTagsKey:
		if update.Value != nil {
			log.Debugf("Updating ARC for profile tags %v", key)
			labels := update.Value.([]string)
			l.UpdateParentTags(key.Name, labels)
		} else {
			log.Debugf("Removing profile tags %v from ARC", key)
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

func (idx *InheritIndex) UpdateLabels(id interface{}, labels map[string]string, parents []string) {
	log.Debug("Inherit index updating labels for ", id)
	log.Debug("Num dirty items ", len(idx.dirtyItemIDs), " items")
	idx.labelsByItemID[id] = labels
	idx.onItemParentsUpdate(id, parents)
	idx.dirtyItemIDs[id] = true
	idx.flushUpdates()
	log.Debug("Num ending dirty items ", len(idx.dirtyItemIDs), " items")
}

func (idx *InheritIndex) DeleteLabels(id interface{}) {
	log.Debug("Inherit index deleting labels for ", id)
	delete(idx.labelsByItemID, id)
	idx.onItemParentsUpdate(id, []string{})
	idx.dirtyItemIDs[id] = true
	idx.flushUpdates()
}

func (idx *InheritIndex) onItemParentsUpdate(id interface{}, parents []string) {
	oldParents := idx.parentIDsByItemID[id]
	for _, parent := range oldParents {
		idx.itemIDsByParentID.Discard(parent, id)
	}
	if len(parents) > 0 {
		idx.parentIDsByItemID[id] = parents
	} else {
		delete(idx.parentIDsByItemID, id)
	}
	for _, parent := range parents {
		idx.itemIDsByParentID.Put(parent, id)
	}
}

func (idx *InheritIndex) UpdateParentLabels(parentID string, labels map[string]string) {
	idx.labelsByParentID[parentID] = labels
	idx.flushChildren(parentID)
}

func (idx *InheritIndex) DeleteParentLabels(parentID string) {
	delete(idx.labelsByParentID, parentID)
	idx.flushChildren(parentID)
}

func (idx *InheritIndex) UpdateParentTags(parentID string, Tags []string) {
	idx.tagsByParentID[parentID] = Tags
	idx.flushChildren(parentID)
}

func (idx *InheritIndex) DeleteParentTags(parentID string) {
	delete(idx.tagsByParentID, parentID)
	idx.flushChildren(parentID)
}

func (idx *InheritIndex) flushChildren(parentID interface{}) {
	idx.itemIDsByParentID.Iter(parentID, func(itemID interface{}) {
		log.Debug("Marking child ", itemID, " dirty")
		idx.dirtyItemIDs[itemID] = true
	})
	idx.flushUpdates()
}

func (idx *InheritIndex) flushUpdates() {
	for itemID := range idx.dirtyItemIDs {
		log.Debugf("Flushing %#v", itemID)
		itemLabels, ok := idx.labelsByItemID[itemID]
		if !ok {
			// Item deleted.
			log.Debugf("Flushing delete of item %v", itemID)
			idx.index.DeleteLabels(itemID)
		} else {
			// Item updated/created, re-evaluate labels.
			log.Debugf("Flushing update of item %v", itemID)
			combinedLabels := make(map[string]string)
			parentIDs := idx.parentIDsByItemID[itemID]
			for _, parentID := range parentIDs {
				parentTags := idx.tagsByParentID[parentID]
				for _, tag := range parentTags {
					_, ok := combinedLabels[tag]
					_, ok2 := itemLabels[tag]
					if !ok && !ok2 {
						combinedLabels[tag] = ""
					}
				}
				parentLabels := idx.labelsByParentID[parentID]
				for k, v := range parentLabels {
					if _, ok := itemLabels[k]; !ok {
						combinedLabels[k] = v
					}
				}
			}
			if len(combinedLabels) > 0 {
				for k, v := range itemLabels {
					combinedLabels[k] = v
				}
			} else {
				combinedLabels = itemLabels
			}
			idx.index.UpdateLabels(itemID, combinedLabels)
		}
	}
	idx.dirtyItemIDs = make(map[interface{}]bool)
}
