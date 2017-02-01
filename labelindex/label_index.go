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

	"github.com/projectcalico/libcalico-go/lib/selector"
)

type Index interface {
	UpdateSelector(id interface{}, sel selector.Selector)
	DeleteSelector(id interface{})
	UpdateLabels(id interface{}, labels map[string]string)
	DeleteLabels(id interface{})
}

type MatchCallback func(selId, labelId interface{})

type linearScanIndex struct {
	// All known labels and selectors.
	labelsById    map[interface{}]map[string]string
	selectorsById map[interface{}]selector.Selector

	// Current matches.
	selIdsByLabelId map[interface{}]map[interface{}]bool
	labelIdsBySelId map[interface{}]map[interface{}]bool

	// Callback functions
	OnMatchStarted MatchCallback
	OnMatchStopped MatchCallback
}

func NewIndex(onMatchStarted, onMatchStopped MatchCallback) Index {
	return &linearScanIndex{
		labelsById:      make(map[interface{}]map[string]string),
		selectorsById:   make(map[interface{}]selector.Selector),
		selIdsByLabelId: make(map[interface{}]map[interface{}]bool),
		labelIdsBySelId: make(map[interface{}]map[interface{}]bool),
		OnMatchStarted:  onMatchStarted,
		OnMatchStopped:  onMatchStopped,
	}
}

func (idx *linearScanIndex) UpdateSelector(id interface{}, sel selector.Selector) {
	log.Infof("Updating selector %v", id)
	if sel == nil {
		panic("Selector should not be nil")
	}
	idx.scanAllLabels(id, sel)
	idx.selectorsById[id] = sel
}

func (idx *linearScanIndex) DeleteSelector(id interface{}) {
	log.Infof("Deleting selector %v", id)
	matchSet := idx.labelIdsBySelId[id]
	matchSlice := make([]interface{}, 0, len(matchSet))
	for labelId, _ := range matchSet {
		matchSlice = append(matchSlice, labelId)
	}
	for _, labelId := range matchSlice {
		idx.deleteMatch(id, labelId)
	}
	delete(idx.selectorsById, id)
}

func (idx *linearScanIndex) UpdateLabels(id interface{}, labels map[string]string) {
	log.Debugf("Updating labels for ID %v", id)
	idx.scanAllSelectors(id, labels)
	idx.labelsById[id] = labels
}

func (idx *linearScanIndex) DeleteLabels(id interface{}) {
	log.Debugf("Deleting labels for %v", id)
	matchSet := idx.selIdsByLabelId[id]
	matchSlice := make([]interface{}, 0, len(matchSet))
	for selId, _ := range matchSet {
		matchSlice = append(matchSlice, selId)
	}
	for _, selId := range matchSlice {
		idx.deleteMatch(selId, id)
	}
	delete(idx.labelsById, id)
}

func (idx *linearScanIndex) scanAllLabels(selId interface{}, sel selector.Selector) {
	log.Debugf("Scanning all (%v) labels against selector %v",
		len(idx.labelsById), selId)
	for labelId, labels := range idx.labelsById {
		idx.updateMatches(selId, sel, labelId, labels)
	}
}

func (idx *linearScanIndex) scanAllSelectors(labelId interface{}, labels map[string]string) {
	log.Debugf("Scanning all (%v) selectors against labels %v",
		len(idx.selectorsById), labelId)
	for selId, sel := range idx.selectorsById {
		idx.updateMatches(selId, sel, labelId, labels)
	}
}

func (idx *linearScanIndex) updateMatches(selId interface{}, sel selector.Selector,
	labelId interface{}, labels map[string]string) {
	nowMatches := sel.Evaluate(labels)
	if nowMatches {
		idx.storeMatch(selId, labelId)
	} else {
		idx.deleteMatch(selId, labelId)
	}
}

func (idx *linearScanIndex) storeMatch(selId, labelId interface{}) {
	previouslyMatched := idx.labelIdsBySelId[selId][labelId]
	if !previouslyMatched {
		log.Debugf("Selector %v now matches labels %v", selId, labelId)
		labelIds, ok := idx.labelIdsBySelId[selId]
		if !ok {
			labelIds = make(map[interface{}]bool)
			idx.labelIdsBySelId[selId] = labelIds
		}
		labelIds[labelId] = true

		selIDs, ok := idx.selIdsByLabelId[labelId]
		if !ok {
			selIDs = make(map[interface{}]bool)
			idx.selIdsByLabelId[labelId] = selIDs
		}
		selIDs[selId] = true

		idx.OnMatchStarted(selId, labelId)
	}
}

func (idx *linearScanIndex) deleteMatch(selId, labelId interface{}) {
	previouslyMatched := idx.labelIdsBySelId[selId][labelId]
	if previouslyMatched {
		log.Debugf("Selector %v no longer matches labels %v",
			selId, labelId)

		delete(idx.labelIdsBySelId[selId], labelId)
		if len(idx.labelIdsBySelId[selId]) == 0 {
			delete(idx.labelIdsBySelId, selId)
		}

		delete(idx.selIdsByLabelId[labelId], selId)
		if len(idx.selIdsByLabelId[labelId]) == 0 {
			delete(idx.selIdsByLabelId, labelId)
		}

		idx.OnMatchStopped(selId, labelId)
	}
}
