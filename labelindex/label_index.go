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

	"github.com/projectcalico/felix/set"
	"github.com/projectcalico/libcalico-go/lib/selector"
	"github.com/projectcalico/libcalico-go/lib/selector/parser"
)

type Index interface {
	UpdateSelector(id interface{}, sel selector.Selector)
	DeleteSelector(id interface{})
	UpdateLabels(id interface{}, labels parser.Labels)
	DeleteLabels(id interface{})
}

type MatchCallback func(selId, labelId interface{})

type linearScanIndex struct {
	// All known labels and selectors.
	labelsById    map[interface{}]parser.Labels
	selectorsById map[interface{}]selector.Selector

	// Current matches.
	selIdsByLabelId map[interface{}]set.Set
	labelIdsBySelId map[interface{}]set.Set

	// Callback functions
	OnMatchStarted MatchCallback
	OnMatchStopped MatchCallback
}

func NewIndex(onMatchStarted, onMatchStopped MatchCallback) *linearScanIndex {
	return &linearScanIndex{
		labelsById:      make(map[interface{}]parser.Labels),
		selectorsById:   make(map[interface{}]selector.Selector),
		selIdsByLabelId: make(map[interface{}]set.Set),
		labelIdsBySelId: make(map[interface{}]set.Set),
		OnMatchStarted:  onMatchStarted,
		OnMatchStopped:  onMatchStopped,
	}
}

func (idx *linearScanIndex) UpdateSelector(id interface{}, sel selector.Selector) {
	log.Infof("Updating selector %v", id)
	if sel == nil {
		log.WithField("id", id).Panic("Selector should not be nil")
	}
	idx.scanAllLabels(id, sel)
	idx.selectorsById[id] = sel
}

func (idx *linearScanIndex) DeleteSelector(id interface{}) {
	log.Infof("Deleting selector %v", id)
	matchSet := idx.labelIdsBySelId[id]
	if matchSet != nil {
		matchSet.Iter(func(labelId interface{}) error {
			// This modifies the set we're iterating over, but that's safe in Go.
			idx.deleteMatch(id, labelId)
			return nil
		})
	}
	delete(idx.selectorsById, id)
}

func (idx *linearScanIndex) UpdateLabels(id interface{}, labels parser.Labels) {
	log.Debugf("Updating labels for ID %v", id)
	idx.scanAllSelectors(id, labels)
	idx.labelsById[id] = labels
}

func (idx *linearScanIndex) DeleteLabels(id interface{}) {
	log.Debugf("Deleting labels for %v", id)
	matchSet := idx.selIdsByLabelId[id]
	if matchSet != nil {
		matchSet.Iter(func(selId interface{}) error {
			// This modifies the set we're iterating over, but that's safe in Go.
			idx.deleteMatch(selId, id)
			return nil
		})
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

func (idx *linearScanIndex) scanAllSelectors(labelId interface{}, labels parser.Labels) {
	log.Debugf("Scanning all (%v) selectors against labels %v",
		len(idx.selectorsById), labelId)
	for selId, sel := range idx.selectorsById {
		idx.updateMatches(selId, sel, labelId, labels)
	}
}

func (idx *linearScanIndex) updateMatches(
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

func (idx *linearScanIndex) storeMatch(selId, labelId interface{}) {
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

func (idx *linearScanIndex) deleteMatch(selId, labelId interface{}) {
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
