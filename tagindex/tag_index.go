// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
//
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

package tagindex

import (
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

// A TagIndex dynamically calculates the matching tags for a set of endpoints.
// It generates events when endpoints start and stop matching "active" tags.
// Tags are marked active by calling the SetTagActive/SetTagInactive
// methods.
type TagIndex struct {
	profileIDToTags         map[string][]string
	profileIDToEndpointKey  map[string]map[model.Key]bool
	endpointKeyToProfileIDs *EndpointKeyToProfileIDMap
	matches                 map[indexKey]map[string]bool
	activeTags              map[string]bool

	onMatchStarted MatchCallback
	onMatchStopped MatchCallback
}

type indexKey struct {
	tag string
	key model.Key
}

type MatchCallback func(key model.Key, tagID string)

func NewIndex(onMatchStarted, onMatchStopped MatchCallback) *TagIndex {
	idx := &TagIndex{
		profileIDToTags:         make(map[string][]string),
		profileIDToEndpointKey:  make(map[string]map[model.Key]bool),
		endpointKeyToProfileIDs: NewEndpointKeyToProfileIDMap(),
		matches:                 make(map[indexKey]map[string]bool),
		activeTags:              make(map[string]bool),

		onMatchStarted: onMatchStarted,
		onMatchStopped: onMatchStopped,
	}
	return idx
}

func (idx *TagIndex) RegisterWith(dispatcher *dispatcher.Dispatcher) {
	dispatcher.Register(model.WorkloadEndpointKey{}, idx.OnUpdate)
	dispatcher.Register(model.HostEndpointKey{}, idx.OnUpdate)
	dispatcher.Register(model.ProfileTagsKey{}, idx.OnUpdate)
}

// SetTagActive marks the given tag as active if it isn't already.
// If the tag becomes active and it matches endpoints, synchronously invokes
// the match-started callback for each matching endpoint.
func (idx *TagIndex) SetTagActive(tag string) {
	if idx.activeTags[tag] {
		return
	}
	logCxt := log.WithField("tag", tag)
	logCxt.Info("Tag active, scanning endpoints")
	// Generate events for all endpoints.
	idx.activeTags[tag] = true
	for key := range idx.matches {
		if key.tag == tag {
			logCxt.WithField("match", key).Debug(
				"Found match, triggering onMatchStarted")
			idx.onMatchStarted(key.key, tag)
		}
	}
}

// SetTagInactive marks the given tag as inactive if it isn't already.
// If the tag becomes inactive and it matches endpoints, synchronously invokes
// the match-stopped callback for each matching endpoint.
func (idx *TagIndex) SetTagInactive(tag string) {
	if !idx.activeTags[tag] {
		return
	}
	logCxt := log.WithField("tag", tag)
	logCxt.Info("Tag no longer active, scanning endpoints")
	delete(idx.activeTags, tag)
	for key := range idx.matches {
		if key.tag == tag {
			logCxt.WithField("match", key).Debug(
				"Found match, triggering onMatchStopped")
			idx.onMatchStopped(key.key, tag)
		}
	}
}

// OnUpdate is called when a datamodel update is received.  It updates the
// index and fires the match-started/stopped callbacks as appropriate.
func (idx *TagIndex) OnUpdate(update api.Update) (filterOut bool) {
	switch key := update.Key.(type) {
	case model.ProfileTagsKey:
		if update.Value != nil {
			tags := update.Value.([]string)
			idx.updateProfileTags(key.Name, tags)
		} else {
			idx.updateProfileTags(key.Name, []string{})
		}
	case model.HostEndpointKey:
		if update.Value != nil {
			ep := update.Value.(*model.HostEndpoint)
			idx.updateEndpoint(key, ep.ProfileIDs)
		} else {
			idx.updateEndpoint(key, []string{})
		}
	case model.WorkloadEndpointKey:
		if update.Value != nil {
			ep := update.Value.(*model.WorkloadEndpoint)
			idx.updateEndpoint(key, ep.ProfileIDs)
		} else {
			idx.updateEndpoint(key, []string{})
		}
	}
	return
}

func (idx *TagIndex) updateProfileTags(profileID string, tags []string) {
	log.Debugf("Updating tags for profile %v to %v", profileID, tags)
	oldTags := idx.profileIDToTags[profileID]
	// Calculate the added and removed tags.  Initialise removedTags with
	// a copy of the old tags, then remove any still-present tags.
	removedTags := make(map[string]bool)
	for _, tag := range oldTags {
		removedTags[tag] = true
	}
	addedTags := make(map[string]bool)
	for _, tag := range tags {
		if removedTags[tag] {
			delete(removedTags, tag)
		} else {
			addedTags[tag] = true
		}
	}

	// Find all the endpoints with this profile and update their
	// memberships.
	for epKey, _ := range idx.profileIDToEndpointKey[profileID] {
		for tag, _ := range addedTags {
			idx.addToIndex(epKey, tag, profileID)
		}
		for tag, _ := range removedTags {
			idx.removeFromIndex(epKey, tag, profileID)
		}
	}

	if len(tags) > 0 {
		idx.profileIDToTags[profileID] = tags
	} else {
		delete(idx.profileIDToTags, profileID)
	}
}

func (idx *TagIndex) updateEndpoint(key model.Key, profileIDs []string) {
	log.Debugf("Updating endpoint %v, profile IDs: %v", key, profileIDs)
	// Figure out what's changed and update the cache.
	removedIDs, addedIDs := idx.endpointKeyToProfileIDs.Update(key, profileIDs)

	// Add the new IDs into the main index first so that we don't flap
	// when a profile is renamed.
	for id := range addedIDs {
		// Update reverse index, which we use when resolving profile
		// updates.
		log.Debugf("Profile ID added: %v", id)
		revIdx, ok := idx.profileIDToEndpointKey[id]
		if !ok {
			revIdx = make(map[model.Key]bool)
			idx.profileIDToEndpointKey[id] = revIdx
		}
		revIdx[key] = true

		// Update the main match index, triggering callbacks for
		// new matches.
		for _, tag := range idx.profileIDToTags[id] {
			idx.addToIndex(key, tag, id)
		}
	}
	// Now process removed profile IDs.
	for id := range removedIDs {
		// Clean up the reverse index that we use when doing profile
		// updates.
		log.Debugf("Profile ID removed: %v", id)
		revIdx := idx.profileIDToEndpointKey[id]
		delete(revIdx, key)
		if len(revIdx) == 0 {
			log.Debugf("%v no longer has any endpoints", id)
			delete(idx.profileIDToEndpointKey, id)
		}

		// Update the main match index, triggering callbacks for
		// stopped matches.
		for _, tag := range idx.profileIDToTags[id] {
			idx.removeFromIndex(key, tag, id)
		}
	}
}

func (idx *TagIndex) addToIndex(epKey model.Key, tag string, profID string) {
	logCxt := log.WithFields(log.Fields{
		"epKey":  epKey,
		"tag":    tag,
		"profID": profID,
	})
	logCxt.Debug("Adding match to index.")
	idxKey := indexKey{tag: tag, key: epKey}
	matchingProfIDs, ok := idx.matches[idxKey]
	if !ok {
		logCxt.Debug("Endpoint newly matches tag")
		matchingProfIDs = make(map[string]bool)
		idx.matches[idxKey] = matchingProfIDs
		if idx.activeTags[tag] {
			logCxt.Debug("Tag active, triggering onMatchStarted")
			idx.onMatchStarted(epKey, tag)
		}
	}
	matchingProfIDs[profID] = true
}

func (idx *TagIndex) removeFromIndex(epKey model.Key, tag string, profID string) {
	logCxt := log.WithFields(log.Fields{
		"epKey":  epKey,
		"tag":    tag,
		"profID": profID,
	})
	logCxt.Debugf("Removing match from index")
	idxKey := indexKey{tag: tag, key: epKey}
	matchingProfIDs := idx.matches[idxKey]
	delete(matchingProfIDs, profID)
	if len(matchingProfIDs) == 0 {
		// There's no-longer a profile keeping this tag alive.
		logCxt.Debug("Endpoint no longer matches tag")
		delete(idx.matches, idxKey)
		if idx.activeTags[tag] {
			logCxt.Debug("Tag active, triggering onMatchStopped")
			idx.onMatchStopped(epKey, tag)
		}
	}
}

type EndpointKeyToProfileIDMap struct {
	endpointKeyToProfileIDs map[model.Key][]string
}

func NewEndpointKeyToProfileIDMap() *EndpointKeyToProfileIDMap {
	return &EndpointKeyToProfileIDMap{
		endpointKeyToProfileIDs: make(map[model.Key][]string),
	}
}

func (idx EndpointKeyToProfileIDMap) Update(key model.Key, profileIDs []string) (
	removedIDs, addedIDs map[string]bool) {
	oldIDs := idx.endpointKeyToProfileIDs[key]
	removedIDs = make(map[string]bool)
	for _, id := range oldIDs {
		removedIDs[id] = true
	}
	addedIDs = make(map[string]bool)
	for _, id := range profileIDs {
		if removedIDs[id] {
			delete(removedIDs, id)
		} else {
			addedIDs[id] = true
		}
	}

	// Store off the update in our cache.
	if len(profileIDs) > 0 {
		idx.endpointKeyToProfileIDs[key] = profileIDs
	} else {
		// No profiles is equivalent to deletion so we may as well
		// clean up completely.
		delete(idx.endpointKeyToProfileIDs, key)
	}

	return removedIDs, addedIDs
}
