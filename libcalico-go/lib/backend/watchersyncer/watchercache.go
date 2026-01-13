// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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

package watchersyncer

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Compile-time check that watcherCache implements api.EventHandler interface
var _ api.EventHandler = (*watcherCache)(nil)

// The watcherCache provides watcher/syncer support for a single key type in the
// backend.  These results are sent to the main WatcherSyncer on a buffered "results"
// channel.  To ensure the order of events is received correctly by the main WatcherSyncer,
// we send all notification types in this channel.  Note that because of this the results
// channel is untyped - however the watcherSyncer only expects one of the following
// types:
// -  An error
// -  An api.Update
// -  A api.SyncStatus (only for the very first InSync notification)
type watcherCache struct {
	logger                 *logrus.Entry
	client                 api.Client
	resources              map[string]cacheEntry
	resyncEpoch            uint64
	lastHandledResyncEpoch uint64
	results                chan<- interface{}
	hasSynced              bool
	resourceType           ResourceType
}

// cacheEntry is an entry in our cache.  It groups the a key with the last known
// revision that we processed.  We store the revision so that we can determine
// if an entry has been updated (and therefore whether we need to send an update
// event in the syncer callback).
type cacheEntry struct {
	revision    string
	key         model.Key
	resyncEpoch uint64
}

// Create a new watcherCache.
func newWatcherCache(client api.Client, resourceType ResourceType, results chan<- interface{}) *watcherCache {
	return &watcherCache{
		logger:       logrus.WithField("ListRoot", listRootForLog(resourceType.ListInterface)),
		client:       client,
		resourceType: resourceType,
		results:      results,
		resources:    make(map[string]cacheEntry),
	}
}

func listRootForLog(listInterface model.ListInterface) string {
	root := model.ListOptionsToDefaultPathRoot(listInterface)
	root = strings.Replace(root, "/calico/resources/v3/projectcalico.org/", ".../v3/pc.org/", 1)
	root = strings.Replace(root, "/calico/", ".../", 1)
	return root
}

// run creates the watcher and loops indefinitely reading from the watcher.
func (wc *watcherCache) run(ctx context.Context) {
	wc.logger.Debug("Watcher cache starting...")

	// On shutdown, send deletions for all the objects we're tracking.
	defer wc.sendDeletionsForAllResources()

	// Run ListAndWatch - this will block until context is cancelled or an error occurs
	// watcherCache directly implements the EventHandler interface
	if err := wc.client.ListAndWatch(ctx, wc.resourceType.ListInterface, wc); err != nil {
		wc.logger.WithError(err).Error("ListAndWatch failed")
	}
}

// OnResyncStarted implements api.EventHandler interface.
// It is called when a resync operation is about to begin.
func (wc *watcherCache) OnResyncStarted() {
	wc.logger.Debug("Resync started notification received")
	// Notify the converter that we are resyncing.
	if wc.resourceType.UpdateProcessor != nil {
		wc.logger.Debug("Trigger converter resync notification")
		wc.resourceType.UpdateProcessor.OnSyncerStarting()
	}
	if len(wc.resources) > 0 {
		// Our cache isn't empty, so we need to use the resync epoch to detect
		// deletes during the resync.
		wc.resyncEpoch++
	} else {
		// Cache empty, reset the resync epoch so we can skip the post-resync scan.
		wc.resyncEpoch = 0
		wc.lastHandledResyncEpoch = 0
	}
}

// OnAdd handles add events from ListAndWatch
func (wc *watcherCache) OnAdd(kvp *model.KVPair) {
	wc.handleWatchListEvent(kvp)
}

// OnUpdate handles update events from ListAndWatch
func (wc *watcherCache) OnUpdate(kvp *model.KVPair) {
	wc.handleWatchListEvent(kvp)
}

// OnDelete handles delete events from ListAndWatch
func (wc *watcherCache) OnDelete(kvp *model.KVPair) {
	kvp.Value = nil
	wc.handleWatchListEvent(kvp)
}

// OnSync handles processing to finish synchronization.
// If this watcher has never been synced then notify the main watcherSyncer that we've synced.
// We may also need to send deleted messages for old resources that were not validated in the
// resync (i.e. they must have since been deleted).
func (wc *watcherCache) OnSync() {
	if wc.resyncEpoch != wc.lastHandledResyncEpoch {
		// We just completed a resync with a non-empty cache, we need to scan
		// the cache to look for resources that were deleted during the resync.
		updates := make([]api.Update, 0)
		for k, r := range wc.resources {
			if r.resyncEpoch == wc.resyncEpoch {
				// This resource was validated during the resync.
				continue
			}
			updates = append(updates, api.Update{
				UpdateType: api.UpdateTypeKVDeleted,
				KVPair: model.KVPair{
					Key: r.key,
				},
			})
			delete(wc.resources, k)
		}
		wc.logger.WithField("Num", len(updates)).Debug("Sending resync deletes")
		wc.results <- updates
		wc.lastHandledResyncEpoch = wc.resyncEpoch
	}

	// If we haven't already sent an InSync event then send a synced notification.  The watcherSyncer will send a Synced
	// event when it has received synced events from each cache. Once in-sync the cache remains in-sync.
	if !wc.hasSynced {
		wc.logger.Info("Sending synced update")
		wc.results <- api.InSync
		wc.hasSynced = true
	}
}

// OnError handles error events from ListAndWatch.
// It forwards the error to the results channel for the main watcherSyncer to handle.
func (wc *watcherCache) OnError(err error) {
	wc.logger.WithError(err).Warn("Received error from ListAndWatch")
	wc.results <- err
}

// handleWatchListEvent handles a watch event converting it if required and passing to
// handleConvertedWatchEvent to send the appropriate update types.
func (wc *watcherCache) handleWatchListEvent(kvp *model.KVPair) {
	if wc.resourceType.UpdateProcessor == nil {
		// No update processor - handle immediately.
		wc.handleConvertedWatchEvent(kvp)
		return
	}

	// We have an update processor so use that to convert the event data.
	kvps, err := wc.resourceType.UpdateProcessor.Process(kvp)
	for _, kvp := range kvps {
		wc.handleConvertedWatchEvent(kvp)
	}

	// If we hit a conversion error, log the error and notify the main syncer.
	if err != nil {
		wc.results <- err
	}
}

// handleWatchBookmark handles a bookmark event from the API server, these
// update the revision that we should be watching from without sending
// a KVP.  This prevents datastore compactions from invalidating our watches.
func (wc *watcherCache) handleConvertedWatchEvent(kvp *model.KVPair) {
	if kvp.Value == nil {
		wc.handleDeletedUpdate(kvp.Key)
	} else {
		wc.handleAddedOrModifiedUpdate(kvp)
	}
}

// handleAddedOrModifiedUpdate handles a single Added or Modified update request.
// Whether we send an Added or Modified depends on whether we have already sent
// an added notification for this resource.
func (wc *watcherCache) handleAddedOrModifiedUpdate(kvp *model.KVPair) {
	thisKey := kvp.Key
	thisKeyString := thisKey.String()
	thisRevision := kvp.Revision

	// If the resource is already in our map, then this is a modified event.  Check the
	// revision to see if we actually need to send an update.
	send := true

	if resource, ok := wc.resources[thisKeyString]; ok {
		if resource.revision == thisRevision {
			// No update to revision, so no event to send.
			wc.logger.WithField("Key", thisKeyString).Debug("Swallowing event update from datastore because entry is same as cached entry")
			send = false
		} else {
			// Resource is modified, send an update event and store the latest revision.
			wc.logger.WithField("Key", thisKeyString).Debug("Datastore entry modified, sending syncer update")
		}
		if send {
			wc.results <- []api.Update{{
				UpdateType: api.UpdateTypeKVUpdated,
				KVPair:     *kvp,
			}}
		}
		resource.revision = thisRevision
		resource.resyncEpoch = wc.resyncEpoch
		wc.resources[thisKeyString] = resource
		return
	}

	// The resource has not been seen before, so send a new event, and store the
	// current revision.
	wc.logger.WithField("Key", thisKeyString).Debug("Cache entry added, sending syncer update")
	wc.results <- []api.Update{{
		UpdateType: api.UpdateTypeKVNew,
		KVPair:     *kvp,
	}}
	wc.resources[thisKeyString] = cacheEntry{
		revision:    thisRevision,
		key:         thisKey,
		resyncEpoch: wc.resyncEpoch,
	}
}

// handleDeletedWatchEvent sends a deleted event and removes the resource key from our cache.
func (wc *watcherCache) handleDeletedUpdate(key model.Key) {
	thisKeyString := key.String()

	// If we have seen an added event for this key then send a deleted event and remove
	// from the cache.
	if _, ok := wc.resources[thisKeyString]; ok {
		wc.logger.WithField("Key", thisKeyString).Debug("Datastore entry deleted, sending syncer update")
		wc.results <- []api.Update{{
			UpdateType: api.UpdateTypeKVDeleted,
			KVPair: model.KVPair{
				Key: key,
			},
		}}
		delete(wc.resources, thisKeyString)
	}
}

func (wc *watcherCache) sendDeletionsForAllResources() {
	for _, value := range wc.resources {
		wc.results <- []api.Update{{
			UpdateType: api.UpdateTypeKVDeleted,
			KVPair: model.KVPair{
				Key: value.key,
			},
		}}
	}
	clear(wc.resources)
}
