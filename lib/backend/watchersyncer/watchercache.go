// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
)

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
	logger               *logrus.Entry
	client               api.Client
	watch                api.WatchInterface
	resources            map[string]cacheEntry
	oldResources         map[string]cacheEntry
	results              chan<- interface{}
	hasSynced            bool
	resourceType         ResourceType
	currentWatchRevision string
}

var (
	ListRetryInterval = 1000 * time.Millisecond
	WatchPollInterval = 5000 * time.Millisecond
)

// cacheEntry is an entry in our cache.  It groups the a key with the last known
// revision that we processed.  We store the revision so that we can determine
// if an entry has been updated (and therefore whether we need to send an update
// event in the syncer callback).
type cacheEntry struct {
	revision string
	key      model.Key
}

// Create a new watcherCache.
func newWatcherCache(client api.Client, resourceType ResourceType, results chan<- interface{}) *watcherCache {
	return &watcherCache{
		logger:       logrus.WithField("ListRoot", model.ListOptionsToDefaultPathRoot(resourceType.ListInterface)),
		client:       client,
		resourceType: resourceType,
		results:      results,
		resources:    make(map[string]cacheEntry, 0),
	}
}

// run creates the watcher and loops indefinitely reading from the watcher.
func (wc *watcherCache) run() {
	wc.logger.Debug("Watcher cache starting, start initial sync processing")
	wc.resyncAndCreateWatcher()

	wc.logger.Debug("Starting main event processing loop")
	for {
		rc := wc.watch.ResultChan()
		wc.logger.WithField("RC", rc).Debug("Reading event from results channel")
		event, ok := <-rc
		if !ok {
			// If the channel is closed then resync/recreate the watch.
			wc.logger.Info("Watch channel closed by remote - recreate watcher")
			wc.resyncAndCreateWatcher()
			continue
		}

		// Handle the specific event type.
		switch event.Type {
		case api.WatchAdded, api.WatchModified:
			kvp := event.New
			wc.handleWatchListEvent(kvp)
		case api.WatchDeleted:
			// Nil out the value to indicate a delete.
			kvp := event.Old
			kvp.Value = nil
			wc.handleWatchListEvent(kvp)
		case api.WatchError:
			// Handle a WatchError.  First determine if the error type indicates that the
			// watch has closed, and if so we'll need to resync and create a new watcher.
			wc.results <- event.Error
			if e, ok := event.Error.(cerrors.ErrorWatchTerminated); ok {
				wc.logger.Debug("Received watch terminated error - recreate watcher")
				if !e.ClosedByRemote {
					// If the watcher was not closed by remote, reset the currentWatchRevision.  This will
					// trigger a full resync rather than simply trying to watch from the last event
					// revision.
					wc.logger.Debug("Watch was not closed by remote - full resync required")
					wc.currentWatchRevision = ""
				}
				wc.resyncAndCreateWatcher()
			}
		default:
			// Unknown event type - not much we can do other than log.
			wc.logger.WithField("EventType", event.Type).Panic("Unknown event type received from the datastore")
		}
	}
}

// resyncAndCreateWatcher loops performing resync processing until it successfully
// completes a resync and starts a watcher.
func (wc *watcherCache) resyncAndCreateWatcher() {
	// Make sure any previous watcher is stopped.
	wc.logger.Info("Starting watch sync/resync processing")
	if wc.watch != nil {
		wc.logger.Info("Stopping previous watcher")
		wc.watch.Stop()
		wc.watch = nil
	}

	// If we don't have a currentWatchRevision then we need to perform a full resync.
	performFullResync := wc.currentWatchRevision == ""

	for {
		// Start the resync.  This processing loops until we create the watcher.  If the
		// watcher continuously fails then this loop effectively becomes a polling based
		// syncer.
		wc.logger.Debug("Starting main resync loop")

		if performFullResync {
			wc.logger.Debug("Full resync is required")

			// Notify the converter that we are resyncing.
			if wc.resourceType.UpdateProcessor != nil {
				wc.logger.Debug("Trigger converter resync notification")
				wc.resourceType.UpdateProcessor.OnSyncerStarting()
			}

			// Start the sync by Listing the current resources.
			l, err := wc.client.List(context.Background(), wc.resourceType.ListInterface, "")
			if err != nil {
				// Failed to perform the list.  Pause briefly (so we don't tight loop) and retry.
				wc.logger.WithError(err).Info("Failed to perform list of current data during resync")
				time.Sleep(ListRetryInterval)
				continue
			}

			// Move the current resources over to the oldResources
			wc.oldResources = wc.resources
			wc.resources = make(map[string]cacheEntry, 0)

			// Send updates for each of the resources we listed - this will revalidate entries in
			// the oldResources map.
			for _, kvp := range l.KVPairs {
				wc.handleWatchListEvent(kvp)
			}

			// We've listed the current settings.  Complete the sync by notifying the main WatcherSyncer
			// go routine (if we haven't already) and by sending deletes for the old resources that were
			// not acknowledged by the List.  The oldResources will be empty after this call.
			wc.finishResync()

			// Store the current watch revision.  This gets updated on any new add/modified event.
			wc.currentWatchRevision = l.Revision
		}

		// And now start watching from the revision returned by the List, or from a previous watch event
		// (depending on whether we were performing a full resync).
		w, err := wc.client.Watch(context.Background(), wc.resourceType.ListInterface, wc.currentWatchRevision)
		if err != nil {
			// Failed to create the watcher - we'll need to retry.
			if _, ok := err.(cerrors.ErrorOperationNotSupported); ok {
				// Watch is not supported on this resource type, so pause for the watch poll interval.
				// This loop effectively becomes a poll loop for this resource type.
				wc.logger.Debug("Watch operation not supported")
				time.Sleep(WatchPollInterval)
				continue
			}

			// We hit an error creating the Watch.  Trigger a full resync.
			// TODO We should be able to improve this by handling specific error cases with another
			//      watch retry.  This would require some care to ensure the correct errors are captured
			//      for the different datastore drivers.
			wc.logger.WithError(err).WithField("performFullResync", performFullResync).Info("Failed to create watcher")
			performFullResync = true
			continue
		}

		// Store the watcher and exit back to the main event loop.
		wc.logger.Debug("Resync completed, now watching for change events")
		wc.watch = w
		return
	}
}

// finishResync handles processing to finish synchronization.
// If this watcher has never been synced then notify the main watcherSyncer that we've synced.
// We may also need to send deleted messages for old resources that were not validated in the
// resync (i.e. they must have since been deleted).
func (wc *watcherCache) finishResync() {
	// If this is our first synced event then send a synced notification.  The main
	// watcherSyncer code will send a Synced event when it has received synced events from
	// each cache.
	if !wc.hasSynced {
		wc.logger.Info("Sending synced update")
		wc.results <- api.InSync
		wc.hasSynced = true
	}

	// If the watcher failed at any time, we end up recreating a watcher and storing off
	// the current known resources for revalidation.  Now that we have finished the sync,
	// any of the remaining resources that were not accounted for must have been deleted
	// and we need to send deleted events for them.
	numOldResources := len(wc.oldResources)
	if numOldResources > 0 {
		wc.logger.WithField("Num", numOldResources).Debug("Sending resync deletes")
		updates := make([]api.Update, 0, len(wc.oldResources))
		for _, r := range wc.oldResources {
			updates = append(updates, api.Update{
				UpdateType: api.UpdateTypeKVDeleted,
				KVPair: model.KVPair{
					Key: r.key,
				},
			})
		}
		wc.results <- updates
	}
	wc.oldResources = nil
}

// handleWatchListEvent handles a watch event converting it if required and passing to
// handleConvertedWatchEvent to send the appropriate update types.
func (wc *watcherCache) handleWatchListEvent(kvp *model.KVPair) {
	// Track the resource version from this watch/list event.
	wc.currentWatchRevision = kvp.Revision

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

	// If we hit a conversion error, notify the main syncer.
	if err != nil {
		wc.results <- err
	}
}

// handleConvertedWatchEvent handles a converted watch event fanning out
// to the add/mod or delete processing as necessary.
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
	wc.markAsValid(thisKeyString)

	// If the resource is already in our map, then this is a modified event.  Check the
	// revision to see if we actually need to send an update.
	if resource, ok := wc.resources[thisKeyString]; ok {
		if resource.revision == thisRevision {
			// No update to revision, so no event to send.
			wc.logger.WithField("Key", thisKeyString).Debug("Swallowing event update from datastore because entry is same as cached entry")
			return
		}
		// Resource is modified, send an update event and store the latest revision.
		wc.logger.WithField("Key", thisKeyString).Debug("Datastore entry modified, sending syncer update")
		wc.results <- []api.Update{{
			UpdateType: api.UpdateTypeKVUpdated,
			KVPair:     *kvp,
		}}
		resource.revision = thisRevision
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
		revision: thisRevision,
		key:      thisKey,
	}
}

// handleDeletedWatchEvent sends a deleted event and removes the resource key from our cache.
func (wc *watcherCache) handleDeletedUpdate(key model.Key) {
	thisKeyString := key.String()
	wc.markAsValid(thisKeyString)

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

// markAsValid marks a resource that we have just seen as valid, by moving it from the set of
// "oldResources" that were stored during the resync back into the main "resources" set.  Any entries
// remaining in the oldResources map once the current snapshot events have been processed, indicates
// entries that were deleted during the resync - see corresponding code in finishResync().
func (wc *watcherCache) markAsValid(resourceKey string) {
	if wc.oldResources != nil {
		if oldResource, ok := wc.oldResources[resourceKey]; ok {
			wc.logger.WithField("Key", resourceKey).Debug("Marking key as re-processed")
			wc.resources[resourceKey] = oldResource
			delete(wc.oldResources, resourceKey)
		}
	}
}
