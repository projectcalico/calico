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
	"errors"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	utilnet "k8s.io/apimachinery/pkg/util/net"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
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
	logger                 *logrus.Entry
	client                 api.Client
	watch                  api.WatchInterface
	resources              map[string]cacheEntry
	oldResources           map[string]cacheEntry
	results                chan<- interface{}
	hasSynced              bool
	resourceType           ResourceType
	currentWatchRevision   string
	errorCountAtCurrentRev int
	resyncBlockedUntil     time.Time
	lastSuccessfulConnTime time.Time
	watchRetryTimeout      time.Duration
}

const (
	MaxErrorsPerRevision = 5
)

var (
	MinResyncInterval        = 500 * time.Millisecond
	ListRetryInterval        = 1000 * time.Millisecond
	WatchPollInterval        = 5000 * time.Millisecond
	DefaultWatchRetryTimeout = 600 * time.Second
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
func newWatcherCache(client api.Client, resourceType ResourceType, results chan<- interface{}, watchTimeout time.Duration) *watcherCache {
	return &watcherCache{
		logger:               logrus.WithField("ListRoot", listRootForLog(resourceType.ListInterface)),
		client:               client,
		resourceType:         resourceType,
		results:              results,
		resources:            make(map[string]cacheEntry, 0),
		currentWatchRevision: "0",
		resyncBlockedUntil:   time.Now(),
		watchRetryTimeout:    watchTimeout,
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

	// Main loop, repeatedly resync with the store and then watch for changes
	// until our watch fails.
	for ctx.Err() == nil {
		wc.resyncAndLoopReadingFromWatcher(ctx)
	}
}

func (wc *watcherCache) resyncAndLoopReadingFromWatcher(ctx context.Context) {
	defer wc.cleanExistingWatcher()
	wc.maybeResyncAndCreateWatcher(ctx)
	if ctx.Err() != nil {
		// maybeResyncAndCreateWatcher may have returned early with no watcher,
		// in which case it's not safe to call loopReadingFromWatcher.
		return
	}
	wc.loopReadingFromWatcher(ctx)
}

func (wc *watcherCache) loopReadingFromWatcher(ctx context.Context) {
	eventLogger := wc.logger.WithField("event", nil)

	for {
		select {
		case <-ctx.Done():
			wc.logger.Debug("Context is done. Returning")
			return
		case event, ok := <-wc.watch.ResultChan():
			if !ok {
				// If the channel is closed then resync/recreate the watch.
				wc.logger.Debug("Watch channel closed by remote - recreate watcher")
				return
			}

			// Re-use this log event so that we don't allocate every time.
			eventLogger.Data["event"] = event
			eventLogger.Debug("Got event from results channel")

			// Handle the specific event type.
			switch event.Type {
			case api.WatchAdded, api.WatchModified:
				kvp := event.New
				wc.handleWatchListEvent(kvp)
				wc.lastSuccessfulConnTime = time.Now()
			case api.WatchDeleted:
				// Nil out the value to indicate a delete.
				kvp := event.Old
				if kvp == nil {
					// Bug, we're about to panic when we hit the nil pointer, log something useful.
					eventLogger.Panic("Deletion event without old value")
				}
				kvp.Value = nil
				wc.handleWatchListEvent(kvp)
				wc.lastSuccessfulConnTime = time.Now()
			case api.WatchBookmark:
				wc.handleWatchBookmark(event)
				wc.lastSuccessfulConnTime = time.Now()
			case api.WatchError:
				if kerrors.IsResourceExpired(event.Error) {
					// Our current watch revision is too old.  Even with watch bookmarks, we hit this path after the
					// API server restarts (and presumably does an immediate compaction).
					eventLogger.Info("Watch has expired, triggering full resync.")
					wc.resetWatchRevisionForFullResync()
					// "Layer 7" error so the connection is good.
					wc.lastSuccessfulConnTime = time.Now()
				} else {
					// Unknown error, default is to just try restarting the watch on assumption that it's
					// a connectivity issue.  Note that, if the error recurs when recreating the watch, we will
					// check for various expected connectivity failure conditions and handle them there.
					wc.errorCountAtCurrentRev++
					if wc.errorCountAtCurrentRev >= MaxErrorsPerRevision {
						// Too many errors at the current revision, trigger a full resync.
						eventLogger.Warn("Watch repeatedly failed without making progress, triggering full resync")
						wc.resetWatchRevisionForFullResync()
					} else {
						eventLogger.Info("Watch of resource finished. Attempting to restart it...")
					}
				}
				return
			default:
				// Unknown event type - not much we can do other than log.
				eventLogger.Errorf("Unknown event type received from the datastore")
			}
		}
	}
}

// maybeResyncAndCreateWatcher loops performing resync processing until it successfully
// completes a resync and starts a watcher.
func (wc *watcherCache) maybeResyncAndCreateWatcher(ctx context.Context) {
	// The passed in context allows a resync to be stopped mid-resync. The resync should be stopped as quickly as
	// possible, but there should be usable data available in wc.resources so that delete events can be sent.
	// The strategy is to
	// - cancel any long running functions calls made from here, i.e. pass ctx to the client.list() calls
	//    - but if it finishes, then ensure that the listing gets processed.
	// - cancel any sleeps if the context is cancelled

	// Make sure any previous watcher is stopped.
	wc.logger.Debug("Starting watch sync/resync processing")
	wc.cleanExistingWatcher()

	// If we don't have a currentWatchRevision then we need to perform a full resync.
	var performFullResync bool
	for {
		start := time.Now()
		select {
		case <-ctx.Done():
			wc.logger.Debug("Context is done. Returning")
			return
		case <-wc.resyncThrottleC():
			// Start the resync.  This processing loops until we create the watcher.  If the
			// watcher continuously fails then this loop effectively becomes a polling based
			// syncer.
			wc.logger.Debugf("Starting main resync loop after delay %v", time.Since(start))
		}

		// Avoid tight loop in unexpected failure scenarios.  For example, if creating the watch succeeds but the
		// watch immediately ends.
		wc.resyncBlockedUntil = time.Now().Add(MinResyncInterval)

		performFullResync = performFullResync || wc.currentWatchRevision == "0"
		if performFullResync {
			wc.logger.Info("Full resync is required")

			// Notify the converter that we are resyncing.
			if wc.resourceType.UpdateProcessor != nil {
				wc.logger.Debug("Trigger converter resync notification")
				wc.resourceType.UpdateProcessor.OnSyncerStarting()
			}

			// Start the sync by Listing the current resources. Start from the current watch revision, which will
			// be 0 at start of day or the latest received revision.
			l, err := wc.client.List(ctx, wc.resourceType.ListInterface, wc.currentWatchRevision)
			if err != nil {
				// Failed to perform the list.  Pause briefly (so we don't tight loop) and retry.
				wc.logger.WithError(err).Info("Failed to perform list of current data during resync")
				if kerrors.IsResourceExpired(err) || isTooLargeResourceVersionError(err) {
					// Our current watch revision is out of sync. Start again without a revision.
					wc.logger.Info("Resource too old/new error from server, clearing cached watch revision.")
					wc.resetWatchRevisionForFullResync()
					// Error is a "layer 7" error; so connection is good!
					wc.lastSuccessfulConnTime = time.Now()
				} else if time.Since(wc.lastSuccessfulConnTime) > wc.watchRetryTimeout {
					// Need to send back an error here for handling. Only callbacks with connection failure handling should actually kick off anything.
					wc.logger.Warn("Connection to datastore has failed - signaling error to client.")
					wc.results <- errorSyncBackendError{
						Err: err,
					}

					if wc.resourceType.SendDeletesOnConnFail {
						// Unable to List, and we need to send deletes on connection failure. Send them now.
						// Note: We do not need to check if the context is done since we will send deletes during exit
						// processing anyway.
						wc.logger.Info("connection failed, sending deletion events for all resources.")
						wc.sendDeletionsForAllResources()
					}
				}

				wc.resyncBlockedUntil = time.Now().Add(ListRetryInterval)
				continue
			}
			wc.lastSuccessfulConnTime = time.Now()

			// Once this point is reached, it's important not to drop out if the context is cancelled.
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
			wc.logger.Logger.WithField("revision", l.Revision).Debug("List completed.")
			if l.Revision == "" || l.Revision == "0" {
				if len(l.KVPairs) == 0 {
					// Got a bad revision but there are no items.  This may mean that the datastore
					// returns an unhelpful "not found" error instead of an empty list.  Revert to a
					// poll until some items show up.
					wc.logger.Info("List returned no items and an empty/zero revision, reverting to poll.")
					wc.currentWatchRevision = "0"
					performFullResync = true
					wc.resyncBlockedUntil = time.Now().Add(WatchPollInterval)
					continue
				}
				wc.logger.Panic("BUG: List returned items with empty/zero revision.  Watch would be inconsistent.")
			}
			wc.currentWatchRevision = l.Revision
			wc.errorCountAtCurrentRev = 0

			// Mark the resync as complete.
			performFullResync = false
		}

		// And now start watching from the revision returned by the List, or from a previous watch event
		// (depending on whether we were performing a full resync).
		wc.logger.WithField("revision", wc.currentWatchRevision).Debug("Starting watch from revision")
		w, err := wc.client.Watch(ctx, wc.resourceType.ListInterface, api.WatchOptions{
			Revision:            wc.currentWatchRevision,
			AllowWatchBookmarks: true,
		})
		if err != nil {
			if kerrors.IsResourceExpired(err) || kerrors.IsGone(err) || isTooLargeResourceVersionError(err) {
				// Our current watch revision is too old (or too new!). Start again
				// without a revision. Condition cribbed from client-go's reflector.
				wc.logger.Info("Watch has expired, queueing full resync.")
				wc.resetWatchRevisionForFullResync()
				// Error is a "layer 7" error; so connection is good!
				wc.lastSuccessfulConnTime = time.Now()
				continue
			}

			if utilnet.IsConnectionRefused(err) || kerrors.IsTooManyRequests(err) {
				// Connection-related error, we can just retry without resetting
				// the watch. Condition cribbed from client-go's reflector
				if time.Since(wc.lastSuccessfulConnTime) > wc.watchRetryTimeout {
					// Too long since we were connected, and we may need to signal an error to the client.
					// The signalling is done as part of the resync machinery so trigger a resync now.
					wc.logger.WithError(err).Warn("Timed out waiting for connection to be restored, forcing a resync.")
					wc.resetWatchRevisionForFullResync()
				}
				wc.logger.WithError(err).Warn("API server refused connection, will retry.")
				continue
			}

			var errNotSupp cerrors.ErrorOperationNotSupported
			var errNotExist cerrors.ErrorResourceDoesNotExist
			if errors.As(err, &errNotSupp) ||
				errors.As(err, &errNotExist) {
				// Watch is not supported on this resource type, either because the type fundamentally
				// doesn't support it, or because there are no resources to watch yet (and Kubernetes won't
				// let us watch if there are no resources yet). Pause for the watch poll interval.
				// This loop effectively becomes a poll loop for this resource type.
				wc.logger.Debug("Watch operation not supported; reverting to poll.")
				wc.resyncBlockedUntil = time.Now().Add(WatchPollInterval)

				// Make sure we force a re-list of the resource even if the watch previously succeeded
				// but now cannot.
				performFullResync = true
				continue
			}

			// None of our expected errors, retry a few times before we give up and try a full resync.
			wc.errorCountAtCurrentRev++
			wc.logger.WithError(err).WithField("performFullResync", performFullResync).WithField("errorsWithoutProgress", wc.errorCountAtCurrentRev).Warn(
				"Failed to create watcher; will retry.")
			if wc.errorCountAtCurrentRev >= MaxErrorsPerRevision {
				// Hitting repeated errors, try a full resync next time.
				performFullResync = true
			}
			continue
		}

		// Store the watcher and exit back to the main event loop.
		wc.logger.Debug("Resync completed, now watching for change events")
		wc.watch = w
		return
	}
}

func (wc *watcherCache) resetWatchRevisionForFullResync() {
	wc.currentWatchRevision = "0"
	wc.errorCountAtCurrentRev = 0
}

var closedTimeC = make(chan time.Time)

func init() {
	close(closedTimeC)
}

func (wc *watcherCache) resyncThrottleC() <-chan time.Time {
	blockFor := time.Until(wc.resyncBlockedUntil)
	var blockC <-chan time.Time
	if blockFor > 0 {
		wc.logger.WithField("delay", blockFor).Debug("Sleeping before next resync")
		blockC = time.After(blockFor)
	} else {
		blockC = closedTimeC // Triggers immediately.
	}
	return blockC
}

func (wc *watcherCache) cleanExistingWatcher() {
	if wc.watch != nil {
		wc.logger.Debug("Stopping previous watcher")
		wc.watch.Stop()
		wc.watch = nil
	}
}

// finishResync handles processing to finish synchronization.
// If this watcher has never been synced then notify the main watcherSyncer that we've synced.
// We may also need to send deleted messages for old resources that were not validated in the
// resync (i.e. they must have since been deleted).
func (wc *watcherCache) finishResync() {
	// If we haven't already sent an InSync event then send a synced notification.  The watcherSyncer will send a Synced
	// event when it has received synced events from each cache. Once in-sync the cache remains in-sync.
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
	wc.errorCountAtCurrentRev = 0

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
func (wc *watcherCache) handleWatchBookmark(event api.WatchEvent) {
	wc.logger.WithField("newRevision", event.New.Revision).Debug("Watch bookmark received")
	wc.currentWatchRevision = event.New.Revision
	wc.errorCountAtCurrentRev = 0
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

	// Just signaled deletion of all resources, must perform a full resync to restore them.
	wc.resetWatchRevisionForFullResync()
}
