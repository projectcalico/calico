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
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

const (
	maxUpdatesToConsolidate = 1000
)

// ResourceType groups together the watch and conversion information for a
// specific resource type.
type ResourceType struct {
	// ListInterface specifies the resource type to watch.
	ListInterface model.ListInterface

	// UpdateProcessor converts the raw KVPairs returned from the datastore into the appropriate
	// KVPairs required for the syncer.  This is optional.
	UpdateProcessor SyncerUpdateProcessor

	// SendDeletesOnConnFail will send deletes for all resources (and therefore do a full resync) if
	// the connection fails at any point.
	SendDeletesOnConnFail bool

	// Client identifier. If using a single client syncer, this should be blank. Otherwise this refers
	// to the named client in the supplied map of clients. If a client is not in the supplied map, then
	// the corresponding watcher will not be created (i.e. there will be no updates from that resource
	// type).
	ClientID string
}

// Error indicating a problem with a watcher communicating with the backend.
type errorSyncBackendError struct {
	Err error
}

func (e errorSyncBackendError) Error() string {
	return e.Err.Error()
}

// SyncerUpdateProcessor is used to convert a Watch update into one or more additional
// Syncer updates.
type SyncerUpdateProcessor interface {
	// Process is called to process a watch update.  The processor may convert this
	// to zero or more updates.  The processor may use these calls to maintain a local cache
	// if required.  It is safe for the processor to send multiple duplicate adds or deletes
	// since the WatcherSyncer maintains it's own cache and will swallow duplicates.
	// A KVPair with a nil value indicates a delete.  A non nil value indicates an add/modified.
	// The processor may respond with any number of adds or deletes.
	// If the resource cannot be converted then the update processor should treat this as a
	// delete event and return the appropriate delete keys where possible.
	Process(*model.KVPair) ([]*model.KVPair, error)

	// OnSyncerStarting is called when syncer is starting a full sync for the associated resource
	// type.  That means it is first going to list current resources and then watch for any updates.
	// If the processor maintains a private internal cache, then the cache should be cleared at
	// this point since the cache will be re-populated from the sync.
	OnSyncerStarting()
}

type Option func(*watcherSyncer)

func WithWatchRetryTimeout(t time.Duration) Option {
	return func(ws *watcherSyncer) {
		ws.watchRetryTimeout = t
	}
}

// New creates a new multiple Watcher-backed api.Syncer.
func New(client api.Client, resourceTypes []ResourceType, callbacks api.SyncerCallbacks, options ...Option) api.Syncer {
	return NewMultiClient(map[string]api.Client{"": client}, resourceTypes, callbacks, options...)
}

// NewMultiClient creates a new multiple Watcher-backed api.Syncer with multiple backing clients.
func NewMultiClient(clients map[string]api.Client, resourceTypes []ResourceType, callbacks api.SyncerCallbacks, options ...Option) api.Syncer {
	rs := &watcherSyncer{
		watcherCaches:     make([]*watcherCache, 0, len(resourceTypes)),
		cacheStatuses:     make([]api.SyncStatus, 0, len(resourceTypes)),
		results:           make(chan resultWithID, 2000),
		callbacks:         callbacks,
		watchRetryTimeout: DefaultWatchRetryTimeout,
	}
	for _, o := range options {
		o(rs)
	}
	for _, r := range resourceTypes {
		if client, ok := clients[r.ClientID]; ok {
			cacheID := len(rs.watcherCaches)
			rs.cacheStatuses = append(rs.cacheStatuses, api.WaitForDatastore)
			rs.watcherCaches = append(rs.watcherCaches, newWatcherCache(client, r, rs.results, rs.watchRetryTimeout, cacheID))
		} else {
			log.WithFields(log.Fields{
				"ClientID":      r.ClientID,
				"ListInterface": r.ListInterface,
			}).Debug("Skipping syncer resource because no client has been specified that matches the associated clientID")
		}
	}
	return rs
}

// watcherSyncer implements the api.Syncer interface.
type watcherSyncer struct {
	status            api.SyncStatus
	watcherCaches     []*watcherCache
	results           chan resultWithID
	cacheStatuses     []api.SyncStatus
	callbacks         api.SyncerCallbacks
	wgwc              *sync.WaitGroup
	wgws              *sync.WaitGroup
	cancel            context.CancelFunc
	watchRetryTimeout time.Duration
}

func (ws *watcherSyncer) Start() {
	log.Info("Start called")

	// Create a context and a wait group.
	// The context is passed to the run() method where it is passed on to all the watcher caches.
	// The cancel function is stored off and when called it signals to the caches that they need to wrap up their work.
	// watcher caches wait group (wswc) is used to signal the completion of all of the watcher cache goroutines.
	// watcher syncer wait group (wswc) is used to signal the completion of the watcher syncer itself.
	ctx, cancel := context.WithCancel(context.Background())
	ws.cancel = cancel
	ws.wgwc = &sync.WaitGroup{}
	ws.wgws = &sync.WaitGroup{}

	ws.wgws.Add(1)
	ws.wgwc.Add(len(ws.watcherCaches))
	go func() {
		defer ws.wgws.Done()
		ws.run(ctx)
		log.Debug("Watcher syncer run completed")
	}()
}

// Stop the watcher syncer and all the watcher caches. Delete events are created for all items
// in the watcher caches.
func (ws *watcherSyncer) Stop() {
	// Send a cancel to all the watcher caches, telling them to finish their work.
	ws.cancel()
	log.Debug("Waiting for watcher caches to stop")

	// Block on the watcher cache wait group, waiting for the watcher caches to finish
	ws.wgwc.Wait()
	log.Debug("Watcher caches have stopped")

	// Closing the results chan signals to the watchersyncer to shut itself down now that nothing else will write to
	// the results chan
	close(ws.results)
	ws.wgws.Wait()
}

// Send a status update and store the status.
func (ws *watcherSyncer) sendStatusUpdate(status api.SyncStatus) {
	log.WithFields(log.Fields{
		"from": ws.status,
		"to":   status,
	}).Info("watchersyncer transition")
	ws.callbacks.OnStatusUpdated(status)
	ws.status = status
}

// run implements the main syncer loop that loops forever receiving watch events and translating
// to syncer updates.
func (ws *watcherSyncer) run(ctx context.Context) {
	log.Debug("Sending initial status event and starting watchers")
	ws.sendStatusUpdate(api.WaitForDatastore)
	for _, wc := range ws.watcherCaches {
		// no need for ws.wgwc.Add(1), been set already
		go func(wc *watcherCache) {
			defer ws.wgwc.Done()
			wc.run(ctx)
			log.Debug("Watcher cache run completed")
		}(wc)
	}

	log.Info("Starting main event processing loop")
	var updates []api.Update
	for result := range ws.results {
		// Process the data - this will append the data in subsequent calls, and action
		// it if we hit a non-update event.
		updates := ws.processResult(updates, result)

		// Append results into the one update until we either flush the channel or we
		// hit our fixed limit per update.
	consolidationLoop:
		for range maxUpdatesToConsolidate {
			select {
			case next, ok := <-ws.results:
				if !ok {
					break consolidationLoop
				}
				updates = ws.processResult(updates, next)
			default:
				break consolidationLoop
			}
		}

		// Consolidation done, send any remaining buffered updates.
		updates = ws.sendUpdates(updates)
	}
}

// Process a result from the result channel.  We don't immediately action updates, but
// instead start grouping them together so that we can send a larger single update to
// Felix.
func (ws *watcherSyncer) processResult(updates []api.Update, r resultWithID) []api.Update {
	switch v := r.value.(type) {
	case []api.Update:
		updates = append(updates, v...)

	case error:
		// Received an error.  Firstly, send any updates that we have grouped.
		updates = ws.sendUpdates(updates)

		// If this is a parsing error, and if the callbacks support
		// it, then send the error update.
		log.WithError(v).Debug("Error received in main syncer event processing loop")
		if pe, ok := v.(cerrors.ErrorParsingDatastoreEntry); ok {
			if ec, ok := ws.callbacks.(api.SyncerParseFailCallbacks); ok {
				log.Debug("syncer receiver can receive parse failed callbacks")
				ec.ParseFailed(pe.RawKey, pe.RawValue)
			}
		}

		if se, ok := v.(errorSyncBackendError); ok {
			if ec, ok := ws.callbacks.(api.SyncFailCallbacks); ok {
				log.Debug("syncer receiver can receive sync failed callbacks")
				ec.SyncFailed(se.Err)
			}
		}

	case api.SyncStatus:
		log.WithFields(log.Fields{
			"cacheID": r.cacheID,
			"status":  v,
		}).Debug("Received status event from watcher cache")

		ws.cacheStatuses[r.cacheID] = v

		var numWaiting, numSynced int
		for _, s := range ws.cacheStatuses {
			switch s {
			case api.WaitForDatastore:
				numWaiting++
			case api.InSync:
				numSynced++
			}
		}

		var newStatus api.SyncStatus
		switch {
		case numSynced == len(ws.cacheStatuses):
			newStatus = api.InSync
		case numWaiting == len(ws.cacheStatuses):
			newStatus = api.WaitForDatastore
		default:
			newStatus = api.ResyncInProgress
		}

		if newStatus != ws.status {
			// Flush before announcing the transition so the consumer sees events
			// ahead of the boundary they belong to.
			updates = ws.sendUpdates(updates)
			ws.sendStatusUpdate(newStatus)
		}
	}

	return updates
}

// sendUpdates is used to send the consolidated set of updates.  Returns nil.
func (ws *watcherSyncer) sendUpdates(updates []api.Update) []api.Update {
	log.WithField("NumUpdates", len(updates)).Debug("Sending syncer updates (if any to send)")
	if len(updates) > 0 {
		ws.callbacks.OnUpdates(updates)
	}
	return nil
}
