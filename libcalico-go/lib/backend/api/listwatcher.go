// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package api

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Default configuration values for list-watch operations.
// These are variables (not constants) to allow tests to modify them.
var (
	MinResyncInterval = 500 * time.Millisecond
	ListRetryInterval = 1000 * time.Millisecond
	WatchPollInterval = 5000 * time.Millisecond
	WatchRetryTimeout = 600 * time.Second

	// MissingAPIRetryTime is the time to wait before retrying when the backing
	// API is not installed. This is a long interval since missing APIs are expected
	// to be a stable state.
	MissingAPIRetryTime = 30 * time.Minute

	// MaxErrorsPerRevision is the maximum number of errors allowed at a single
	// revision before triggering a full resync.
	MaxErrorsPerRevision = 5
)

// closedTimeC is a closed channel that triggers immediately in select statements.
var closedTimeC <-chan time.Time

func init() {
	c := make(chan time.Time)
	close(c)
	closedTimeC = c
}

// ListWatchBackend defines the interface for backend-specific list-watch operations.
// Implementations should provide backend-specific logic for performing list and watch operations.
type ListWatchBackend interface {
	// PerformList executes a list operation and returns the results.
	// It should handle backend-specific error handling and return appropriate errors.
	PerformList(ctx context.Context) (*model.KVPairList, error)

	// CreateWatch creates a new watch from the current revision.
	// The implementation should use GenericListWatcher.CurrentRevision for the starting point.
	// The isInitialSync parameter indicates if this is the initial sync (resync required).
	CreateWatch(ctx context.Context, isInitialSync bool) (WatchInterface, error)

	// HandleWatchEvent processes a single watch event.
	// Returns nil to continue processing, or an error to stop the watch loop.
	HandleWatchEvent(event WatchEvent) error

	// HandleListError processes errors from the List operation.
	// Implementations should handle all error cases including scheduling retries.
	HandleListError(err error)

	// HandleWatchError processes errors from the Watch operation.
	// This is called when CreateWatch fails.
	HandleWatchError(err error)

	// PerformInitialSync executes the initial synchronization.
	// For WatchList mode (k8s): notifies resync started, sync completion is via bookmark
	// For ListThenWatch mode (etcd): performs list, sends events, notifies sync complete
	// Returns an error if the sync fails and should be retried.
	PerformInitialSync(ctx context.Context, g *GenericListWatcher) error
}

// GenericListWatcher provides common functionality for list-watch implementations.
// Backend-specific implementations should embed this struct to reuse common logic
// for retry throttling, revision tracking, and error counting.
//
// State management:
//   - InitialSyncPending: Indicates that initial sync is required. This is set to true
//     initially and after certain error conditions. It's cleared after successful sync
//     (either via List completion in fallback mode, or via bookmark in WatchList mode).
//
// The relationship between InitialSyncPending and CurrentRevision:
//   - InitialSyncPending=true, CurrentRevision="": True initial sync, full dataset expected.
//   - InitialSyncPending=true, CurrentRevision!="": Recovery/reconnection scenario.
//     In both WatchList and ListThenWatch modes, the full dataset will be received:
//   - WatchList mode: With SendInitialEvents=true, server re-sends all initial events
//   - ListThenWatch mode: List API returns full dataset from that revision
//   - InitialSyncPending=false: Already synced, just watching for changes.
//
// In all cases where InitialSyncPending=true, OnResyncStarted() is called to prepare
// for receiving the full dataset (e.g., increment resync epoch for deletion tracking).
type GenericListWatcher struct {
	List    model.ListInterface
	Handler EventHandler
	Logger  *log.Entry

	// State tracking
	CurrentRevision        string
	ErrorCountAtCurrentRev int
	LastSuccessfulConnTime time.Time
	InitialSyncPending     bool // Indicates that initial sync is required

	// Throttling for retries
	RetryBlockedUntil time.Time

	// Watch management - shared across implementations
	Watch WatchInterface
}

// NewGenericListWatcher creates a new GenericListWatcher with the given parameters.
func NewGenericListWatcher(list model.ListInterface, handler EventHandler) *GenericListWatcher {
	return &GenericListWatcher{
		List:                   list,
		Handler:                handler,
		Logger:                 log.WithField("list", list),
		CurrentRevision:        "", // Empty revision to request latest data
		InitialSyncPending:     true,
		LastSuccessfulConnTime: time.Now(),
	}
}

// RetryThrottleC returns a channel that will be triggered after the retry delay has passed.
// If no delay is needed, it returns a closed channel that triggers immediately.
func (g *GenericListWatcher) RetryThrottleC() <-chan time.Time {
	blockFor := time.Until(g.RetryBlockedUntil)
	if blockFor > 0 {
		g.Logger.WithField("delay", blockFor).Debug("Waiting before next retry")
		return time.After(blockFor)
	}
	return closedTimeC // Triggers immediately.
}

// RetryAfter schedules the next retry attempt after the specified duration.
func (g *GenericListWatcher) RetryAfter(d time.Duration) {
	g.RetryBlockedUntil = time.Now().Add(d)
}

// UpdateRevision updates the current revision and resets the error count.
func (g *GenericListWatcher) UpdateRevision(revision string) {
	if revision != "" {
		g.CurrentRevision = revision
		g.ErrorCountAtCurrentRev = 0
	}
}

// MarkSuccessfulConnection updates the last successful connection time.
func (g *GenericListWatcher) MarkSuccessfulConnection() {
	g.LastSuccessfulConnTime = time.Now()
}

// ResetForFullResync resets the current revision to empty to trigger a full resync.
func (g *GenericListWatcher) ResetForFullResync() {
	g.CurrentRevision = ""
	g.ErrorCountAtCurrentRev = 0
	g.InitialSyncPending = true
}

// MarkInitialSyncComplete clears the initial sync pending flag.
// This should be called after the initial sync is complete (either via List
// completion in ListThenWatch mode, or via bookmark in WatchList mode).
func (g *GenericListWatcher) MarkInitialSyncComplete() {
	g.InitialSyncPending = false
}

// PerformListSync performs a full list-based synchronization.
// This is the common implementation for List+Watch mode used by etcd and k8s fallback.
// It notifies the handler, performs the list, sends events, and marks sync complete.
func (g *GenericListWatcher) PerformListSync(ctx context.Context, backend ListWatchBackend) error {
	g.Logger.Info("Full resync is required (ListThenWatch mode)")

	// Notify handler that resync is starting
	g.Handler.OnResyncStarted()

	// Perform the list operation
	list, err := backend.PerformList(ctx)
	if err != nil {
		backend.HandleListError(err)
		return err
	}

	// Successfully listed resources
	g.MarkSuccessfulConnection()

	if list.Revision == "" || list.Revision == "0" {
		if len(list.KVPairs) == 0 {
			g.Logger.Info("List returned no items and an empty/zero revision, reverting to poll.")
			g.ResetForFullResync()
			g.RetryAfter(WatchPollInterval)
			return errors.New("list returned no items and an empty/zero revision")
		}
		g.Logger.Panic("BUG: List returned items with empty/zero revision. Watch would be inconsistent.")
	}

	g.Logger.WithFields(log.Fields{
		"numKVs":   len(list.KVPairs),
		"revision": list.Revision,
	}).Debug("List completed")

	// Send add events for each resource
	g.SendListAsAddEvents(list)

	// Update revision and notify sync complete
	g.UpdateRevision(list.Revision)
	g.Handler.OnSync()

	g.MarkInitialSyncComplete()
	return nil
}

// IncrementErrorCount increments the error count at the current revision.
// Returns true if the error count has exceeded the maximum, indicating
// a full resync should be triggered.
func (g *GenericListWatcher) IncrementErrorCount() bool {
	g.ErrorCountAtCurrentRev++
	return g.ErrorCountAtCurrentRev >= MaxErrorsPerRevision
}

// CheckConnectionTimeout checks if the connection has been lost for too long.
// Returns true if the timeout has been exceeded.
func (g *GenericListWatcher) CheckConnectionTimeout() bool {
	return time.Since(g.LastSuccessfulConnTime) > WatchRetryTimeout
}

// RunLoopWithBackend executes the main list-and-watch loop using the provided backend.
// This is the preferred method for running list-watch operations as it uses the
// Backend interface for backend-specific operations while keeping common logic centralized.
func (g *GenericListWatcher) RunLoopWithBackend(ctx context.Context, backend ListWatchBackend) error {
	g.Logger.Debug("Starting ListAndWatch loop with backend")

	// Main loop, repeatedly resync with the store and then watch for changes
	// until our watch fails or context is cancelled.
	for ctx.Err() == nil {
		// Wait for any pending retry throttle before proceeding
		select {
		case <-ctx.Done():
			g.Logger.Debug("Context cancelled, stopping ListAndWatch")
			return ctx.Err()
		case <-g.RetryThrottleC():
		}

		// Schedule minimum retry delay to avoid tight loops
		g.RetryAfter(MinResyncInterval)

		// Perform resync and watch cycle
		g.resyncAndLoopReadingFromWatcher(ctx, backend)
	}

	g.Logger.Debug("Context cancelled, stopping ListAndWatch")
	return ctx.Err()
}

// resyncAndLoopReadingFromWatcher performs resync if needed, then loops reading from watcher.
// This is a common implementation used by both k8s and etcd backends.
func (g *GenericListWatcher) resyncAndLoopReadingFromWatcher(ctx context.Context, backend ListWatchBackend) {
	defer g.CleanExistingWatcher()
	g.maybeResyncAndCreateWatcher(ctx, backend)
	if ctx.Err() != nil {
		return
	}
	// Only loop if watcher was successfully created
	if g.Watch == nil {
		return
	}
	g.loopReadingFromWatcherWithBackend(ctx, backend)
}

// CleanExistingWatcher cleans up the current watcher if it exists.
// This is a common implementation that can be used by all backends.
func (g *GenericListWatcher) CleanExistingWatcher() {
	if g.Watch != nil {
		g.Watch.Stop()
		g.Watch = nil
	}
}

// maybeResyncAndCreateWatcher performs a resync if needed and creates a new watcher.
func (g *GenericListWatcher) maybeResyncAndCreateWatcher(ctx context.Context, backend ListWatchBackend) {
	if g.InitialSyncPending {
		if err := backend.PerformInitialSync(ctx, g); err != nil {
			// Backend handles error cases including scheduling retries
			return
		}
	}

	// Start watching from the current revision
	g.Logger.WithField("revision", g.CurrentRevision).Debug("Starting watch")
	watcher, err := backend.CreateWatch(ctx, g.InitialSyncPending)
	if err != nil {
		g.Logger.WithError(err).Info("Failed to start watch")
		backend.HandleWatchError(err)
		return
	}

	g.Watch = watcher
}

// loopReadingFromWatcherWithBackend reads events from the watcher using the backend's event handler.
func (g *GenericListWatcher) loopReadingFromWatcherWithBackend(ctx context.Context, backend ListWatchBackend) {
	g.LoopReadingFromWatcher(ctx, g.Watch, backend.HandleWatchEvent)
}

// SendListAsAddEvents sends all KVPairs from a list result as Add events to the handler.
// This is a common operation after performing a List operation during resync.
func (g *GenericListWatcher) SendListAsAddEvents(list *model.KVPairList) {
	for _, kvp := range list.KVPairs {
		g.Handler.OnAdd(kvp)
	}
}

// LoopReadingFromWatcher processes events from a watcher until the context is cancelled,
// the watch channel is closed, or an error occurs. The onEvent callback is called for
// each event and should return nil to continue processing, or an error to stop.
func (g *GenericListWatcher) LoopReadingFromWatcher(ctx context.Context, watcher WatchInterface, onEvent func(WatchEvent) error) {
	for {
		select {
		case <-ctx.Done():
			g.Logger.Debug("Context is done. Returning")
			return

		case event, ok := <-watcher.ResultChan():
			if !ok {
				// If the channel is closed then resync/recreate the watch.
				g.Logger.Debug("Watch channel closed by remote - will recreate watcher")
				return
			}

			// Handle the event, return if handler returns an error
			if err := onEvent(event); err != nil {
				return
			}
		}
	}
}

// HandleBasicWatchEvent processes a basic watch event (Added, Modified, Deleted).
// It updates the revision and calls the appropriate handler method.
// Returns true if the event was handled, false if it requires special handling (e.g., Bookmark, Error).
func (g *GenericListWatcher) HandleBasicWatchEvent(event WatchEvent) bool {
	switch event.Type {
	case WatchAdded:
		if event.New == nil {
			g.Logger.Error("Added event without new value, skipping")
			return true
		}
		g.UpdateRevision(event.New.Revision)
		g.Handler.OnAdd(event.New)
		g.MarkSuccessfulConnection()
		return true

	case WatchModified:
		if event.New == nil {
			g.Logger.Error("Modified event without new value, skipping")
			return true
		}
		g.UpdateRevision(event.New.Revision)
		g.Handler.OnUpdate(event.New)
		g.MarkSuccessfulConnection()
		return true

	case WatchDeleted:
		if event.Old == nil {
			g.Logger.Error("Deletion event without old value, skipping")
			return true
		}
		g.UpdateRevision(event.Old.Revision)
		g.Handler.OnDelete(event.Old)
		g.MarkSuccessfulConnection()
		return true

	default:
		// Event requires special handling (Bookmark, Error, or unknown)
		return false
	}
}
