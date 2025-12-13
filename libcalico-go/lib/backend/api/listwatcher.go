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

// SyncStrategy defines the interface for different synchronization strategies.
// This allows clean separation between WatchList mode (k8s) and traditional
// List+Watch mode (etcd).
type SyncStrategy interface {
	// PerformInitialSync executes the initial synchronization.
	// For WatchList strategy: notifies resync started, sync completion is via bookmark
	// For ListThenWatch strategy: performs list, sends events, notifies sync complete
	// Returns an error if the sync fails and should be retried.
	PerformInitialSync(ctx context.Context, g *GenericListWatcher, backend ListWatchBackend) error
}

// ListThenWatchStrategy implements the traditional List+Watch synchronization pattern.
// This is used by etcd backend where we first list all resources, then watch for changes.
type ListThenWatchStrategy struct{}

var _ SyncStrategy = ListThenWatchStrategy{}

// PerformInitialSync executes a full list operation and sends all resources as Add events.
func (s ListThenWatchStrategy) PerformInitialSync(ctx context.Context, g *GenericListWatcher, backend ListWatchBackend) error {
	g.Logger.Info("Full resync is required (ListThenWatch mode)")

	// Notify handler that resync is starting
	g.Handler.OnResyncStarted()

	// Perform the list operation
	list, err := backend.PerformList(ctx)
	if err != nil {
		// Backend handles all error cases including scheduling retries
		backend.HandleListError(err)
		return err
	}

	// Successfully listed resources
	g.MarkSuccessfulConnection()

	if list.Revision == "" || list.Revision == "0" {
		if len(list.KVPairs) == 0 {
			// Got a bad revision but there are no items. This may mean that the datastore
			// returns an unhelpful "not found" error instead of an empty list. Revert to a
			// poll until some items show up.
			g.Logger.Info("List returned no items and an empty/zero revision, reverting to poll.")
			g.ResetForFullResync()
			g.RetryAfter(WatchPollInterval)
			return errors.New("list returned no items and an empty/zero revision")
		}
		g.Logger.Panic("BUG: List returned items with empty/zero revision. Watch would be inconsistent.")
	}

	backend.OnListSuccess()
	g.Logger.WithFields(log.Fields{
		"numKVs":   len(list.KVPairs),
		"revision": list.Revision,
	}).Debug("List completed")

	// Send add events for each resource
	g.SendListAsAddEvents(list)

	// Update revision and notify sync complete
	g.UpdateRevision(list.Revision)
	g.Handler.OnSync()

	return nil
}

// WatchListStrategy implements the WatchList synchronization pattern.
// This is used by k8s backend where initial data comes through Watch events
// and sync completion is signaled by a bookmark event.
//
// WatchList mode differs from traditional List+Watch in several key ways:
//   - Initial data is streamed incrementally through ADDED watch events
//   - A bookmark with InitialEventsAnnotationKey signals sync completion
//   - Memory pressure is reduced since resources aren't loaded all at once
//
// Resync semantics in WatchList mode:
// When PerformInitialSync is called (i.e., ShouldPerformFullResync returns true),
// it means we need to receive the full dataset. This is because in WatchList mode
// with SendInitialEvents=true, the server will re-send all initial events regardless
// of the CurrentRevision value. Therefore, OnResyncStarted() is always called to
// allow the handler to prepare for the full dataset (e.g., increment resync epoch
// for tracking deletions).
//
// This behavior is similar to ListThenWatchStrategy where a relist always returns
// the full dataset. The key difference is how the data is delivered:
//   - WatchList: Data comes through ADDED watch events, sync signaled by bookmark
//   - ListThenWatch: Data comes through List API response
type WatchListStrategy struct{}

var _ SyncStrategy = WatchListStrategy{}

// PerformInitialSync prepares for WatchList mode sync.
// In WatchList mode, initial data comes through Watch events, not a List call.
// OnSync will be triggered by a bookmark event with InitialEventsAnnotationKey.
//
// OnResyncStarted is always called because when using SendInitialEvents=true,
// the server will send all initial events as ADDED watch events, regardless of
// the CurrentRevision value. The handler needs to prepare for receiving the
// complete dataset (e.g., increment resync epoch for deletion tracking).
func (s WatchListStrategy) PerformInitialSync(ctx context.Context, g *GenericListWatcher, backend ListWatchBackend) error {
	g.Logger.Info("Using WatchList mode for initial sync")

	// Notify handler that resync is starting.
	// In WatchList mode with SendInitialEvents=true, the server sends all
	// initial events regardless of CurrentRevision, so we always need to
	// prepare for a full resync.
	g.Handler.OnResyncStarted()

	// No list operation needed - initial data comes through watch events
	return nil
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

	// OnListSuccess is called after a successful list operation.
	// Implementations can use this to update backend-specific state.
	OnListSuccess()

	// ShouldPerformFullResync returns true if a full resync should be performed.
	// This allows backends to trigger resyncs based on backend-specific conditions.
	ShouldPerformFullResync() bool

	// GetSyncStrategy returns the synchronization strategy to use.
	// This replaces the UsesWatchListMode method with a proper strategy pattern.
	GetSyncStrategy() SyncStrategy
}

// GenericListWatcher provides common functionality for list-watch implementations.
// Backend-specific implementations should embed this struct to reuse common logic
// for retry throttling, revision tracking, and error counting.
type GenericListWatcher struct {
	List    model.ListInterface
	Handler EventHandler
	Logger  *log.Entry

	// State tracking
	CurrentRevision        string
	ErrorCountAtCurrentRev int
	LastSuccessfulConnTime time.Time

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
		CurrentRevision:        "0", // Initialize to "0" to indicate list is required
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

// ResetForFullResync resets the current revision to "0" to trigger a full resync.
func (g *GenericListWatcher) ResetForFullResync() {
	g.CurrentRevision = "0"
	g.ErrorCountAtCurrentRev = 0
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
// This method uses the strategy pattern to handle different synchronization modes.
func (g *GenericListWatcher) maybeResyncAndCreateWatcher(ctx context.Context, backend ListWatchBackend) {
	// Determine if we need to perform a full resync
	performFullResync := backend.ShouldPerformFullResync()

	if performFullResync {
		// Use strategy pattern to perform initial sync
		strategy := backend.GetSyncStrategy()
		if err := strategy.PerformInitialSync(ctx, g, backend); err != nil {
			// Strategy handles error cases including scheduling retries
			return
		}
	}

	// Start watching from the current revision
	g.Logger.WithField("revision", g.CurrentRevision).Debug("Starting watch")
	watcher, err := backend.CreateWatch(ctx, performFullResync)
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
