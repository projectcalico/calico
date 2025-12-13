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

package k8s

import (
	"context"
	"errors"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/utils/pointer"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// ListWatcher implements the ListAndWatch logic for Kubernetes backends.
// It embeds GenericListWatcher for common functionality and implements
// the ListWatchBackend interface for k8s-specific logic:
// - Bookmark handling
// - WatchList support with fallback
// - k8s-specific error handling
//
// State management:
//   - fallbackToList: Set to true when WatchList mode is not supported by the server.
//     Once set, the ListWatcher uses ListThenWatchStrategy instead of WatchListStrategy.
//   - needsInitialSync: Indicates that initial sync is required. This is set to true
//     initially and after certain error conditions. It's cleared after successful sync
//     (either via List completion in fallback mode, or via bookmark in WatchList mode).
//
// The relationship between needsInitialSync and CurrentRevision:
//   - needsInitialSync=true, CurrentRevision="0": True initial sync, full dataset expected.
//   - needsInitialSync=true, CurrentRevision!="0": Recovery/reconnection scenario.
//     In both WatchList and ListThenWatch modes, the full dataset will be received:
//     * WatchList mode: With SendInitialEvents=true, server re-sends all initial events
//     * ListThenWatch mode: List API returns full dataset from that revision
//   - needsInitialSync=false: Already synced, just watching for changes.
//
// In all cases where needsInitialSync=true, OnResyncStarted() is called to prepare
// for receiving the full dataset (e.g., increment resync epoch for deletion tracking).
type ListWatcher struct {
	*api.GenericListWatcher
	client           resources.K8sResourceClient
	fallbackToList   bool
	needsInitialSync bool
}

// Ensure ListWatcher implements ListWatchBackend
var _ api.ListWatchBackend = (*ListWatcher)(nil)

// NewListWatcher creates a new k8sListWatcher instance
func NewListWatcher(client resources.K8sResourceClient, list model.ListInterface, handler api.EventHandler) *ListWatcher {
	return &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             client,
		needsInitialSync:   true,
	}
}

// PerformList implements ListWatchBackend.PerformList for k8s.
func (lw *ListWatcher) PerformList(ctx context.Context) (*model.KVPairList, error) {
	return lw.client.List(ctx, lw.List, lw.CurrentRevision)
}

// CreateWatch implements ListWatchBackend.CreateWatch for k8s.
func (lw *ListWatcher) CreateWatch(ctx context.Context, isInitialSync bool) (api.WatchInterface, error) {
	watchOptions := api.WatchOptions{
		AllowWatchBookmarks: true,
		Revision:            lw.CurrentRevision,
	}

	// Configure WatchList options for initial sync when not in fallback mode
	if isInitialSync && !lw.fallbackToList {
		watchOptions.SendInitialEvents = pointer.Bool(true)
		watchOptions.ResourceVersionMatch = metav1.ResourceVersionMatchNotOlderThan
	}

	return lw.client.Watch(ctx, lw.List, watchOptions)
}

// HandleListError implements ListWatchBackend.HandleListError for k8s.
func (lw *ListWatcher) HandleListError(err error) {
	if kerrors.IsNotFound(err) {
		// The resource type doesn't exist yet (CRD not installed)
		// This is a valid long-term state, so we don't want to keep retrying rapidly
		lw.Logger.Info("Backing API not installed, marking as in-sync and retrying later")

		// Notify handler that we're in sync (even though API is not installed)
		// This allows the syncer to proceed without this resource type
		lw.Handler.OnSync()

		// Schedule retry for a long time later
		lw.RetryAfter(api.MissingAPIRetryTime)
		return
	}

	lw.Logger.WithError(err).Info("Failed to perform list of current data")

	if kerrors.IsResourceExpired(err) || isTooLargeResourceVersionError(err) {
		// Our current watch revision is out of sync, start again without a revision
		lw.Logger.Info("Resource too old/new error from server, clearing cached watch revision")
		lw.ResetForFullResync()
		// Error is a "layer 7" error; so connection is good!
		lw.MarkSuccessfulConnection()
		// Schedule a retry to avoid tight loop
		lw.RetryAfter(api.ListRetryInterval)
		return
	}

	// Generic error handling
	// Check if we've been disconnected too long
	if lw.CheckConnectionTimeout() {
		lw.Logger.Warn("Connection has failed for too long")
		lw.Handler.OnError(err)
	}

	// Schedule retry with delay
	lw.RetryAfter(api.ListRetryInterval)
}

// HandleWatchError implements ListWatchBackend.HandleWatchError for k8s.
func (lw *ListWatcher) HandleWatchError(err error) {
	// Check if WatchList is not supported
	if lw.CurrentRevision == "0" && kerrors.IsInvalid(err) {
		lw.Logger.WithError(err).Warn("Backend not support WatchList, falling back to List")
		lw.fallbackToList = true
		return
	}

	// Check for revision-related errors
	if kerrors.IsResourceExpired(err) || kerrors.IsGone(err) || isTooLargeResourceVersionError(err) {
		// Our current watch revision is too old (or too new!), start again
		lw.Logger.Info("Watch has expired, queueing full resync")
		lw.ResetForFullResync()
		// Error is a "layer 7" error; so connection is good!
		lw.MarkSuccessfulConnection()
		return
	}

	// Check for connection-related errors
	if utilnet.IsConnectionRefused(err) || kerrors.IsTooManyRequests(err) {
		// Connection-related error, we can just retry without resetting the watch
		if lw.CheckConnectionTimeout() {
			// Too long since we were connected
			lw.Logger.WithError(err).Warn("Timed out waiting for connection to be restored, forcing resync")
			lw.ResetForFullResync()
			return
		}
		lw.Logger.WithError(err).Warn("API server refused connection, will retry")
		return
	}

	var errNotSupp cerrors.ErrorOperationNotSupported
	var errNotExist cerrors.ErrorResourceDoesNotExist
	if errors.As(err, &errNotSupp) ||
		errors.As(err, &errNotExist) {
		// Watch is not supported on this resource type, either because the type fundamentally
		// doesn't support it, or because there are no resources to watch yet (and Kubernetes won't
		// let us watch if there are no resources yet). Pause for the watch poll interval.
		// This loop effectively becomes a poll loop for this resource type.
		lw.Logger.Debug("Watch operation not supported; reverting to poll.")
		lw.RetryAfter(api.WatchPollInterval)

		// Make sure we force a re-list of the resource even if the watch previously succeeded
		// but now cannot.
		lw.fallbackToList = true
		lw.needsInitialSync = true
		return
	}

	// None of our expected errors, retry a few times before we give up
	if lw.IncrementErrorCount() {
		// Too many errors at the current revision, trigger a full resync
		lw.Logger.WithError(err).Warn("Watch repeatedly failed without making progress, triggering full resync")
		lw.ResetForFullResync()
		return
	}

	lw.Logger.WithError(err).Warn("Watch of resource finished. Attempting to restart it...")
}

// HandleWatchEvent implements ListWatchBackend.HandleWatchEvent for k8s.
func (lw *ListWatcher) HandleWatchEvent(event api.WatchEvent) error {
	// Try to handle basic events (Added, Modified, Deleted) using common method
	if lw.HandleBasicWatchEvent(event) {
		return nil // continue processing
	}

	// Handle k8s-specific events
	switch event.Type {
	case api.WatchBookmark:
		lw.handleBookmark(event)
		lw.MarkSuccessfulConnection()
		return nil

	case api.WatchError:
		lw.HandleWatchError(event.Error)
		return event.Error // stop processing, will recreate watcher

	default:
		lw.Logger.Errorf("Unknown event type received from the datastore: %v", event.Type)
	}

	return nil
}

// OnListSuccess implements ListWatchBackend.OnListSuccess for k8s.
// This is called after a successful list operation and clears the initial sync flag.
func (lw *ListWatcher) OnListSuccess() {
	lw.needsInitialSync = false
}

// ShouldPerformFullResync implements ListWatchBackend.ShouldPerformFullResync for k8s.
// Returns true if needsInitialSync flag is set or CurrentRevision is "0" (initial state or after reset).
//
// This method determines whether PerformInitialSync should be called. When true,
// the full dataset will be received regardless of CurrentRevision value:
//   - WatchList mode: With SendInitialEvents=true, server sends all initial events as ADDED
//   - ListThenWatch mode: List API returns full dataset
//
// In all cases, OnResyncStarted() is called to prepare for the full dataset.
//
// The actual behavior depends on the SyncStrategy returned by GetSyncStrategy.
func (lw *ListWatcher) ShouldPerformFullResync() bool {
	return lw.needsInitialSync || lw.CurrentRevision == "0"
}

// GetSyncStrategy implements ListWatchBackend.GetSyncStrategy for k8s.
// Returns WatchListStrategy when not in fallback mode, ListThenWatchStrategy otherwise.
//
// Strategy selection:
//   - WatchListStrategy: Used by default. Initial data comes through watch events with
//     SendInitialEvents=true. Sync completion is signaled by a bookmark with
//     InitialEventsAnnotationKey. More memory-efficient for large clusters.
//   - ListThenWatchStrategy: Used as fallback when WatchList is not supported by the server.
//     Performs a traditional List operation first, then starts watching.
func (lw *ListWatcher) GetSyncStrategy() api.SyncStrategy {
	if lw.fallbackToList {
		return api.ListThenWatchStrategy{}
	}
	return api.WatchListStrategy{}
}

// handleBookmark processes a bookmark event
func (lw *ListWatcher) handleBookmark(event api.WatchEvent) {
	lw.Logger.WithField("newRevision", event.New.Revision).Debug("Watch bookmark received")
	lw.UpdateRevision(event.New.Revision)

	// Check if this bookmark indicates sync completion (for WatchList)
	k8sRes, ok := event.New.Value.(resources.Resource)
	if ok && k8sRes.GetObjectMeta().GetAnnotations()[metav1.InitialEventsAnnotationKey] == "true" {
		// This bookmark indicates we've received all initial events
		lw.Handler.OnSync()
		// Clear the initial sync flag after WatchList sync completion
		lw.needsInitialSync = false
	}
}
