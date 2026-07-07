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

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/utils/pointer"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// ListWatcher implements the ListAndWatch logic for Kubernetes backends.
// It embeds GenericListWatcher for common functionality and implements
// the ListWatchBackend interface for k8s-specific logic:
// - Bookmark handling
// - WatchList support with fallback
// - k8s-specific error handling
type ListWatcher struct {
	*api.GenericListWatcher
	client resources.K8sResourceClient
}

// Ensure ListWatcher implements ListWatchBackend
var _ api.ListWatchBackend = (*ListWatcher)(nil)

// NewListWatcher creates a new k8sListWatcher instance
func NewListWatcher(client resources.K8sResourceClient, list model.ListInterface, handler api.EventHandler, opts ...api.ListWatcherOption) *ListWatcher {
	return &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler, opts...),
		client:             client,
	}
}

// SupportsWatchList implements api.WatchListSupporter for k8s.
func (lw *ListWatcher) SupportsWatchList() bool {
	if supporter, ok := lw.client.(api.WatchListSupporter); ok {
		return supporter.SupportsWatchList()
	}
	return true
}

// PerformList implements ListWatchBackend.PerformList for k8s.
func (lw *ListWatcher) PerformList(ctx context.Context) (*model.KVPairList, error) {
	return lw.client.List(ctx, lw.List, "")
}

// CreateWatch implements ListWatchBackend.CreateWatch for k8s.
func (lw *ListWatcher) CreateWatch(ctx context.Context, useWatchList bool) (api.WatchInterface, error) {
	watchOptions := api.WatchOptions{
		AllowWatchBookmarks: true,
		Revision:            lw.CurrentRevision,
	}

	// Configure WatchList options when requested by the generic list watcher.
	if useWatchList {
		watchOptions.Revision = ""
		watchOptions.SendInitialEvents = pointer.Bool(true)
		watchOptions.ResourceVersionMatch = api.ResourceVersionMatchNotOlderThan
	}

	return lw.client.Watch(ctx, lw.List, watchOptions)
}

// HandleListError implements ListWatchBackend.HandleListError for k8s.
func (lw *ListWatcher) HandleListError(err error) {
	if kerrors.IsNotFound(err) {
		// The resource type doesn't exist yet (CRD not installed)
		// This is a valid long-term state, so we don't want to keep retrying rapidly
		lw.Logger.Info("Backing API not installed, marking as in-sync and retrying later")

		// Treat the response as healthy, but force a full resync if the API
		// becomes available later.
		lw.ResetForFullResync()
		lw.MarkSuccessfulConnection()

		// Notify handler that we're in sync (even though API is not installed)
		// This allows the syncer to proceed without this resource type
		lw.Handler.OnSync()

		// Schedule retry for a long time later
		lw.RetryAfter(lw.Options.MissingAPIRetryTime)
		return
	}

	if kerrors.IsResourceExpired(err) || isTooLargeResourceVersionError(err) {
		// Our current watch revision is out of sync, start again without a revision
		lw.Logger.WithError(err).Info("Resource too old/new error from server, clearing cached watch revision")
		lw.ResetForFullResync()
		// Error is a "layer 7" error; so connection is good!
		lw.MarkSuccessfulConnection()
		// Schedule a retry to avoid tight loop
		lw.RetryAfter(lw.Options.ListRetryInterval)
		return
	}

	lw.GenericListWatcher.HandleListError(err)
}

// HandleWatchError implements ListWatchBackend.HandleWatchError for k8s.
func (lw *ListWatcher) HandleWatchError(err error) {
	if kerrors.IsNotFound(err) {
		lw.HandleListError(err)
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

	if lw.HandleWatchUnavailableError(err) {
		return
	}

	lw.GenericListWatcher.HandleWatchError(err)
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

// PerformInitialSync implements ListWatchBackend.PerformInitialSync for k8s.
// k8s supports two modes:
//   - WatchList mode (default): Initial data comes through watch events with
//     SendInitialEvents=true. Sync completion is signaled by a bookmark.
//   - List+Watch mode (fallback): Performs a traditional List operation first.
func (lw *ListWatcher) PerformInitialSync(ctx context.Context, g *api.GenericListWatcher, useWatchList bool) error {
	if !useWatchList {
		// Fall back to traditional List+Watch mode, use common implementation.
		return g.PerformListSync(ctx, lw)
	}

	// WatchList mode: initial data comes through watch events
	g.Logger.Info("Using WatchList mode for initial sync")
	g.Handler.OnResyncStarted()
	return nil
}

// handleBookmark processes a bookmark event
func (lw *ListWatcher) handleBookmark(event api.WatchEvent) {
	if event.New == nil {
		lw.Logger.Warn("Watch bookmark received without revision")
		return
	}

	lw.Logger.WithField("newRevision", event.New.Revision).Debug("Watch bookmark received")
	lw.UpdateRevision(event.New.Revision)

	// Check if this bookmark indicates sync completion (for WatchList)
	k8sRes, ok := event.New.Value.(resources.Resource)
	if ok && k8sRes.GetObjectMeta().GetAnnotations()[metav1.InitialEventsAnnotationKey] == "true" {
		// This bookmark indicates we've received all initial events
		lw.Handler.OnSync()
		// Clear the initial sync flag after WatchList sync completion
		lw.MarkInitialSyncComplete()
	}
}
