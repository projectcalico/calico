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

package etcdv3

import (
	"context"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// ListWatcher encapsulates the list-watch logic for etcd backend.
// It embeds GenericListWatcher for common functionality and implements
// the ListWatchBackend interface for etcd-specific logic.
type ListWatcher struct {
	*api.GenericListWatcher
	client *etcdV3Client
}

// Ensure ListWatcher implements ListWatchBackend
var _ api.ListWatchBackend = (*ListWatcher)(nil)

// ListAndWatch implements the list-and-watch pattern for etcd resources.
// For etcd, this uses the existing watcher implementation which already handles
// both list and watch operations internally. Unlike kubernetes, etcd doesn't need
// separate handling for bookmarks, CRD installation, or WatchList fallbacks.
func (c *etcdV3Client) ListAndWatch(ctx context.Context, l model.ListInterface, handler api.EventHandler, opts ...api.ListWatcherOption) error {
	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(l, handler, opts...),
		client:             c,
	}
	return lw.ListAndWatchWithBackend(ctx, lw)
}

// PerformList implements ListWatchBackend.PerformList for etcd.
func (lw *ListWatcher) PerformList(ctx context.Context) (*model.KVPairList, error) {
	return lw.client.List(ctx, lw.List, "")
}

// CreateWatch implements ListWatchBackend.CreateWatch for etcd.
func (lw *ListWatcher) CreateWatch(ctx context.Context, useWatchList bool) (api.WatchInterface, error) {
	return lw.client.Watch(ctx, lw.List, api.WatchOptions{
		Revision: lw.CurrentRevision,
	})
}

// HandleWatchEvent implements ListWatchBackend.HandleWatchEvent for etcd.
func (lw *ListWatcher) HandleWatchEvent(event api.WatchEvent) error {
	// Try to handle basic events (Added, Modified, Deleted) using common method
	if lw.HandleBasicWatchEvent(event) {
		return nil // continue processing
	}

	// Handle etcd-specific events
	switch event.Type {
	case api.WatchError:
		lw.Logger.WithError(event.Error).Warn("Received watch error from etcd")

		// Increment error count and check if we need a full resync
		if lw.IncrementErrorCount() {
			lw.Logger.Warn("Too many errors at current revision, triggering full resync")
			lw.ResetForFullResync()
		} else {
			// Not yet hit the error threshold, just log and retry
			lw.Logger.Info("Watch of resource finished. Attempting to restart it...")
		}

		return event.Error // stop processing, will recreate watcher

	default:
		lw.Logger.WithField("eventType", event.Type).Warn("Unexpected watch event type")
	}

	return nil
}

// HandleListError implements ListWatchBackend.HandleListError for etcd.
// etcd uses generic error handling for all list errors.
func (lw *ListWatcher) HandleListError(err error) {
	lw.GenericListWatcher.HandleListError(err)
}

// HandleWatchError implements ListWatchBackend.HandleWatchError for etcd.
func (lw *ListWatcher) HandleWatchError(err error) {
	lw.GenericListWatcher.HandleWatchError(err)
}

// PerformInitialSync implements ListWatchBackend.PerformInitialSync for etcd.
// etcd uses traditional List+Watch mode: list all resources first, then watch for changes.
func (lw *ListWatcher) PerformInitialSync(ctx context.Context, g *api.GenericListWatcher, useWatchList bool) error {
	return g.PerformListSync(ctx, lw)
}
