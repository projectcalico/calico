// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dedupebuffer

import (
	"container/list"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// DeduplicatingBuffer buffer implements the syncer callbacks API on its
// input, and calls another syncer callback on its output. In-between it
// maintains an in-order queue of KV updates and a tracking map to record what
// is in the queue.
//
// If an update comes in for a key that already has a value in the queue then
// the value in the queue is replaced with the updated KV.
//
// This can cause reordering (which is allowed by the syncer API) but it
// ensures that the amount of KVs in flight is bounded to the total size of
// the datastore even under substantial overload. The effect is that the
// client will periodically "skip ahead" to the more recent state of the
// datatstore without seeing intermediate states.
type DeduplicatingBuffer struct {
	lock sync.Mutex
	cond *sync.Cond

	// keyToPendingUpdate holds an entry for each updateWithStringKey in the
	// pendingUpdates queue
	keyToPendingUpdate map[string]*list.Element
	sentKeys           set.Set[string]
	pendingUpdates     list.List // Mix of api.SyncStatus and updateWithStringKey.

	mostRecentStatus api.SyncStatus
	stopped          bool
}

func New() *DeduplicatingBuffer {
	d := &DeduplicatingBuffer{
		keyToPendingUpdate: map[string]*list.Element{},
		sentKeys:           set.New[string](),
	}
	d.cond = sync.NewCond(&d.lock)
	return d
}

// OnStatusUpdated queues a status update to be sent to the sink.
func (d *DeduplicatingBuffer) OnStatusUpdated(status api.SyncStatus) {
	d.lock.Lock()
	defer d.lock.Unlock()

	// Statuses are idempotent so skip sending if the latest one in the queue
	// was the same.
	if d.mostRecentStatus == status {
		return
	}

	// If the last message on the queue was a status message then replace it.
	// this prevents us from growing the queue without bound if status is
	// flapping. We can add at most one status to the queue for each
	// non-status update and the number of non-status updates is bounded by
	// the size of the datastore.
	if back := d.pendingUpdates.Back(); back != nil {
		if _, ok := back.Value.(api.SyncStatus); ok {
			back.Value = status
			d.mostRecentStatus = status
			return
		}
	}

	// Add the status to the queue.
	queueWasEmpty := d.pendingUpdates.Len() == 0
	d.pendingUpdates.PushBack(status)
	d.mostRecentStatus = status
	if queueWasEmpty {
		// Only need to signal when the first item goes on the queue.
		d.cond.Signal()
	}
}

// OnUpdates adds a slice of updates to the buffer and does housekeeping to
// deduplicate in-flight updates to the same keys.  It should only block for
// short periods even if the downstream sink blocks for a long time.
func (d *DeduplicatingBuffer) OnUpdates(updates []api.Update) {
	d.OnUpdatesKeysKnown(updates, nil)
}

// OnUpdatesKeysKnown is like OnUpdates, but it allows for the pre-serialised
// keys of the KV pairs to be passed in.  If an entry in keys is "" or if keys
// is shorter than updates the key will be computed.
//
// The updates and keys slices are not retained.
func (d *DeduplicatingBuffer) OnUpdatesKeysKnown(updates []api.Update, keys []string) {
	d.lock.Lock()
	defer d.lock.Unlock()

	queueWasEmpty := d.pendingUpdates.Len() == 0
	for i, u := range updates {
		key := keys[i]
		if key == "" {
			var err error
			keys[i], err = model.KeyToDefaultPath(u.Key)
			if err != nil {
				log.WithError(err).WithField("key", u.Key).Error(
					"Failed to generate default path for key.  Will skip this update.")
				keys[i] = ""
			}
			continue
		}

		if element, ok := d.keyToPendingUpdate[key]; ok {
			// Already got an in-flight update for this key.
			if u.Value == nil && !d.sentKeys.Contains(key) {
				// This is a deletion, but the key in question never made it
				// off the queue, remove it entirely.
				delete(d.keyToPendingUpdate, key)
				d.pendingUpdates.Remove(element)
			} else {
				// Update to a key that's already on the queue, swap in the
				// most recent value.
				element.Value = u
			}
		} else {
			// No in-flight entry for this key.  Add to queue and record that
			// it's in flight.
			element = d.pendingUpdates.PushBack(updateWithStringKey{
				key:    key,
				update: u,
			})
			d.keyToPendingUpdate[key] = element
		}
	}
	queueNowEmpty := d.pendingUpdates.Len() == 0
	if queueWasEmpty && !queueNowEmpty {
		// Only need to signal when the first item goes on the queue.
		d.cond.Signal()
	}
}

func (d *DeduplicatingBuffer) SendToSinkForever(sink api.SyncerCallbacks) {
	for !d.stopped {
		d.sendNextBatchToSink(sink)
	}
}

func (d *DeduplicatingBuffer) Stop() {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.stopped = true
	d.cond.Signal()
}

type updateWithStringKey struct {
	key    string
	update api.Update
}

func (d *DeduplicatingBuffer) sendNextBatchToSink(sink api.SyncerCallbacks) {
	d.lock.Lock()
	defer d.lock.Unlock()
	for d.pendingUpdates.Len() == 0 {
		if d.stopped {
			return
		}
		d.cond.Wait()
	}
	const batchSize = 100
	buf := make([]any, 0, batchSize)
	for d.pendingUpdates.Len() > 0 {
		if d.stopped {
			return
		}

		// Grab a batch of updates off the queue.
		buf = buf[:0]
		for i := 0; i < batchSize && d.pendingUpdates.Len() > 0; i++ {
			first := d.pendingUpdates.Front()
			value := first.Value
			buf = append(buf, value)
			d.pendingUpdates.Remove(first)
			if u, ok := value.(updateWithStringKey); ok {
				key := u.key
				delete(d.keyToPendingUpdate, key)
				// Update sentKeys now, before we drop the lock.  Once we drop
				// the lock we're committed to sending these keys.
				if u.update.Value == nil {
					d.sentKeys.Discard(key)
				} else {
					d.sentKeys.Add(key)
				}
			}
		}

		// Release lock while we send them downstream.
		d.lock.Unlock()

		updates := make([]api.Update, 0, len(buf))
		for _, msg := range buf {
			switch msg := msg.(type) {
			case updateWithStringKey:
				updates = append(updates, msg.update)
			case api.SyncStatus:
				if len(updates) > 0 {
					sink.OnUpdates(updates)
					updates = updates[len(updates):] // Re-slice to end so we don't share storage.
				}
				sink.OnStatusUpdated(msg)
			}
		}
		if len(updates) > 0 {
			sink.OnUpdates(updates)
			updates = updates[len(updates):] // Re-slice to end so we don't share storage.
		}

		d.lock.Lock()
	}
}

var _ api.SyncerCallbacks = (*DeduplicatingBuffer)(nil)
