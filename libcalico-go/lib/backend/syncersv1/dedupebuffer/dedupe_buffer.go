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
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// DedupeBuffer buffer implements the syncer callbacks API on its
// input, and calls another syncer callback on its output. In-between it
// maintains an in-order queue of KV updates and a tracking map to record what
// is in the queue.
//
// If an update comes in for a key that already has a value in the queue then
// the value in the queue is replaced with the updated KV.
//
// This can cause reordering between different resources (which is allowed
// by the syncer API) but it ensures that the amount of KVs in flight is
// bounded to the total size of the datastore even under substantial overload.
// The effect is that the client will periodically "skip ahead" to the more
// recent state of the datastore without seeing intermediate states.
type DedupeBuffer struct {
	lock sync.Mutex
	cond *sync.Cond

	// keyToPendingUpdate holds an entry for each updateWithStringKey in the
	// pendingUpdates queue
	keyToPendingUpdate    map[string]*list.Element
	peakPendingUpdatesLen int

	// liveResourceKeys Contains an entry for every key that we have sent to
	// the consumer and that we have not subsequently sent a deletion for.
	liveResourceKeys set.Set[string]
	// pendingUpdates is the queue of updates that we want to send to the
	// consumer.  We use a linked list so that we can remove items from
	// the middle if they are deleted before making it off the queue.
	pendingUpdates list.List // Mix of api.SyncStatus and updateWithStringKey.

	mostRecentStatusReceived api.SyncStatus
	stopped                  bool
}

func New() *DedupeBuffer {
	d := &DedupeBuffer{
		keyToPendingUpdate: map[string]*list.Element{},
		liveResourceKeys:   set.New[string](),
	}
	d.cond = sync.NewCond(&d.lock)
	return d
}

// OnStatusUpdated queues a status update to be sent to the sink.
func (d *DedupeBuffer) OnStatusUpdated(status api.SyncStatus) {
	d.lock.Lock()
	defer d.lock.Unlock()

	// Statuses are idempotent so skip sending if the latest one in the queue
	// was the same.
	if d.mostRecentStatusReceived == status {
		return
	}
	d.mostRecentStatusReceived = status

	// If the last message on the queue was a status message then replace it.
	// this prevents us from growing the queue without bound if status is
	// flapping. We can add at most one status to the queue for each
	// non-status update and the number of non-status updates is bounded by
	// the size of the datastore.
	if back := d.pendingUpdates.Back(); back != nil {
		if _, ok := back.Value.(api.SyncStatus); ok {
			back.Value = status
			return
		}
	}

	// Add the status to the queue.
	queueWasEmpty := d.pendingUpdates.Len() == 0
	d.pendingUpdates.PushBack(status)
	if queueWasEmpty {
		// Only need to signal when the first item goes on the queue.
		d.cond.Signal()
	}
}

// OnUpdates adds a slice of updates to the buffer and does housekeeping to
// deduplicate in-flight updates to the same keys.  It should only block for
// short periods even if the downstream sink blocks for a long time.
func (d *DedupeBuffer) OnUpdates(updates []api.Update) {
	d.OnUpdatesKeysKnown(updates, nil)
}

// OnUpdatesKeysKnown is like OnUpdates, but it allows for the pre-serialised
// keys of the KV pairs to be passed in.  If an entry in keys is "" or if keys
// is shorter than updates the key will be computed.
//
// The updates and keys slices are not retained.
func (d *DedupeBuffer) OnUpdatesKeysKnown(updates []api.Update, keys []string) {
	debug := log.IsLevelEnabled(log.DebugLevel)
	if debug {
		log.WithField("numUpdates", len(updates)).Debug("Updates received")
	}
	d.lock.Lock()
	defer d.lock.Unlock()
	if debug {
		log.WithFields(log.Fields{
			"queueLen": d.pendingUpdates.Len(),
		}).Debug("Acquired lock")
	}

	queueWasEmpty := d.pendingUpdates.Len() == 0
	for i, u := range updates {
		var key string
		if i < len(keys) {
			// Have a cached key.
			key = keys[i]
		}
		if key == "" {
			// No key provided, calculate it.
			var err error
			key, err = model.KeyToDefaultPath(u.Key)
			if err != nil {
				// Shouldn't happen, we get our keys from Typha which has already
				// encoded them once!
				log.WithError(err).WithField("key", u.Key).Error(
					"Failed to generate default path for key.  Will skip this update.")
				continue
			}
		}

		if element, ok := d.keyToPendingUpdate[key]; ok {
			// Already got an in-flight update for this key.
			if u.Value == nil && !d.liveResourceKeys.Contains(key) {
				// This is a deletion, but the key in question never made it
				// off the queue, remove it entirely.
				if debug {
					log.WithField("key", key).Debug("Key deleted before being sent.")
				}
				delete(d.keyToPendingUpdate, key)
				d.pendingUpdates.Remove(element)
			} else {
				// Update to a key that's already on the queue, swap in the
				// most recent value.
				if debug {
					log.WithField("key", key).Debug("Key updated before being sent.")
				}
				usk := element.Value.(updateWithStringKey)
				usk.update = u
				element.Value = usk
			}
		} else {
			// No in-flight entry for this key.  Add to queue and record that
			// it's in flight.
			if debug {
				log.WithField("key", key).Debug("No in flight value for key, adding to queue.")
			}
			element = d.pendingUpdates.PushBack(updateWithStringKey{
				key:    key,
				update: u,
			})
			d.keyToPendingUpdate[key] = element
			d.peakPendingUpdatesLen = max(len(d.keyToPendingUpdate), d.peakPendingUpdatesLen)
		}
	}
	queueNowEmpty := d.pendingUpdates.Len() == 0
	if queueWasEmpty && !queueNowEmpty {
		// Only need to signal when the first item goes on the queue.
		if debug {
			log.Debug("Queue transitioned to non-empty; signalling.")
		}
		d.cond.Signal()
	}
}

func (d *DedupeBuffer) SendToSinkForever(sink api.SyncerCallbacks) {
	d.lock.Lock()
	defer d.lock.Unlock()
	for !d.stopped {
		d.sendNextBatchToSinkLockHeld(sink)
	}
}

func (d *DedupeBuffer) Stop() {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.stopped = true
	d.cond.Signal()
}

type updateWithStringKey struct {
	key    string
	update api.Update
}

var ErrEmptyQueue = fmt.Errorf("queue is empty")

// sendNextBatchToSinkNoBlock is intended for use in tests, to allow one
// batch of updates to be processed synchronously.  It returns ErrEmptyQueue
// if there's nothing to process.
func (d *DedupeBuffer) sendNextBatchToSinkNoBlock(sink api.SyncerCallbacks) error {
	d.lock.Lock()
	defer d.lock.Unlock()
	if d.pendingUpdates.Len() == 0 {
		return ErrEmptyQueue
	}
	d.sendNextBatchToSinkLockHeld(sink)
	return nil
}

func (d *DedupeBuffer) sendNextBatchToSinkLockHeld(sink api.SyncerCallbacks) {
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

		buf = d.pullNextBatch(buf, batchSize)
		d.dropLockAndSendBatch(sink, buf)
	}
}

func (d *DedupeBuffer) pullNextBatch(buf []any, batchSize int) []any {
	// Grab a batch of updates off the queue.
	buf = buf[:0]
	for len(buf) < batchSize && d.pendingUpdates.Len() > 0 {
		first := d.pendingUpdates.Front()
		buf = append(buf, first.Value)
		d.pendingUpdates.Remove(first)
		if u, ok := first.Value.(updateWithStringKey); ok {
			key := u.key
			delete(d.keyToPendingUpdate, key)
			if len(d.keyToPendingUpdate) == 0 && d.peakPendingUpdatesLen > 100 {
				// Map blocks never get freed when a map is scaled down.
				// https://github.com/golang/go/issues/20135
				// Opportunistically free the map when it's empty. This can
				// free a good amount of RAM after loading a large snapshot.
				d.keyToPendingUpdate = map[string]*list.Element{}
				d.peakPendingUpdatesLen = 0
			}
			// Update liveResourceKeys now, before we drop the lock.  Once we drop
			// the lock we're committed to sending these keys.
			if u.update.Value == nil {
				d.liveResourceKeys.Discard(key)
			} else {
				d.liveResourceKeys.Add(key)
			}
		}
	}
	return buf
}

func (d *DedupeBuffer) dropLockAndSendBatch(sink api.SyncerCallbacks, buf []any) {
	// RELEASE(!) lock while we send updates downstream.  We may block in this
	// method for a long time if downstream is slow.  Meanwhile, we want the
	// sender to be able to be able to add more items to the queue and to
	// be able to do the dedupe work if needed.
	d.lock.Unlock()
	defer d.lock.Lock()

	debug := log.IsLevelEnabled(log.DebugLevel)
	updates := make([]api.Update, 0, len(buf))
	for _, msg := range buf {
		switch msg := msg.(type) {
		case updateWithStringKey:
			updates = append(updates, msg.update)
		case api.SyncStatus:
			if len(updates) > 0 {
				if debug {
					log.WithField("updates", updates).Debug("Sending updates (pre status update)")
				}
				sink.OnUpdates(updates)
				updates = updates[len(updates):] // Re-slice to end so we don't share storage.
			}
			if debug {
				log.WithField("status", msg).Debug("Sending status update")
			}
			sink.OnStatusUpdated(msg)
		default:
			log.WithField("msg", msg).Panicf("Unexpected message on queue: %T", msg)
		}
	}
	if len(updates) > 0 {
		if debug {
			log.WithField("updates", updates).Debug("Sending updates")
		}
		sink.OnUpdates(updates)
		updates = updates[len(updates):] // Re-slice to end so we don't share storage.
	}
}

var _ api.SyncerCallbacks = (*DedupeBuffer)(nil)
