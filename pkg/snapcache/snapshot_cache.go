// Copyright (c) 2017 Tigera, Inc. All rights reserved.
//
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

package snapcache

import (
	"context"
	"sync"
	"sync/atomic"
	"unsafe"

	log "github.com/Sirupsen/logrus"
	"github.com/Workiva/go-datastructures/trie/ctrie"

	"time"

	"github.com/prometheus/client_golang/prometheus"

	"reflect"

	"github.com/projectcalico/typha/pkg/jitter"
	"github.com/projectcalico/typha/pkg/syncproto"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
)

const defaultMaxBatchSize = 100

var (
	summaryUpdateSize = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_update_size",
		Help: "Number of KVs recorded in each breadcrumb.",
	})
	gaugeCurrentSequenceNumber = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "typha_snapshot_seq_number",
		Help: "Current (server-local) sequence number; number of snapshot deltas processed.",
	})
	counterBreadcrumbNonBlock = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "typha_breadcrumb_non_block",
		Help: "Count of the number of times Typha got the next Breadcrumb without blocking.",
	})
	counterBreadcrumbBlock = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "typha_breadcrumb_block",
		Help: "Count of the number of times Typha got the next Breadcrumb after blocking.",
	})
)

func init() {
	prometheus.MustRegister(summaryUpdateSize)
	prometheus.MustRegister(gaugeCurrentSequenceNumber)
	prometheus.MustRegister(counterBreadcrumbNonBlock)
	prometheus.MustRegister(counterBreadcrumbBlock)
}

// SnapshotCache consumes updates from the Syncer API and caches them in the form of a series of
// Breadcrumb objects.  Each Breadcrumb (conceptually) contains the complete snapshot of the
// datastore at the revision it was created as well as a list of deltas from the previous snapshot.
// A client that wants to keep in sync can get the current Breadcrumb, process the key-value pairs
// that it contains, then walk forward through the linked list of Breadcrumb objects, processing
// only the deltas.
//
// The Breadcrumb object provides a Next() method, which returns the next Breadcrumb in the
// sequence, blocking until it is available if required.
//
// Keys and values are stored in their serialized form so that each request handling thread
// has less work to do.
//
// Implementation
//
// To avoid the overhead of taking a complete copy of the state for each Breadcrumb, we use a Ctrie,
// which supports efficient, concurrent-read-safe snapshots.  The main thread of the SnapshotCache
// processes updates sequentially, updating the Ctrie.  After processing a batch of updates, the
// main thread generates a new Breadcrumb object with a read-only snapshot of the Ctrie along with
// the list of deltas.
//
// Each Breadcrumb object contains a pointer to the next Breadcrumb, which is filled in using an
// atomic write once it is available.  This allows each client to follow the linked list of
// Breadcrumb without blocking until it reaches the end of the list (i.e. until it has "caught up").
// When it reaches the end of the list, the Next() method blocks on a global condition variable,
// which is Broadcast() by the main thread once the next snapshot is available.
//
// Why not use channels to fan out to the clients?  I think it'd be more tricky to make robust and
// non-blocking:  We'd need to keep a list of channels to send to (one per client); the
// book-keeping around adding/removing from that list is a little fiddly and we'd need to
// iterate over the list (which may be slow) to send the updates to each client.  If any of the
// clients were blocked, we'd need to selectively skip channels (else we'd block all clients due
// to one slow client) and keep track of what we'd sent to each channel.  All doable but, I think,
// more fiddly than using a non-blocking linked list and a condition variable and letting each
// client look after itself.
type SnapshotCache struct {
	config Config

	inputC chan interface{}

	pendingStatus  api.SyncStatus
	pendingUpdates []api.Update

	kvs               *ctrie.Ctrie
	breadcrumbCond    *sync.Cond
	currentBreadcrumb unsafe.Pointer

	wakeUpTicker *jitter.Ticker
}

type Config struct {
	MaxBatchSize int
}

func New(config Config) *SnapshotCache {
	if config.MaxBatchSize <= 0 {
		log.WithFields(log.Fields{
			"value":   config.MaxBatchSize,
			"default": defaultMaxBatchSize,
		}).Info("Defaulting MaxBatchSize.")
		config.MaxBatchSize = defaultMaxBatchSize
	}
	kvs := ctrie.New(nil /*default hash factory*/)
	cond := sync.NewCond(&sync.Mutex{})
	snap := &Breadcrumb{
		Timestamp: time.Now(),
		nextCond:  cond,
		KVs:       kvs.ReadOnlySnapshot(),
	}
	return &SnapshotCache{
		config: config,
		inputC:            make(chan interface{}, config.MaxBatchSize*2),
		breadcrumbCond:    cond,
		kvs:               kvs,
		currentBreadcrumb: (unsafe.Pointer)(snap),
		wakeUpTicker:      jitter.NewTicker(10*time.Second, time.Second),
	}
}

// CurrentBreadcrumb returns the current Breadcrumb, which contains a snapshot of the datastore
// at the time it was created and a method to wait for the next Breadcrumb to be dropped. It is
// safe to call from any goroutine.
func (c *SnapshotCache) CurrentBreadcrumb() *Breadcrumb {
	return (*Breadcrumb)(atomic.LoadPointer(&c.currentBreadcrumb))
}

// OnStatusUpdated implements the SyncerCallbacks API.  It shouldn't be called directly.
func (c *SnapshotCache) OnStatusUpdated(status api.SyncStatus) {
	c.inputC <- status
}

// OnUpdates implements the SyncerCallbacks API.  It shouldn't be called directly.
func (c *SnapshotCache) OnUpdates(updates []api.Update) {
	if len(updates) == 0 {
		log.Debug("Ignoring 0-length update")
		return
	}
	c.inputC <- updates
}

// Start starts the cache's main loop in a background goroutine.
func (c *SnapshotCache) Start(ctx context.Context) {
	go c.loop(ctx)
}

func (c *SnapshotCache) loop(ctx context.Context) {
	for {
		// First, block, waiting for updates and batch them up in our pendingXXX fields.
		// This will opportunistically slurp up a limited number of pending updates.
		if err := c.fillBatchFromInputQueue(ctx); err != nil {
			return
		}
		// Then publish the updates in new Breadcrumb(s).
		c.publishBreadcrumbs()
	}
}

// fillBatchFromInputQueue waits for some input on the input channel, then opportunistically
// pulls as much as possible from the channel.  Input is stored in the pendingXXX fields for
// the next stage of processing.
func (c *SnapshotCache) fillBatchFromInputQueue(ctx context.Context) error {
	batchSize := 0
	storePendingUpdate := func(obj interface{}) {
		switch obj := obj.(type) {
		case api.SyncStatus:
			log.WithField("status", obj).Info("Received status update message from datastore.")
			c.pendingStatus = obj
		case []api.Update:
			log.WithField("numUpdates", len(obj)).Debug("Received updates.")
			c.pendingUpdates = append(c.pendingUpdates, obj...)
		default:
			log.WithField("obj", obj).Panic("Unexpected object")
		}
		batchSize++
	}

	log.Debug("Waiting for next input...")
	select {
	case obj := <-c.inputC:
		log.WithField("update", obj).Debug("Got first update, peeking...")
		storePendingUpdate(obj)
	batchLoop:
		for batchSize < c.config.MaxBatchSize {
			select {
			case obj = <-c.inputC:
				storePendingUpdate(obj)
			case <-ctx.Done():
				return ctx.Err()
			default:
				break batchLoop
			}
		}
		log.WithField("numUpdates", batchSize).Debug("Finished reading batch.")
	case <-ctx.Done():
		log.WithError(ctx.Err()).Info("Context is done. Stopping.")
	case <-c.wakeUpTicker.C:
		// Workaround the fact that go doesn't have a timeout on Cond.Wait().  Periodically
		// wake all the clients so they can check if their Context is done.
		log.Debug("Waking all clients.")
		c.breadcrumbCond.Broadcast()
	}
	return ctx.Err()
}

// publishBreadcrumbs sends a series of Breadcrumbs, draining the pending updates list.
func (c *SnapshotCache) publishBreadcrumbs() {
	for {
		c.publishBreadcrumb()
		if len(c.pendingUpdates) == 0 {
			break
		}
	}
}

// publishBreadcrumb updates the master Ctrie and publishes a new Breadcrumb containing a read-only
// snapshot of the Ctrie and the deltas from this batch.
func (c *SnapshotCache) publishBreadcrumb() {
	var updates []api.Update
	var lastUpdate bool
	if len(c.pendingUpdates) > c.config.MaxBatchSize {
		updates = c.pendingUpdates[:c.config.MaxBatchSize]
		c.pendingUpdates = c.pendingUpdates[c.config.MaxBatchSize:]
	} else {
		updates = c.pendingUpdates
		c.pendingUpdates = c.pendingUpdates[:0]
		lastUpdate = true
	}

	// Create the new crumb.
	oldCrumb := c.CurrentBreadcrumb()
	newCrumb := &Breadcrumb{
		SequenceNumber: oldCrumb.SequenceNumber + 1,
		Timestamp:      time.Now(),
		SyncStatus:     oldCrumb.SyncStatus,
		nextCond:       c.breadcrumbCond,
		Updates:        make([]syncproto.SerializedUpdate, 0, len(updates)),
	}
	if lastUpdate {
		// Only update the status if this is the last message in the batch, otherwise
		// we might tell the client that we're in sync too soon.
		newCrumb.SyncStatus = c.pendingStatus
	}
	// Update the main trie and record the updates in the new crumb.
	for _, kv := range updates {
		// Pre-serialise the KV so that we only serialise once per update instead of once
		// for each client.
		newUpd, err := syncproto.SerializeUpdate(kv)
		if err != nil {
			log.WithError(err).WithField("kv", kv).Error(
				"Bug: dropping unserializable KV")
			continue
		}
		// Update the master KV map.
		keyAsBytes := []byte(newUpd.Key)
		oldUpd, exists := c.kvs.Lookup(keyAsBytes)
		if newUpd.Value == nil {
			if !exists {
				continue
			}
			c.kvs.Remove(keyAsBytes)
		} else {
			if exists && reflect.DeepEqual(oldUpd, newUpd) {
				continue
			}
			c.kvs.Insert(keyAsBytes, newUpd)
		}

		// Record the update in the new Breadcrumb so that clients following the chain of
		// Breadcrumb can apply it as a delta.
		newCrumb.Updates = append(newCrumb.Updates, newUpd)
	}
	summaryUpdateSize.Observe(float64(len(newCrumb.Updates)))
	// Add the new read-only snapshot to the new crumb.
	newCrumb.KVs = c.kvs.ReadOnlySnapshot()

	// Replace the Breadcrumb and link the old Breadcrumb to the new so that clients can follow
	// the trail.
	log.WithField("seqNo", oldCrumb.SequenceNumber).Debug("Acquiring Breadcrumb lock")
	c.breadcrumbCond.L.Lock()
	log.WithField("seqNo", oldCrumb.SequenceNumber).Debug("Acquired Breadcrumb lock")
	atomic.StorePointer(&(oldCrumb.next), (unsafe.Pointer)(newCrumb))
	atomic.StorePointer(&c.currentBreadcrumb, (unsafe.Pointer)(newCrumb))
	c.breadcrumbCond.L.Unlock()
	// Then wake up any watching clients.  Note: Go's Cond doesn't require us to hold the lock
	// while calling Broadcast.
	log.WithField("seqNo", newCrumb.SequenceNumber).Debug("Broadcasting new Breadcrumb")
	c.breadcrumbCond.Broadcast()
	gaugeCurrentSequenceNumber.Set(float64(newCrumb.SequenceNumber))
}

type Breadcrumb struct {
	SequenceNumber uint64
	Timestamp      time.Time

	KVs        *ctrie.Ctrie
	Updates    []syncproto.SerializedUpdate
	SyncStatus api.SyncStatus

	nextCond *sync.Cond
	next     unsafe.Pointer
}

func (s *Breadcrumb) Next(ctx context.Context) (*Breadcrumb, error) {
	// Opportunistically grab the next Breadcrumb with an atomic read; this avoids lock
	// contention if the next Breadcrumb is already available.
	next := (*Breadcrumb)(atomic.LoadPointer(&s.next))
	if next != nil {
		counterBreadcrumbNonBlock.Inc()
		return next, nil
	}

	// Next snapshot isn't available yet, block on the condition variable and wait for it.
	counterBreadcrumbBlock.Inc()
	s.nextCond.L.Lock()
	for ; next == nil && ctx.Err() == nil; next = (*Breadcrumb)(atomic.LoadPointer(&s.next)) {
		s.nextCond.Wait()
	}
	s.nextCond.L.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return next, nil
}
