// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
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
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/btree"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
	"github.com/projectcalico/calico/typha/pkg/jitter"
	"github.com/projectcalico/calico/typha/pkg/promutils"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

const (
	defaultMaxBatchSize   = 100
	defaultWakeUpInterval = time.Second
)

var (
	syncerLabel = []string{"syncer"}

	gaugeVecCurrentSequenceNumber = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "typha_breadcrumb_seq_number",
		Help: "Current (server-local) sequence number; number of snapshot deltas processed.",
	}, syncerLabel)
	counterVecBreadcrumbNonBlock = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "typha_breadcrumb_non_block",
		Help: "Count of the number of times Typha got the next Breadcrumb without blocking.",
	}, syncerLabel)
	counterVecBreadcrumbBlock = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "typha_breadcrumb_block",
		Help: "Count of the number of times Typha got the next Breadcrumb after blocking.",
	}, syncerLabel)
	counterVecUpdatesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "typha_updates_total",
		Help: "Total number of updates received from the Syncer.",
	}, syncerLabel)
	counterVecUpdatesSkipped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "typha_updates_skipped",
		Help: "Total number of updates skipped as duplicates.",
	}, syncerLabel)
	gaugeVecSnapshotSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "typha_cache_size",
		Help: "Current number of key/value pairs contained in the cache of the datastore.",
	}, syncerLabel)
)

func init() {
	prometheus.MustRegister(gaugeVecCurrentSequenceNumber)
	promutils.PreCreateGaugePerSyncer(gaugeVecCurrentSequenceNumber)
	prometheus.MustRegister(gaugeVecSnapshotSize)
	promutils.PreCreateGaugePerSyncer(gaugeVecSnapshotSize)
	prometheus.MustRegister(counterVecBreadcrumbNonBlock)
	promutils.PreCreateCounterPerSyncer(counterVecBreadcrumbNonBlock)
	prometheus.MustRegister(counterVecBreadcrumbBlock)
	promutils.PreCreateCounterPerSyncer(counterVecBreadcrumbBlock)
	prometheus.MustRegister(counterVecUpdatesTotal)
	promutils.PreCreateCounterPerSyncer(counterVecUpdatesTotal)
	prometheus.MustRegister(counterVecUpdatesSkipped)
	promutils.PreCreateCounterPerSyncer(counterVecUpdatesSkipped)
}

// Cache consumes updates from the Syncer API and caches them in the form of a series of
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
// # Implementation
//
// To avoid the overhead of taking a complete copy of the state for each Breadcrumb, we use a B-tree,
// which supports efficient, concurrent-read-safe snapshots.  The main thread of the SnapshotCache
// processes updates sequentially, updating the B-tree.  After processing a batch of updates, the
// main thread generates a new Breadcrumb object with a snapshot of the B-tree along with
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
// bookkeeping around adding/removing from that list is a little fiddly and we'd need to
// iterate over the list (which may be slow) to send the updates to each client.  If any of the
// clients were blocked, we'd need to selectively skip channels (else we'd block all clients due
// to one slow client) and keep track of what we'd sent to each channel.  All doable but, I think,
// more fiddly than using a non-blocking linked list and a condition variable and letting each
// client look after itself.
type Cache struct {
	config Config

	inputC chan interface{}

	pendingStatus  api.SyncStatus
	pendingUpdates []api.Update

	// kvs contains the current state of the datastore.  Its keys are the serialized form of our model keys
	// and the values are SerializedUpdate objects.
	kvs *btree.BTreeG[syncproto.SerializedUpdate]
	// breadcrumbCond is the condition variable used to signal when a new breadcrumb is available.
	breadcrumbCond *sync.Cond
	// lastBroadcast is the last time we did a broadcast to wake up breadcrumb followers.
	lastBroadcast time.Time
	// currentBreadcrumb points to the most recent Breadcrumb, which contains the most recent snapshot of kvs.
	// As described above, we use an unsafe.Pointer so we can do opportunistic atomic reads of the value to avoid
	// blocking.
	currentBreadcrumb unsafe.Pointer

	wakeUpTicker *jitter.Ticker
	healthTicks  <-chan time.Time

	gaugeSnapSize              prometheus.Gauge
	counterUpdatesTotal        prometheus.Counter
	counterUpdatesSkipped      prometheus.Counter
	gaugeCurrentSequenceNumber prometheus.Gauge
	counterBreadcrumbBlock     prometheus.Counter
	counterBreadcrumbNonBlock  prometheus.Counter
	summaryUpdateSize          prometheus.Summary

	// Done is created by Start() and closed when the main loop exits.
	Done chan struct{}
}

const (
	healthInterval = 10 * time.Second
)

type healthAggregator interface {
	RegisterReporter(name string, reports *health.HealthReport, timeout time.Duration)
	Report(name string, report *health.HealthReport)
}

type Config struct {
	MaxBatchSize     int
	WakeUpInterval   time.Duration
	HealthAggregator healthAggregator
	Name             string
	HealthName       string
}

func (config *Config) ApplyDefaults() {
	if config.MaxBatchSize <= 0 {
		log.WithFields(log.Fields{
			"value":   config.MaxBatchSize,
			"default": defaultMaxBatchSize,
		}).Info("Defaulting MaxBatchSize.")
		config.MaxBatchSize = defaultMaxBatchSize
	}
	if config.WakeUpInterval <= 0 {
		log.WithFields(log.Fields{
			"value":   config.WakeUpInterval,
			"default": defaultWakeUpInterval,
		}).Info("Defaulting WakeUpInterval.")
		config.WakeUpInterval = defaultWakeUpInterval
	}
	if config.HealthName == "" {
		if config.Name == "" {
			config.HealthName = "cache"
		} else if strings.HasSuffix(config.Name, "cache") {
			config.HealthName = config.Name
		} else {
			config.HealthName = config.Name + "-cache"
		}
	}
	if config.Name == "" {
		config.Name = "cache"
	}
}

func New(config Config) *Cache {
	config.ApplyDefaults()
	kvs := btree.NewG[syncproto.SerializedUpdate](2, func(a, b syncproto.SerializedUpdate) bool { return a.Key < b.Key })
	cond := sync.NewCond(&sync.Mutex{})

	c := &Cache{
		config:         config,
		inputC:         make(chan interface{}, config.MaxBatchSize*2),
		breadcrumbCond: cond,
		kvs:            kvs,
		wakeUpTicker:   jitter.NewTicker(config.WakeUpInterval, config.WakeUpInterval/10),
		healthTicks:    time.NewTicker(healthInterval).C,
	}

	var err error
	c.gaugeSnapSize, err = gaugeVecSnapshotSize.GetMetricWithLabelValues(config.Name)
	if err != nil {
		log.WithError(err).Panic("Bug: failed to get Prometheus gauge.")
	}
	c.counterUpdatesTotal = counterVecUpdatesTotal.WithLabelValues(config.Name)
	c.counterUpdatesSkipped = counterVecUpdatesSkipped.WithLabelValues(config.Name)
	c.gaugeCurrentSequenceNumber = gaugeVecCurrentSequenceNumber.WithLabelValues(config.Name)
	c.counterBreadcrumbNonBlock = counterVecBreadcrumbNonBlock.WithLabelValues(config.Name)
	c.counterBreadcrumbBlock = counterVecBreadcrumbBlock.WithLabelValues(config.Name)
	// No vector version of summary so we use an explicit label.   promutils.GetOrRegister avoids panics in UT
	// where the same cache is recreated.
	c.summaryUpdateSize = promutils.GetOrRegister(cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_breadcrumb_size",
		Help: "Number of KVs recorded in each breadcrumb.",
		ConstLabels: map[string]string{
			"syncer": config.Name,
		},
	}))

	snap := &Breadcrumb{
		Timestamp:                 time.Now(),
		nextCond:                  cond,
		KVs:                       kvs.Clone(),
		counterBreadcrumbBlock:    c.counterBreadcrumbBlock,
		counterBreadcrumbNonBlock: c.counterBreadcrumbNonBlock,
	}
	c.currentBreadcrumb = (unsafe.Pointer)(snap)

	if config.HealthAggregator != nil {
		config.HealthAggregator.RegisterReporter(config.HealthName, &health.HealthReport{Live: true, Ready: true}, healthInterval*2)
	}
	c.reportHealth()
	return c
}

// CurrentBreadcrumb returns the current Breadcrumb, which contains a snapshot of the datastore
// at the time it was created and a method to wait for the next Breadcrumb to be dropped. It is
// safe to call from any goroutine.
func (c *Cache) CurrentBreadcrumb() *Breadcrumb {
	return (*Breadcrumb)(atomic.LoadPointer(&c.currentBreadcrumb))
}

// OnStatusUpdated implements the SyncerCallbacks API.  It shouldn't be called directly.
func (c *Cache) OnStatusUpdated(status api.SyncStatus) {
	c.inputC <- status
}

// OnUpdates implements the SyncerCallbacks API.  It shouldn't be called directly.
func (c *Cache) OnUpdates(updates []api.Update) {
	if len(updates) == 0 {
		log.Debug("Ignoring 0-length update")
		return
	}
	c.inputC <- updates
}

// Start starts the cache's main loop in a background goroutine.
func (c *Cache) Start(ctx context.Context) {
	c.Done = make(chan struct{})
	go c.loop(ctx, c.Done)
}

func (c *Cache) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	for {
		// First, block, waiting for updates and batch them up in our pendingXXX fields.
		// This will opportunistically slurp up a limited number of pending updates.
		if err := c.fillBatchFromInputQueue(ctx); err != nil {
			log.WithError(err).Error("Snapshot main loop exiting.")
			return
		}
		// Then publish the updates in new Breadcrumb(s).
		c.publishBreadcrumbs()
	}
}

// fillBatchFromInputQueue waits for some input on the input channel, then opportunistically
// pulls as much as possible from the channel.  Input is stored in the pendingXXX fields for
// the next stage of processing.
func (c *Cache) fillBatchFromInputQueue(ctx context.Context) error {
	somethingToSend := false
	batchSize := 0
	storePendingUpdate := func(obj interface{}) {
		somethingToSend = true
		switch obj := obj.(type) {
		case api.SyncStatus:
			log.WithField("status", obj).Info("Received status update message from datastore.")
			c.pendingStatus = obj
			batchSize++
			// Report health immediately in case our sync status has changed.
			c.reportHealth()
		case []api.Update:
			log.WithField("numUpdates", len(obj)).Debug("Received updates.")
			c.pendingUpdates = append(c.pendingUpdates, obj...)
			batchSize += len(obj)
		default:
			log.WithField("obj", obj).Panic("Unexpected object")
		}
	}

	log.Debug("Waiting for next input...")
	for ctx.Err() == nil && !somethingToSend {
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
					log.WithError(ctx.Err()).Info("Context is done. Stopping.")
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
			// wake all the clients, so they can check if their Context is done.
			if time.Since(c.lastBroadcast) < c.config.WakeUpInterval {
				// Already did a broadcast recently due to minting a real breadcrumb.
				continue
			}
			log.Trace("Waking all clients.")
			c.breadcrumbCond.Broadcast()
			c.lastBroadcast = time.Now()
			// If there are no updates, we want the Prometheus stat to decay
			// to zero.
			c.summaryUpdateSize.Observe(0)
		case <-c.healthTicks:
			c.reportHealth()
		}
	}
	return ctx.Err()
}

func (c *Cache) reportHealth() {
	if c.config.HealthAggregator != nil {
		c.config.HealthAggregator.Report(c.config.HealthName, &health.HealthReport{
			Live:  true,
			Ready: c.pendingStatus == api.InSync,
		})
	}
}

// publishBreadcrumbs sends a series of Breadcrumbs, draining the pending updates list.
func (c *Cache) publishBreadcrumbs() {
	// Always force one call in case we need to send a breadcrumb just to update the sync status.
	c.publishBreadcrumb()

	// Then send anything else we have left.
	for len(c.pendingUpdates) > 0 {
		c.publishBreadcrumb()
	}
}

// publishBreadcrumb updates the master tree and publishes a new Breadcrumb containing a read-only
// snapshot of the tree and the deltas from this batch.
func (c *Cache) publishBreadcrumb() {
	var somethingChanged bool
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
		Deltas:         make([]syncproto.SerializedUpdate, 0, len(updates)),

		counterBreadcrumbBlock:    c.counterBreadcrumbBlock,
		counterBreadcrumbNonBlock: c.counterBreadcrumbNonBlock,
	}
	if lastUpdate && c.pendingStatus != newCrumb.SyncStatus {
		// Only update the status if this is the last message in the batch, otherwise
		// we might tell the client that we're in sync too soon.
		somethingChanged = true
		newCrumb.SyncStatus = c.pendingStatus
	}
	// Update the main trie and record the updates in the new crumb.
	for _, upd := range updates {
		// Update stats.
		c.counterUpdatesTotal.Inc()
		// Pre-serialise the KV so that we only serialise once per update instead of once
		// for each client.
		newUpd, err := syncproto.SerializeUpdate(upd)
		if err != nil {
			log.WithError(err).WithField("upd", upd).Error(
				"Bug: dropping unserializable KV")
			continue
		}
		// Update the master KV map.
		oldUpd, exists := c.kvs.Get(newUpd)
		log.WithFields(log.Fields{
			"oldUpd": oldUpd,
			"newUpd": newUpd,
		}).Debug("Comparing update")
		if upd.Value == nil {
			// This is either a deletion or a validation failure.  We can't skip deletions even if we
			// didn't have that key before because we need to pass through the UpdateType for Felix to
			// correctly calculate its stats.
			c.kvs.Delete(newUpd)
		} else {
			if exists && newUpd.WouldBeNoOp(oldUpd) {
				log.WithField("key", newUpd.Key).Debug("Skipping update to unchanged key")
				c.counterUpdatesSkipped.Inc()
				continue
			}
			// Since the purpose of the snapshot is to hold the initial set of updates to send to Felix at start-of-day,
			// all the updates that it stores should have type UpdateTypeKVNew since they're all new to Felix. Copy
			// the KV and adjust it before storing it in the snapshot.
			updToStore := newUpd
			updToStore.UpdateType = api.UpdateTypeKVNew
			c.kvs.ReplaceOrInsert(updToStore)
		}

		// Record the update in the new Breadcrumb so that clients following the chain of
		// Breadcrumbs can apply it as a delta.
		newCrumb.Deltas = append(newCrumb.Deltas, newUpd)
		somethingChanged = true
	}

	// Even if all updates were filtered out, report that to Prometheus; we
	// want the stat to decay to zero if the event stream is quiet.
	c.summaryUpdateSize.Observe(float64(len(newCrumb.Deltas)))

	if !somethingChanged {
		log.Debug("Skipping Breadcrumb.  No updates to publish.")
		return
	}

	c.gaugeSnapSize.Set(float64(c.kvs.Len()))
	// Add the new read-only snapshot to the new crumb.
	newCrumb.KVs = c.kvs.Clone()

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
	c.lastBroadcast = time.Now()
	c.gaugeCurrentSequenceNumber.Set(float64(newCrumb.SequenceNumber))
}

type Breadcrumb struct {
	SequenceNumber uint64
	Timestamp      time.Time

	KVs        *btree.BTreeG[syncproto.SerializedUpdate]
	Deltas     []syncproto.SerializedUpdate
	SyncStatus api.SyncStatus

	nextCond *sync.Cond
	next     unsafe.Pointer

	counterBreadcrumbNonBlock prometheus.Counter
	counterBreadcrumbBlock    prometheus.Counter
}

func (b *Breadcrumb) Next(ctx context.Context) (*Breadcrumb, error) {
	// Opportunistically grab the next Breadcrumb with an atomic read; this avoids lock
	// contention if the next Breadcrumb is already available.
	next := b.loadNext()
	if next != nil {
		b.counterBreadcrumbNonBlock.Inc()
		return next, nil
	}

	// Next snapshot isn't available yet, block on the condition variable and wait for it.
	b.nextCond.L.Lock()
	for ctx.Err() == nil {
		next = b.loadNext()
		if next != nil {
			break
		}
		b.nextCond.Wait()
	}
	b.nextCond.L.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	b.counterBreadcrumbBlock.Inc()
	return next, nil
}

// loadNext does an atomic load of the next pointer.  It returns nil or the next Breadcrumb.
func (b *Breadcrumb) loadNext() *Breadcrumb {
	return (*Breadcrumb)(atomic.LoadPointer(&b.next))
}
