// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// AggregationBucket is a FlowProvider that represents a bucket of aggregated flows.
var _ FlowProvider = &AggregationBucket{}

// An aggregation bucket represents a bucket of aggregated flows across a time range.
type AggregationBucket struct {
	// The mutex is used to protect access to the bucket's Flows set, which may be
	// modified and accessed by multiple goroutines concurrently.
	sync.RWMutex

	// index is the index of the bucket in the ring.
	index int

	// The start and end time of the bucket.
	StartTime int64
	EndTime   int64

	// pushed indicates whether this bucket has been pushed to the emitter.
	pushed bool

	// LookupFlow is a function that can be used to look up a DiachronicFlow by its key.
	lookupFlow lookupFn

	// Flows contains an indication of the flows that are part of this bucket.
	Flows set.Set[*DiachronicFlow]

	// Tracker for statistics within this bucket.
	stats *statisticsIndex

	// emissions records what each node has already reported into this bucket, so a
	// replayed cache is not counted twice. Nil once no client can replay this far back.
	emissions map[emissionKey]struct{}

	// ready is set when this bucket is sent to any stream, and cleared when this bucket is reset.
	// It can thus be used to determine when a bucket is rolled over between Goldmane deciding to stream it,
	// and the bucket actually being emited. In this case, we should skip streaming the bucket as its contents
	// are no longer valid.
	ready bool
}

func (b *AggregationBucket) AddFlow(flow *types.Flow) {
	b.Lock()
	defer b.Unlock()

	if b.pushed {
		logrus.WithField("flow", flow).Warn("Adding flow to already published bucket")
	}

	if flow == nil {
		logrus.Fatal("BUG: Attempted to add nil flow to bucket")
	}
	if flow.Key == nil {
		logrus.WithField("flow", flow).Fatal("BUG: Attempted to add flow with nil key to bucket")
	}
	if b.lookupFlow == nil {
		logrus.WithField("flow", flow).Fatal("BUG: Attempted to add flow to bucket with no lookup function")
	}
	d := b.lookupFlow(*flow.Key)
	if d == nil {
		logrus.WithField("flow", flow).Fatal("BUG: Attempted to add flow with no corresponding DiachronicFlow")
	}

	// Mark this Flow as part of this bucket.
	b.Flows.Add(d)

	// Track policy stats.
	b.stats.AddFlow(flow)
}

func NewAggregationBucket(start, end time.Time) *AggregationBucket {
	return &AggregationBucket{
		StartTime: start.Unix(),
		EndTime:   end.Unix(),
		Flows:     set.New[*DiachronicFlow](),
		stats:     newStatisticsIndex(),
		emissions: map[emissionKey]struct{}{},
	}
}

// emissionKey identifies one Felix flow log within a bucket. Felix emits on its own window,
// which does not align with the bucket, so a bucket can hold several emissions of one flow.
type emissionKey struct {
	flowID int64
	start  int64
	end    int64
	node   uint32
}

// claimEmission records an emission and reports whether it had not been seen before.
func (b *AggregationBucket) claimEmission(k emissionKey) bool {
	b.Lock()
	defer b.Unlock()

	if b.emissions == nil {
		return true
	}
	if _, seen := b.emissions[k]; seen {
		return false
	}
	b.emissions[k] = struct{}{}
	return true
}

// forgetEmissions drops the dedup state for a bucket old enough that no client will replay
// into it.
func (b *AggregationBucket) forgetEmissions() {
	b.Lock()
	defer b.Unlock()
	b.emissions = nil
}

func (b *AggregationBucket) Fields() logrus.Fields {
	return logrus.Fields{
		"start_time": b.StartTime,
		"end_time":   b.EndTime,
		"index":      b.index,
	}
}

func (b *AggregationBucket) Reset(start, end int64) {
	b.Lock()
	defer b.Unlock()

	b.StartTime = start
	b.EndTime = end
	b.pushed = false
	b.ready = false
	b.stats = newStatisticsIndex()
	b.emissions = map[emissionKey]struct{}{}

	if b.Flows == nil {
		b.Flows = set.New[*DiachronicFlow]()
	} else {
		b.Flows.Clear()
	}
}

// markReady marks this bucket as ready to be consumed by a stream.
func (b *AggregationBucket) markReady() {
	b.Lock()
	defer b.Unlock()
	b.ready = true
}

func (b *AggregationBucket) Iter(fn func(FlowBuilder) bool) {
	b.RLock()
	defer b.RUnlock()
	b.iterLocked(fn)
}

// iterInterval is Iter for a provider queued while the bucket covered the interval beginning at
// start. It yields nothing once the ring has reset the bucket for a later interval, even if that
// interval has since been marked ready.
func (b *AggregationBucket) iterInterval(start int64, fn func(FlowBuilder) bool) {
	b.RLock()
	defer b.RUnlock()

	if b.StartTime != start {
		logrus.WithFields(b.Fields()).WithField("queued_start", start).Info("Skipping bucket that has since been reused")
		return
	}
	b.iterLocked(fn)
}

func (b *AggregationBucket) iterLocked(fn func(FlowBuilder) bool) {
	if !b.ready {
		// Bucket has been reset since it was streamed. Skip it.
		logrus.WithFields(b.Fields()).Info("Skipping bucket that has since rolled over")
		return
	}

	for d := range b.Flows.All() {
		if fn(NewDeferredFlowBuilder(d, b.StartTime, b.EndTime)) {
			break
		}
	}
}

// bucketInterval is the FlowProvider the ring queues for streams. A slow stream can still hold
// it after the ring reuses the bucket, so it remembers which interval it was queued for.
type bucketInterval struct {
	bucket *AggregationBucket
	start  int64
}

var _ FlowProvider = bucketInterval{}

// newBucketInterval returns a provider for the interval b currently covers. Only the main loop
// may call it, since that is the only goroutine that resets buckets.
func newBucketInterval(b *AggregationBucket) bucketInterval {
	return bucketInterval{bucket: b, start: b.StartTime}
}

// Iter yields the bucket's flows if it still covers the queued interval, and nothing otherwise.
func (i bucketInterval) Iter(fn func(FlowBuilder) bool) {
	i.bucket.iterInterval(i.start, fn)
}

func (b *AggregationBucket) QueryStatistics(q *proto.StatisticsRequest) map[StatisticsKey]*counts {
	return b.stats.QueryStatistics(q)
}
