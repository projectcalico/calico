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

package emitter

import (
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
)

type bucketKey struct {
	startTime int64
	endTime   int64
}

// bucketCache is a thread-safe cache of aggregation buckets.
type bucketCache struct {
	sync.Mutex
	buckets map[bucketKey]*aggregator.AggregationBucket
}

func newBucketCache() *bucketCache {
	return &bucketCache{
		buckets: map[bucketKey]*aggregator.AggregationBucket{},
	}
}

func (b *bucketCache) add(k bucketKey, bucket *aggregator.AggregationBucket) {
	b.Lock()
	defer b.Unlock()
	if _, exists := b.buckets[k]; exists {
		// This should never happen, but log an error if it does. This prevents
		// us from overwriting a bucket that's already in the map, which indicates an upstream bug.
		logrus.WithField("bucket", k).Error("Duplicate bucket received.")
		return
	}
	b.buckets[k] = bucket
}

func (b *bucketCache) get(k bucketKey) (*aggregator.AggregationBucket, bool) {
	b.Lock()
	defer b.Unlock()
	bucket, exists := b.buckets[k]
	return bucket, exists
}

func (b *bucketCache) remove(k bucketKey) {
	b.Lock()
	defer b.Unlock()
	delete(b.buckets, k)
}
