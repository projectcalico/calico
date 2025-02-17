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

package aggregator

import (
	"time"
)

type Option func(*LogAggregator)

func WithSink(e Sink) Option {
	return func(a *LogAggregator) {
		a.sink = e
	}
}

// WithRolloverTime sets the rollover time for the aggregator. This configures the bucket size used
// to aggregate flows across nodes in the cluster.
func WithRolloverTime(rollover time.Duration) Option {
	return func(a *LogAggregator) {
		a.aggregationWindow = rollover
	}
}

// WithRolloverFunc allows manual control over the rollover timer, used in tests.
func WithRolloverFunc(f func(time.Duration) <-chan time.Time) Option {
	return func(a *LogAggregator) {
		a.rolloverFunc = f
	}
}

// WithBucketsToCombine sets the number of buckets to combine when pushing flows to the sink.
// This controls time-based aggregation when emiting flows.
func WithBucketsToCombine(numBuckets int) Option {
	return func(a *LogAggregator) {
		a.bucketsToAggregate = numBuckets
	}
}

// WithPushIndex sets the index of the bucket which triggers pushing to the emitter.
func WithPushIndex(index int) Option {
	return func(a *LogAggregator) {
		a.pushIndex = index
	}
}

func WithNowFunc(f func() time.Time) Option {
	return func(a *LogAggregator) {
		a.nowFunc = f
	}
}
