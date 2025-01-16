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

package aggregator_test

import (
	"time"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
)

// testSink implements the Sink interface for testing.
type testSink struct {
	buckets []*aggregator.AggregationBucket
}

func (t *testSink) Receive(b *aggregator.AggregationBucket) {
	t.buckets = append(t.buckets, b)
}

// rolloverController is a helper strut to control when rollovers occur.
type rolloverController struct {
	ch           chan time.Time
	intervalSecs int64
	t            int64
}

func (r *rolloverController) After(_ time.Duration) <-chan time.Time {
	return r.ch
}

func (r *rolloverController) rollover(n int) {
	for i := 0; i < n; i++ {
		r.ch <- time.Now()
		r.t += r.intervalSecs
	}
	// Wait for rollovers to complete.
	time.Sleep(10 * time.Millisecond)
}

func (r *rolloverController) now() int64 {
	return r.t
}
