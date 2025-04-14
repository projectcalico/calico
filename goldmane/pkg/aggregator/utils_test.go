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
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator/bucketing"
)

// testSink implements the Sink interface for testing.
type testSink struct {
	sync.Mutex
	buckets []*bucketing.FlowCollection
}

func newTestSink() *testSink {
	return &testSink{
		buckets: []*bucketing.FlowCollection{},
	}
}

func (t *testSink) Receive(b *bucketing.FlowCollection) {
	t.Lock()
	defer t.Unlock()
	t.buckets = append(t.buckets, b)
}

func (t *testSink) len() int {
	t.Lock()
	defer t.Unlock()
	return len(t.buckets)
}

func (t *testSink) reset() {
	t.Lock()
	defer t.Unlock()
	t.buckets = []*bucketing.FlowCollection{}
}

func (t *testSink) bucket(idx int) *bucketing.FlowCollection {
	t.Lock()
	defer t.Unlock()
	if idx >= len(t.buckets) {
		return nil
	}
	return t.buckets[idx]
}

// rolloverController is a helper struct to control when rollovers occur.
type rolloverController struct {
	ch                    chan time.Time
	clock                 *clock
	aggregationWindowSecs int64
}

func (r *rolloverController) After(_ time.Duration) <-chan time.Time {
	return r.ch
}

// rollover triggers a rollover without advancing the internal clock. Clock manipulation is left to the caller.
func (r *rolloverController) rollover() {
	r.ch <- r.clock.Now()

	// Wait for rollover to complete.
	time.Sleep(10 * time.Millisecond)
}

// rolloverAndAdvanceClock triggers n rollovers, advancing the internal clock by the aggregation window each time.
// Note: rollover is asyncrhonous with the test code, so the caller should use Eventually() for any subsequent assertions.
func (r *rolloverController) rolloverAndAdvanceClock(n int) {
	logrus.Infof("[TEST] Rollover and advance clock %d times", n)
	for range n {
		r.ch <- r.clock.Now()
		r.clock.Advance(time.Duration(r.aggregationWindowSecs) * time.Second)
	}
}

func (r *rolloverController) now() int64 {
	return r.clock.Now().Unix()
}

func newClock(t int64) *clock {
	return &clock{t: t}
}

// clock is a helper structure for tests that need control over time.
type clock struct {
	sync.Mutex
	t int64
}

func (c *clock) Now() time.Time {
	c.Lock()
	defer c.Unlock()
	return time.Unix(c.t, 0)
}

func (c *clock) Advance(d time.Duration) {
	c.Lock()
	defer c.Unlock()
	c.t += int64(d.Seconds())
}

func (c *clock) Set(t time.Time) {
	c.Lock()
	defer c.Unlock()

	c.t = t.Unix()
}
