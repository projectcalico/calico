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
