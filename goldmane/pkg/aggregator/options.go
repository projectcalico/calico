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
		a.rolloverTime = rollover
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
