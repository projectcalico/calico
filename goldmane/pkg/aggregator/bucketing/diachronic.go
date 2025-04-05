package bucketing

type Aggregate[V any] struct {
	StartTime int64
	EndTime   int64
	Aggregate V
}

func newAggregate[V any](start, end int64, aggregate V) Aggregate[V] {
	return Aggregate[V]{
		StartTime: start,
		EndTime:   end,
		Aggregate: aggregate,
	}
}

type DiachronicAggregate[K any, V any] struct {
	StartTime int64
	EndTime   int64
	Key       *K
	Aggregate V
}

type Diachronic[K comparable, V Mergeable[R], R any] struct {
	ID int64

	Key *K

	ring       ROBucketRing[K, V, R]
	numBuckets int
}

func (d *Diachronic[K, V, R]) Aggregate(startGte, startLt int64) *R {
	aggregate := d.ring.AggregateOverTime(d.Key, startGte, startLt)
	return &aggregate.Aggregate
}
