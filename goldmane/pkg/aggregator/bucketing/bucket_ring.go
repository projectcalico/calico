package bucketing

import (
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"sort"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type Key[K comparable] interface {
	*K
	Fields() logrus.Fields
	Compare(*K) bool
}

type ROBucketRing[K comparable, V Mergeable[R], R any] interface {
	AggregateOverTime(key *K, startTime, endTime int64) Aggregate[R]
	TimeRangeForKey(*K) (int64, int64)
}

type RingIndex[K comparable] interface {
	List(opts FindOpts[K]) ([]K, types.ListMeta)
}

type BucketRing[Meta BucketMeta[S], K Key[R], V Mergeable[S], R comparable, S any] struct {
	timeRing *timeRing

	buckets     []*Bucket[Meta, K, V, R, S]
	diachronics map[R]*Diachronic[R, V, S]

	newMeta func() Meta

	stringIndices map[string]indexInf[K, R, string]
}

func (r *BucketRing[Meta, K, V, R, S]) TimeRangeForKey(k *R) (int64, int64) {
	startIdx := r.timeRing.indexAdd(r.timeRing.headIndex, 1)
	var startTime, endTime int64

	// Iterate the buckets from the oldest bucket to the newest, up until we get to the head bucket (which is one bucket
	// into the future).
	for i := startIdx; i != r.timeRing.headIndex; i = r.timeRing.indexAdd(i, 1) {
		if r.buckets[i].HasKey(k) {
			// startTime is set once since we're iterating the buckets in order from oldest to newest.
			if startTime == 0 {
				startTime = r.buckets[i].StartTime()
			}
			endTime = r.buckets[i].EndTime()
		}
	}

	return startTime, endTime
}

func NewRing[Meta BucketMeta[S], K Key[R], V Mergeable[S], R comparable, S any](
	size, interval int,
	now int64,
	newMeta func() Meta,
) *BucketRing[Meta, K, V, R, S] {
	ring := &BucketRing[Meta, K, V, R, S]{
		buckets:       make([]*Bucket[Meta, K, V, R, S], size),
		diachronics:   make(map[R]*Diachronic[R, V, S]),
		timeRing:      newTimeRing(size, interval, now),
		newMeta:       newMeta,
		stringIndices: make(map[string]indexInf[K, R, string]),
	}

	logrus.WithFields(logrus.Fields{
		"num":        size,
		"bucketSize": time.Duration(interval) * time.Second,
	}).Debug("Initializing aggregation buckets")

	for i := 0; i < size; i++ {
		ring.buckets[i] = &Bucket[Meta, K, V, R, S]{
			index:    i,
			timeRing: ring.timeRing,
			Windows:  make(map[K]S),
			Meta:     ring.newMeta(),
		}
	}

	logrus.WithFields(logrus.Fields{
		"headIndex":    ring.timeRing.headIndex,
		"curBucket":    ring.buckets[ring.timeRing.headIndex],
		"oldestBucket": ring.buckets[(ring.timeRing.headIndex+1)%size],
	}).Debug("Initialized bucket ring")

	return ring
}

func (r *BucketRing[Meta, Key, Value, KeyType, ValueType]) AddStringIndex(name string, idx indexInf[Key, KeyType, string]) {
	r.stringIndices[name] = idx
}

func (r *BucketRing[Meta, Key, Value, KeyType, ValueType]) FindAndIterate(opts FindOpts[Key], f func(Value)) types.ListMeta {
	var keys []Key
	var listMeta types.ListMeta
	var indexUsed bool
	if opts.SortBy != "" {
		if idx, ok := r.stringIndices[opts.SortBy]; ok {
			indexUsed = true
			keys, listMeta = idx.list(opts)
		}
	}

	if !indexUsed {
		for _, d := range r.DiachronicsForTimeRange(opts.StartTimeGt, opts.StartTimeLt) {
			if opts.Filter != nil && opts.Filter(d.Key) {
				continue
			}
			keys = append(keys, d.Key)
		}

		// TODO handle sort by for none indexed fields.

		total := len(keys)
		if opts.PageSize > 0 {
			startIdx := (opts.Page) * opts.PageSize
			endIdx := startIdx + opts.PageSize
			if startIdx >= int64(len(keys)) {
				return types.ListMeta{}
			}
			if endIdx >= int64(len(keys)) {
				endIdx = int64(len(keys)) - 1
			}
			keys = keys[startIdx : endIdx+1]
		}

		listMeta = calculateListMeta(total, int(opts.PageSize))
		for _, key := range keys {
			f(r.diachronics[*key].Aggregate(opts.StartTimeGt, opts.StartTimeLt))
		}
	}

	return listMeta
}

func (r *BucketRing[Meta, Key, Value, KeyType, ValueType]) FindIndexedStringValues(opts FindOpts[Key]) ([]string, types.ListMeta) {
	var values []string
	var listMeta types.ListMeta
	if opts.SortBy == "" {
		// TODO log an error
	}

	if idx, ok := r.stringIndices[opts.SortBy]; ok {
		values, listMeta = idx.uniqueIndexKeys(opts)
	} else {
		// TODO log an error
	}

	return values, listMeta
}

func (r *BucketRing[Meta, Key, Value, KeyType, ValueType]) FindStringValues(opts FindOpts[Key], valueFunc func(Key) []string) ([]string, types.ListMeta) {
	var values []string
	var listMeta types.ListMeta

	seen := set.New[string]()
	for _, d := range r.DiachronicsForTimeRange(opts.StartTimeGt, opts.StartTimeLt) {
		if opts.Filter != nil && opts.Filter(d.Key) {
			continue
		}
		vals := valueFunc(d.Key)
		for _, val := range vals {
			if !seen.Contains(val) {
				seen.Add(val)
				values = append(values, val)
			}
		}
	}

	sort.Strings(values)

	total := len(values)
	if opts.PageSize > 0 {
		startIdx := (opts.Page) * opts.PageSize
		endIdx := startIdx + opts.PageSize
		if startIdx >= int64(len(values)) {
			return nil, types.ListMeta{}
		}
		if endIdx >= int64(len(values)) {
			endIdx = int64(len(values)) - 1
		}
		values = values[startIdx : endIdx+1]
	}

	listMeta = calculateListMeta(total, int(opts.PageSize))

	return values, listMeta
}

var nextID int64

// DiachronicSet returns the set of flows that exist across buckets within the given time range.
func (r *BucketRing[Meta, K, V, R, S]) DiachronicSet(startGt, startLt int64, filter func(*R) bool) set.Set[*Diachronic[R, V, S]] {
	diachronics := set.New[*Diachronic[R, V, S]]()
	for _, b := range r.BucketsForTimeRange(startGt, startLt) {
		for k := range b.Windows {
			if filter == nil || filter(k) {
				diachronics.Add(r.diachronics[*k])
			}
		}
	}

	return diachronics
}

func (r *BucketRing[Meta, K, V, R, S]) AggregateOverTime(key *R, startTime, endTime int64) Aggregate[S] {
	var toReturn S
	var found bool
	var aggregateStartTime, aggregateEndTime int64
	for _, bucket := range r.BucketsForTimeRange(startTime, endTime) {
		if s, ok := bucket.Windows[key]; ok {
			if !found {
				toReturn = s
				found = true
				aggregateStartTime = bucket.StartTime()
				aggregateEndTime = bucket.EndTime()
			} else {
				V(&toReturn).Merge(s)
				if aggregateStartTime > bucket.StartTime() {
					aggregateStartTime = bucket.StartTime()
				}
				if aggregateEndTime < bucket.EndTime() {
					aggregateEndTime = bucket.EndTime()
				}
			}
		}
	}

	return newAggregate(aggregateStartTime, aggregateEndTime, toReturn)
}

// IterDiachronicsTime iterates over the diachronics in each bucket in the ring, from the starting time until the ending time.
// If either time is not found, an error is returned.
// If the start time is zero, it will start from the beginning of the ring.
// If the end time is zero, it will iterate until the current time.
func (r *BucketRing[Meta, K, V, R, S]) IterDiachronicsTime(start, end int64, f func(startTime, endTime int64, d *Diachronic[R, V, S])) {
	buckets := r.BucketsForTimeRange(start, end)

	for _, bucket := range buckets {
		startTime := bucket.StartTime()
		endTime := bucket.EndTime()
		for k := range bucket.Windows {
			f(startTime, endTime, r.diachronics[*k])
		}

	}
	return
}

func (r *BucketRing[Meta, K, V, R, S]) Add(t int64, key *R, value S) {
	if _, ok := r.diachronics[*key]; !ok {
		nextID++
		r.diachronics[*key] = &Diachronic[R, V, S]{
			ID:   nextID,
			Key:  key,
			ring: r,
		}
	}

	d := r.diachronics[*key]

	bucket, err := r.BucketForTime(t)
	if err != nil {
		logrus.WithError(err).Warn("Couldn't find bucket for time.")
		return
	}

	if existing, ok := bucket.Windows[key]; ok {
		V(&existing).Merge(value)
		bucket.Windows[key] = existing
	} else {
		bucket.Windows[key] = value
		d.numBuckets++
	}

	for _, idx := range r.stringIndices {
		idx.add(key)
	}

	bucket.Meta.Update(bucket.Windows[key])
	return
}

func (r *BucketRing[Meta, K, V, R, S]) GetDiachronic(key K) *Diachronic[R, V, S] {
	return r.diachronics[*key]
}

// Rollover moves the head index to the next bucket, resetting to 0 if we've reached the end.
// It also clears data from the bucket that is now the head. The start time of the newest bucket
// is returned.
func (r *BucketRing[Meta, K, V, R, S]) Rollover() int64 {
	r.timeRing.rollover()

	headBucket := r.buckets[r.timeRing.headIndex]

	// Clear data from the bucket that is now the head. The start time of the new bucket
	// is the end time of the previous bucket.
	for key := range headBucket.Windows {
		d := r.diachronics[*key]
		d.numBuckets--
		if d.numBuckets == 0 {
			for _, index := range r.stringIndices {
				index.remove(d.Key)
			}
			delete(r.diachronics, *d.Key)
		}
	}

	headBucket.Meta = r.newMeta()
	headBucket.Windows = make(map[K]S)

	return r.timeRing.headIndexStartTime
}

func (r *BucketRing[Meta, K, V, R, S]) BeginningOfHistory() int64 {
	return r.timeRing.tailIndexStartTime
}

func (r *BucketRing[Meta, K, V, R, S]) NumBuckets() int {
	return len(r.buckets)
}

func (r *BucketRing[Meta, K, V, R, S]) CurrentBucket() *Bucket[Meta, K, V, R, S] {
	return r.buckets[r.timeRing.currentIndex()]
}

func (r *BucketRing[Meta, K, V, R, S]) OldestBucket() *Bucket[Meta, K, V, R, S] {
	return r.buckets[r.timeRing.indexAdd(r.timeRing.headIndex, 1)]
}

func (r *BucketRing[Meta, K, V, R, S]) BucketsSince(time int64) []*Bucket[Meta, K, V, R, S] {
	idx, err := r.timeRing.timeToIndex(time)
	if err != nil {
		logrus.WithError(err).Warn("Couldn't find bucket for time")
		return nil
	}
	return r.bucketsBetween(idx, r.timeRing.currentIndex())
}

func (r *BucketRing[Meta, K, V, R, S]) bucketsBetween(start, end int) []*Bucket[Meta, K, V, R, S] {
	if start < len(r.buckets) {
		return r.buckets[start : end+1]
	}

	buckets := r.buckets[start:len(r.buckets)]
	// Do end+1 so that buckets[end] is included
	buckets = append(buckets, r.buckets[0:end+1]...)

	return buckets
}

func (r *BucketRing[Meta, K, V, R, S]) Bucket(idx int) *Bucket[Meta, K, V, R, S] {
	return r.buckets[idx]
}

func (r *BucketRing[Meta, K, V, R, S]) BucketForTime(time int64) (*Bucket[Meta, K, V, R, S], error) {
	idx, err := r.timeRing.timeToIndex(time)
	if err != nil {
		return nil, err
	}

	return r.buckets[idx], nil
}

func (r *BucketRing[Meta, K, V, R, S]) BucketsForTimeRange(startGt, startLt int64) []*Bucket[Meta, K, V, R, S] {
	startIdx, err := r.timeRing.timeToIndex(startGt)
	if err != nil {
		return nil
	}

	endIdx, err := r.timeRing.timeToIndex(startLt)
	if err != nil {
		return nil
	}

	return r.bucketsBetween(startIdx, endIdx)
}

// TODO comment on this and mention how it's guaranteed sorted by time.
func (r *BucketRing[Meta, K, V, R, S]) DiachronicsForTimeRange(startGt, startLt int64) []*Diachronic[R, V, S] {
	startIdx, err := r.timeRing.timeToIndex(startGt)
	if err != nil {
		return nil
	}

	endIdx, err := r.timeRing.timeToIndex(startLt)
	if err != nil {
		return nil
	}

	seen := set.New[K]()

	buckets := r.bucketsBetween(startIdx, endIdx)
	diachronics := make([]*Diachronic[R, V, S], 0, len(buckets))
	for _, b := range buckets {
		for key := range b.Windows {
			if seen.Contains(key) {
				continue
			}
			seen.Add(key)
			diachronics = append(diachronics, r.diachronics[*key])
		}
	}

	return diachronics
}
