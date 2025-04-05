package bucketing

import "github.com/sirupsen/logrus"

type Mergeable[E any] interface {
	*E
	Merge(E) E
}

type BucketMap[K comparable, V any, M Mergeable[V]] map[K]*V

type BucketMeta[V any] interface {
	Update(V)
}

type Bucket[Meta BucketMeta[S], K Key[R], V Mergeable[S], R comparable, S any] struct {
	Meta     Meta
	index    int
	timeRing *timeRing

	// TODO Rename from windows.
	Windows map[K]S
}

func (b *Bucket[Meta, K, V, R, S]) StartTime() int64 {
	return b.timeRing.indexToTime(b.index)
}

func (b *Bucket[Meta, K, V, R, S]) MidTime() int64 {
	return (b.StartTime() + b.EndTime()) / 2
}

func (b *Bucket[Meta, K, V, R, S]) EndTime() int64 {
	return b.timeRing.indexToTime(b.timeRing.indexAdd(b.index, 1))
}

func (b *Bucket[Meta, K, V, R, S]) Fields() logrus.Fields {
	return logrus.Fields{
		"bucketLength": len(b.Windows),
	}
}

type ReadOnlyBucket[K comparable, V any, M Mergeable[V]] interface {
	StartTime() int64
	EndTime() int64
	HasKey(key *K) bool
	Value(key *K) V
}

func (b *Bucket[Meta, K, V, R, S]) Value(key K) S {
	return b.Windows[key]
}

func (b *Bucket[Meta, K, V, R, S]) HasKey(key K) bool {
	_, ok := b.Windows[key]
	return ok
}
