package bucketing

import "fmt"

type timeRing struct {
	size int

	// TODO this comment sucks and needs to be better.
	// headIndex is the index of the newest bucket. This is one ahead of the bucket that represents the current time.
	headIndex int
	interval  int

	tailIndexStartTime int64
	headIndexStartTime int64
}

func newTimeRing(size, interval int, now int64) *timeRing {
	r := &timeRing{
		size:      size,
		interval:  interval,
		headIndex: 0,
	}

	r.headIndexStartTime = now + int64(interval)
	r.tailIndexStartTime = r.headIndexStartTime - int64(interval*size)

	return r
}

func (r *timeRing) rollover() {
	// Capture the new bucket's start time - this is the end time of the previous bucket.
	r.headIndexStartTime = r.headIndexStartTime + int64(r.interval)
	r.tailIndexStartTime = r.headIndexStartTime - int64(r.interval*r.size)

	// Move the head index to the next bucket.
	r.headIndex = r.nextIndex(r.headIndex)
}

// nowIndex returns the index of the bucket that represents the current time.
// This is different from the head index, which is actually one bucket into the future.
func (r *timeRing) currentIndex() int {
	return r.indexSubtract(r.headIndex, 1)
}

func (r *timeRing) currentIndexTime() int64 {
	return r.indexToTime(r.currentIndex())
}

func (r *timeRing) timeToIndex(t int64) (int, error) {
	diff := int(r.headIndexStartTime-t) / r.interval
	if diff > r.size {
		return -1, fmt.Errorf("time %d is after the end of the ring", t)
	} else if diff < 0 {
		return -1, fmt.Errorf("time %d is before the beginning of the ring", t)
	}

	return r.indexSubtract(r.headIndex, diff), nil
}

// idxToStartTime accept a valid index and returns the start time corresponding to that index. If the index is not in
// range this function panic.
func (r *timeRing) indexToTime(idx int) int64 {
	if idx >= r.size || idx < 0 {
		panic("index out of range")
	}

	var diff int
	if idx >= r.headIndex {
		diff = idx - r.headIndex
	} else {
		diff = r.size - r.headIndex + idx
	}

	return r.headIndexStartTime - int64(diff*r.interval)
}

// nextBucketIndex returns the next bucket index, wrapping around if necessary.
func (r *timeRing) nextIndex(idx int) int {
	return r.indexAdd(idx, 1)
}

// indexSubtract subtracts n from idx, wrapping around if necessary.
func (r *timeRing) indexSubtract(idx, n int) int {
	return (idx - n + r.size) % r.size
}

// indexAdd adds n to idx, wrapping around if necessary.
func (r *timeRing) indexAdd(idx, n int) int {
	return (idx + n) % r.size
}
