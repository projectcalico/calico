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

package interncache

import (
	"hash/maphash"
	"runtime"
	"sync"
	"sync/atomic"
	"weak"
)

const (
	defaultNumBuckets = 1 << 10
	growPercent       = 70
	shrinkPercent     = 30
)

type Cache[T any] struct {
	seed   maphash.Seed
	hashFn func(maphash.Seed, *T) uint64
	equals func(*T, *T) bool

	cleanupsPending atomic.Int64

	lock           sync.Mutex
	cleanupTrigger *sync.Cond
	m              [][]weak.Pointer[T]
	len            atomic.Int64
}

func New[T any](
	hashFn func(maphash.Seed, *T) uint64,
	equalsFn func(*T, *T) bool,
) *Cache[T] {
	c := &Cache[T]{
		seed:   maphash.MakeSeed(),
		hashFn: hashFn,
		equals: equalsFn,
		m:      make([][]weak.Pointer[T], defaultNumBuckets),
	}
	c.cleanupTrigger = sync.NewCond(&c.lock)
	return c
}

func (c *Cache[T]) Intern(v *T) *T {
	h := c.hash(v)
	bucketIdx := h % uint64(len(c.m))

	c.lock.Lock()
	defer c.lock.Unlock()
	bucket := c.m[bucketIdx]
	updatedBucket := bucket[:0]
	var foundValue *T
	for _, p := range bucket {
		internedValue := p.Value()
		if internedValue == nil {
			c.len.Add(-1)
			continue
		}
		updatedBucket = append(updatedBucket, p)
		if foundValue != nil {
			continue
		}
		if c.equals(internedValue, v) {
			foundValue = internedValue
		}
	}
	if foundValue == nil {
		updatedBucket = append(updatedBucket, weak.Make(v))
		c.len.Add(1)
		foundValue = v
		runtime.AddCleanup(v, c.onPointerCleanedUp, h)
	}
	c.m[bucketIdx] = updatedBucket
	c.maybeResize()
	return foundValue
}

func (c *Cache[T]) Len() int {
	return int(c.len.Load())
}

func (c *Cache[T]) maybeResize() {
	if c.Len() > len(c.m)*growPercent/100 {
		c.resize(len(c.m) * 2)
	} else if c.Len() > defaultNumBuckets && c.Len() < len(c.m)*shrinkPercent/100 {
		c.resize(len(c.m) * 2)
	}
}

func (c *Cache[T]) resize(newSize int) {
	oldM := c.m
	c.m = make([][]weak.Pointer[T], newSize)
	newLen := int64(0)
	for _, bucket := range oldM {
		for _, p := range bucket {
			value := p.Value()
			if value == nil {
				continue
			}

			h := c.hash(value)
			bucketIdx := h % uint64(len(c.m))
			c.m[bucketIdx] = append(c.m[bucketIdx], p)
			newLen++
		}
	}
	c.len.Store(newLen)
}

func (c *Cache[T]) GC() {
	c.lock.Lock()
	defer c.lock.Unlock()
	for i := range c.m {
		c.gcNilsInBucket(i)
	}
	c.maybeResize()
}

func (c *Cache[T]) gcNilsInBucket(bucketIdx int) {
	bucket := c.m[bucketIdx]
	updatedBucket := bucket[:0]
	for _, p := range bucket {
		if p.Value() == nil {
			c.len.Add(-1)
			continue
		}
		updatedBucket = append(updatedBucket, p)
	}
	c.m[bucketIdx] = updatedBucket
}

func (c *Cache[T]) hash(v *T) uint64 {
	return c.hashFn(c.seed, v)
}

func (c *Cache[T]) onPointerCleanedUp(h uint64) {
	for {
		cleanupsPending := c.cleanupsPending.Load()
		currentLen := c.len.Load()
		if cleanupsPending > currentLen*10/100 {
			if c.cleanupsPending.CompareAndSwap(cleanupsPending, 0) {
				// Trigger a cleanup.
				go c.GC()
			} else {
				continue
			}
		}
	}
}
