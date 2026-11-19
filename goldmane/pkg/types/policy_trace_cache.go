// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package types

import (
	"sync"
	"sync/atomic"
	"unique"

	"github.com/projectcalico/calico/goldmane/proto"
)

// policyTraceGenerationSize bounds each of the trace cache's two generations, so it holds up to
// 32768 entries: about 30 MB at two hits per policy list, 54 MB at four and 101 MB at eight.
const policyTraceGenerationSize = 16384

var defaultPolicyTraceCache = newPolicyTraceCache(policyTraceGenerationSize)

// policyTraceCache maps an interned policy trace string to its decoded, sorted trace, in two
// generations. A full current generation becomes the previous one and the old previous one is
// dropped, so a trace unused for a whole generation leaves within two rotations. A hit in the
// previous generation copies the trace into the current one. Hits in the current generation take
// no lock; inserts and rotations serialize on mu.
type policyTraceCache struct {
	generationSize int64
	current        atomic.Pointer[sync.Map]
	previous       atomic.Pointer[sync.Map]
	mu             sync.Mutex
	currentCount   atomic.Int64
	previousCount  atomic.Int64
	rotations      atomic.Uint64
}

func newPolicyTraceCache(generationSize int64) *policyTraceCache {
	c := &policyTraceCache{generationSize: generationSize}
	c.current.Store(&sync.Map{})
	c.previous.Store(&sync.Map{})
	return c
}

// PolicyTraceCacheSize returns the number of entries across both cache generations, for metrics.
// A trace copied forward from the previous generation counts once in each.
func PolicyTraceCacheSize() int64 {
	return defaultPolicyTraceCache.size()
}

// PolicyTraceCacheRotations returns how many times the cache has started a new generation, for
// metrics.
func PolicyTraceCacheRotations() uint64 {
	return defaultPolicyTraceCache.rotations.Load()
}

// CachedPolicyTrace returns the decoded, sorted policy trace for h, decoding it at most once
// while it stays cached. The result is shared between callers and goroutines, so callers must
// not modify it.
func CachedPolicyTrace(h unique.Handle[string]) *proto.PolicyTrace {
	return defaultPolicyTraceCache.trace(h)
}

// trace returns the cached trace for h, decoding and caching it on a miss. Goroutines that miss
// on the same handle at once may each decode it, but only the first insert is kept and returned
// to all of them.
func (c *policyTraceCache) trace(h unique.Handle[string]) *proto.PolicyTrace {
	if cached, ok := loadTrace(c.current.Load(), h); ok {
		return cached
	}
	if cached, ok := loadTrace(c.previous.Load(), h); ok {
		return c.insert(h, cached)
	}
	return c.insert(h, FlowLogPolicyToProto(h))
}

// insert adds t to the current generation for h and returns the trace the cache keeps for h,
// which is an already cached one if another goroutine got there first. It rotates the generations
// first if the current one is full.
func (c *policyTraceCache) insert(h unique.Handle[string], t *proto.PolicyTrace) *proto.PolicyTrace {
	c.mu.Lock()
	defer c.mu.Unlock()
	current := c.current.Load()
	if cached, ok := loadTrace(current, h); ok {
		return cached
	}
	if cached, ok := loadTrace(c.previous.Load(), h); ok {
		t = cached
	}

	if c.currentCount.Load() >= c.generationSize {
		c.previous.Store(current)
		c.previousCount.Store(c.currentCount.Load())
		current = &sync.Map{}
		c.current.Store(current)
		c.currentCount.Store(0)
		c.rotations.Add(1)
	}
	current.Store(h, t)
	c.currentCount.Add(1)
	return t
}

func (c *policyTraceCache) size() int64 {
	return c.currentCount.Load() + c.previousCount.Load()
}

func loadTrace(m *sync.Map, h unique.Handle[string]) (*proto.PolicyTrace, bool) {
	v, ok := m.Load(h)
	if !ok {
		return nil, false
	}
	p, ok := v.(*proto.PolicyTrace)
	return p, ok
}
