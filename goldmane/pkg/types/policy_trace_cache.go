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

// maxCachedPolicyTraces bounds the decoded trace cache. Full, it retains 60-65 MB at two hits per
// policy list and 200-240 MB at eight. Large clusters with per-namespace policies reach tens of
// thousands of distinct traces.
const maxCachedPolicyTraces = 65536

var defaultPolicyTraceCache = newPolicyTraceCache(maxCachedPolicyTraces)

// policyTraceCache maps an interned policy trace string to its decoded, sorted trace. Lookups
// of a cached trace take no lock. Inserts serialize on mu, so the count matches the cached
// traces exactly, the cache never holds more than limit, and each fill is counted as one reset.
type policyTraceCache struct {
	limit  int64
	traces sync.Map
	mu     sync.Mutex
	count  atomic.Int64
	resets atomic.Uint64
}

func newPolicyTraceCache(limit int64) *policyTraceCache {
	return &policyTraceCache{limit: limit}
}

// PolicyTraceCacheSize returns the number of decoded traces currently cached, for metrics.
func PolicyTraceCacheSize() int64 {
	return defaultPolicyTraceCache.count.Load()
}

// PolicyTraceCacheResets returns how many times the cache has filled and been cleared, for
// metrics.
func PolicyTraceCacheResets() uint64 {
	return defaultPolicyTraceCache.resets.Load()
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
	if cached, ok := c.load(h); ok {
		return cached
	}

	decoded := FlowLogPolicyToProto(h)

	c.mu.Lock()
	defer c.mu.Unlock()
	if cached, ok := c.load(h); ok {
		return cached
	}

	// Churn past the bound clears the whole cache rather than tracking recency. Refilling
	// costs one decode per trace, and the cache never grows past the bound.
	if c.count.Load() >= c.limit {
		c.traces.Clear()
		c.count.Store(0)
		c.resets.Add(1)
	}
	c.traces.Store(h, decoded)
	c.count.Add(1)
	return decoded
}

func (c *policyTraceCache) load(h unique.Handle[string]) (*proto.PolicyTrace, bool) {
	v, ok := c.traces.Load(h)
	if !ok {
		return nil, false
	}
	p, ok := v.(*proto.PolicyTrace)
	return p, ok
}
