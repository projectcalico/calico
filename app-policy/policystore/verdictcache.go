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

package policystore

import (
	"sync"
	"sync/atomic"

	"github.com/projectcalico/calico/felix/proto"
)

// VerdictKey identifies a cached verdict: the endpoint evaluated, the scope and direction of the
// evaluation, and the parts of the flow's L3/L4 header that the endpoint's rules can look at. The
// source port is part of the key only when some applicable rule matches on source ports; flows
// that differ only in their source port (a client reconnecting) then share one entry. The checker
// decides that; see checker.verdictKey.
type VerdictKey struct {
	Endpoint  *proto.WorkloadEndpoint
	Scope     int8
	Direction int8
	Protocol  int32
	SrcPort   int32 // -1 when the key does not include the source port.
	DstPort   int32
	SrcIP     [16]byte
	DstIP     [16]byte
}

// VerdictCacheStats counts cache traffic. One set of counters is shared between the caches of
// successive stores, so that they survive a resync.
type VerdictCacheStats struct {
	Hits, Misses, Resets, Evictions atomic.Uint64
}

// VerdictCache remembers evaluation results for the contents of one PolicyStore.
//
// Entries are valid for one store generation: every Lookup and Store carries the store's current
// Generation, and a cache that sees a new generation starts empty. Any update applied through
// ProcessUpdate moves the generation, so a cached verdict can never outlive the policies, IP sets
// or endpoints it was computed from. This is coarse (an IP set delta anywhere empties the cache)
// and safe; finer invalidation is a separate piece of work.
//
// The cache is bounded. When it is full it starts over rather than evicting one entry: an LRU
// would keep the hot entries but costs a list operation per lookup, and the flows the collector
// sees repeat within a window far smaller than the default capacity.
//
// The cache holds its own lock, so it is safe to use from concurrent evaluations holding the
// store's read lock.
type VerdictCache struct {
	mu         sync.Mutex
	capacity   int
	generation uint64
	entries    map[VerdictKey]any
	flags      map[flagKey]bool
	stats      *VerdictCacheStats
}

// flagKey identifies a per-endpoint property memoised for one generation.
type flagKey struct {
	ep         *proto.WorkloadEndpoint
	scope, dir int8
}

// NewVerdictCache returns a cache holding at most capacity entries, reporting into stats (a
// private set of counters when nil).
func NewVerdictCache(capacity int, stats *VerdictCacheStats) *VerdictCache {
	if stats == nil {
		stats = &VerdictCacheStats{}
	}
	return &VerdictCache{
		capacity: capacity,
		entries:  make(map[VerdictKey]any),
		flags:    make(map[flagKey]bool),
		stats:    stats,
	}
}

// Lookup returns the verdict cached for the key at this generation, if any.
func (c *VerdictCache) Lookup(generation uint64, key VerdictKey) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.syncGeneration(generation)
	v, ok := c.entries[key]
	if ok {
		c.stats.Hits.Add(1)
	} else {
		c.stats.Misses.Add(1)
	}
	return v, ok
}

// Store records a verdict for the key at this generation. The verdict is handed out as-is to
// later lookups, so it must not be modified afterwards.
func (c *VerdictCache) Store(generation uint64, key VerdictKey, verdict any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.syncGeneration(generation)
	if c.capacity <= 0 {
		return
	}
	if len(c.entries) >= c.capacity {
		clear(c.entries)
		c.stats.Evictions.Add(1)
	}
	c.entries[key] = verdict
}

// EndpointFlag memoises, for the current generation, a property of the rules that apply to an
// endpoint in a scope and direction, computing it on first use. The checker uses it to decide how
// the endpoint's flows are keyed without walking the rules on every evaluation.
func (c *VerdictCache) EndpointFlag(generation uint64, ep *proto.WorkloadEndpoint, scope, dir int8, compute func() bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.syncGeneration(generation)
	k := flagKey{ep: ep, scope: scope, dir: dir}
	if v, ok := c.flags[k]; ok {
		return v
	}
	v := compute()
	c.flags[k] = v
	return v
}

// syncGeneration empties the cache when the store has moved on. Called with the lock held.
func (c *VerdictCache) syncGeneration(generation uint64) {
	if c.generation == generation {
		return
	}
	if len(c.entries) > 0 || len(c.flags) > 0 {
		clear(c.entries)
		clear(c.flags)
		c.stats.Resets.Add(1)
	}
	c.generation = generation
}

// Len returns the number of cached verdicts.
func (c *VerdictCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Stats returns the counters the cache reports into.
func (c *VerdictCache) Stats() *VerdictCacheStats {
	return c.stats
}
