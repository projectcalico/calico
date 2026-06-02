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

// Package hashring provides a generic, deterministic consistent
// hash ring keyed by string with a generic value type.
//
// The ring distributes lookup keys across a set of named members
// (each replicated as several virtual nodes) such that adding or
// removing a member reassigns only ~1/N of keys.
//
// The default hash is XXH3-64 (github.com/zeebo/xxh3). Callers
// can swap in any deterministic byte-slice hasher via WithHash.
// Do not use hash/maphash: its seed is process-local.
//
// The Ring is not safe for concurrent use. Callers sharing a
// ring across goroutines should wrap it in their own lock.
package hashring

import (
	"cmp"
	"encoding/binary"
	"slices"

	"github.com/zeebo/xxh3"
)

// Hash hashes a byte slice to a uint64. Implementations must be
// deterministic across processes. Do not use hash/maphash (its
// seed is process-local).
//
// The Ring may pass a buffer it owns and reuses; implementations
// must not retain or mutate the slice past the call.
type Hash func([]byte) uint64

// defaultHash is the default Hash used when no WithHash option is
// passed: XXH3-64 (github.com/zeebo/xxh3). XXH3 is stateless,
// allocation-free, and has much better avalanche than FNV-1a — for
// short or near-sequential inputs (consecutive IPs, etc.) FNV
// clusters virtual nodes badly, leaving some members with zero
// keys; XXH3 reaches the Poisson floor of uniform distribution.
var defaultHash Hash = xxh3.Hash

// Ring is a consistent hash ring keyed by string, owning values of
// type V. The zero value is not usable; construct one with New.
// Not safe for concurrent use.
type Ring[V any] struct {
	hash     Hash
	replicas int
	probes   int

	members     map[string]V
	deletedKeys map[string]struct{} // subset of members queued for sweep
	entries     []entry
	sorted      bool

	scratch []byte
}

type entry struct {
	hash uint64
	key  string
}

// Option configures a Ring at construction time.
type Option func(*ringConfig)

type ringConfig struct {
	hash             Hash
	replicas, probes int
}

// WithHash sets the hash function used by the Ring. The default is
// XXH3-64 (github.com/zeebo/xxh3). The hasher MUST be deterministic
// across processes (do not use hash/maphash).
func WithHash(h Hash) Option {
	return func(c *ringConfig) { c.hash = h }
}

// WithReplicas sets the number of virtual-node positions each member
// occupies on the ring. Higher values reduce imbalance at the cost
// of ring memory (and a one-time sort after mutations). Must be
// >= 1. Default: 1.
func WithReplicas(n int) Option {
	return func(c *ringConfig) { c.replicas = n }
}

// WithProbes sets the number of times Lookup hashes the query key
// (with distinct salts); the member nearest any probe wins. Higher
// values reduce imbalance at the cost of Lookup CPU. Must be >= 1.
// Default: 1.
func WithProbes(n int) Option {
	return func(c *ringConfig) { c.probes = n }
}

// New builds a Ring. Defaults: hash = XXH3-64, replicas = 1,
// probes = 1 (bare consistent hashing — poor load balance). Pass
// WithReplicas / WithProbes to control imbalance and WithHash to
// swap the hasher. Imbalance scales roughly with replicas*probes;
// the two knobs are independent levers on the same budget
// (R=100,P=1 is classic v-nodes, R=1,P=21 is pure multi-probe,
// R=10,P=10 is a hybrid). Any supplied replicas/probes must be >= 1
// and the hash must be non-nil; New panics otherwise.
func New[V any](opts ...Option) *Ring[V] {
	// Pre-build the default hasher so options can override it; any
	// explicit WithHash(nil) lands as cfg.hash == nil after the
	// loop and is caught as a programmer error.
	cfg := ringConfig{hash: defaultHash, replicas: 1, probes: 1}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.hash == nil {
		panic("hashring: hash must not be nil")
	}
	if cfg.replicas < 1 {
		panic("hashring: replicas must be >= 1")
	}
	if cfg.probes < 1 {
		panic("hashring: probes must be >= 1")
	}
	return &Ring[V]{
		hash:        cfg.hash,
		replicas:    cfg.replicas,
		probes:      cfg.probes,
		members:     make(map[string]V),
		deletedKeys: make(map[string]struct{}),
	}
}

// Insert adds (or updates) a member. If key is already present the
// value is replaced but the virtual-node placement is unchanged --
// the same key always produces the same ring positions.
//
// Insert of a key that has been removed but not yet swept (see
// Remove) is also O(R*hash) — the previous virtual nodes are
// reclaimed by dropping the key from the pending-delete set, and
// the new value is stored. No double-counting on the ring.
func (r *Ring[V]) Insert(key string, value V) {
	if _, deleted := r.deletedKeys[key]; deleted {
		delete(r.deletedKeys, key)
		r.members[key] = value
		return
	}
	if _, ok := r.members[key]; ok {
		r.members[key] = value
		return
	}
	r.members[key] = value
	r.entries = slices.Grow(r.entries, r.replicas)
	for i := range r.replicas {
		r.entries = append(r.entries, entry{
			hash: r.saltedHash(key, i),
			key:  key,
		})
	}
	r.sorted = false
}

// Remove queues a member for removal. The member's virtual nodes
// stay in the ring until the next Lookup, which sweeps them in one
// pass; this amortises bulk Removes from O(K*N) to O(N). Remove
// itself is O(1). It is a no-op if key is not present (whether
// "not present" means never inserted or already queued).
func (r *Ring[V]) Remove(key string) {
	if _, ok := r.members[key]; !ok {
		return
	}
	r.deletedKeys[key] = struct{}{}
}

// Len returns the number of distinct members in the ring (excluding
// any queued for removal).
func (r *Ring[V]) Len() int {
	return len(r.members) - len(r.deletedKeys)
}

// Lookup returns the member that owns key. The boolean is false
// (and the returned value is the zero V) iff the ring has no live
// members. Lookup may sort and/or sweep the underlying entry table
// the first time it is called after a mutation; subsequent lookups
// are O(probes * log N).
func (r *Ring[V]) Lookup(key string) (V, bool) {
	var zero V
	if r.Len() == 0 {
		return zero, false
	}
	if len(r.deletedKeys) > 0 {
		// slices.DeleteFunc must preserve relative order — Lookup
		// binary-searches r.entries assuming it stays sorted when
		// r.sorted is true. If you replace this with any non-stable
		// filter (swap-and-truncate etc.), set r.sorted = false
		// here.
		r.entries = slices.DeleteFunc(r.entries, func(e entry) bool {
			_, dead := r.deletedKeys[e.key]
			return dead
		})
		for k := range r.deletedKeys {
			delete(r.members, k)
		}
		clear(r.deletedKeys)
	}
	if !r.sorted {
		slices.SortFunc(r.entries, func(a, b entry) int {
			if c := cmp.Compare(a.hash, b.hash); c != 0 {
				return c
			}
			return cmp.Compare(a.key, b.key)
		})
		r.sorted = true
	}
	bestDist := ^uint64(0)
	bestIdx := 0
	for i := range r.probes {
		probe := r.saltedHash(key, i)
		idx, _ := slices.BinarySearchFunc(r.entries, probe, func(e entry, p uint64) int {
			return cmp.Compare(e.hash, p)
		})
		if idx == len(r.entries) {
			idx = 0
		}
		dist := r.entries[idx].hash - probe
		if dist < bestDist {
			bestDist = dist
			bestIdx = idx
		}
	}
	return r.members[r.entries[bestIdx].key], true
}

// saltedHash hashes key combined with a 4-byte little-endian index.
// It is used for placing virtual-node positions at Insert time and
// for generating distinct Lookup probes — the same encoding for both
// is intentional; placement and lookup are different domains.
func (r *Ring[V]) saltedHash(key string, i int) uint64 {
	r.scratch = append(r.scratch[:0], key...)
	r.scratch = append(r.scratch, 0)
	var idx [4]byte
	binary.LittleEndian.PutUint32(idx[:], uint32(i))
	r.scratch = append(r.scratch, idx[:]...)
	return r.hash(r.scratch)
}
