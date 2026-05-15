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
// The default hash is FNV-1a (stdlib hash/fnv, used via a
// per-Ring hasher). Callers can swap in any deterministic string
// hasher via WithHash — for stronger distribution, wrap
// crypto/sha256 to return the first eight bytes as a uint64. Do
// not use hash/maphash: its seed is process-local.
//
// The Ring is not safe for concurrent use. Callers sharing a
// ring across goroutines should wrap it in their own lock.
package hashring

import (
	"cmp"
	"encoding/binary"
	"hash/fnv"
	"slices"
)

// Hash hashes a byte slice to a uint64. Implementations must be
// deterministic across processes. Do not use hash/maphash (its
// seed is process-local).
//
// The Ring may pass a buffer it owns and reuses; implementations
// must not retain or mutate the slice past the call.
type Hash func([]byte) uint64

// newDefaultHash returns a Hash backed by a per-Ring stdlib
// hash/fnv.New64a hasher. Each Ring gets its own hasher so the
// closure has no shared state (no goroutine-safety pitfall beyond
// the Ring itself).
func newDefaultHash() Hash {
	h := fnv.New64a()
	return func(b []byte) uint64 {
		h.Reset()
		h.Write(b)
		return h.Sum64()
	}
}

// Ring is a consistent hash ring keyed by string, owning values of
// type V. The zero value is not usable; construct one with New.
// Not safe for concurrent use.
type Ring[V any] struct {
	hash     Hash
	replicas int
	probes   int

	members map[string]V
	entries []entry
	sorted  bool

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
// stdlib hash/fnv 64-bit FNV-1a, used via a per-Ring hasher. The
// hasher MUST be deterministic across processes (do not use
// hash/maphash).
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

// New builds a Ring. Defaults: hash = FNV1a, replicas = 1,
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
	cfg := ringConfig{hash: newDefaultHash(), replicas: 1, probes: 1}
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
		hash:     cfg.hash,
		replicas: cfg.replicas,
		probes:   cfg.probes,
		members:  make(map[string]V),
	}
}

// Insert adds (or updates) a member. If key is already present the
// value is replaced but the virtual-node placement is unchanged --
// the same key always produces the same ring positions.
func (r *Ring[V]) Insert(key string, value V) {
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

// Remove drops a member and all of its virtual nodes. It is a no-op
// if key is not present.
func (r *Ring[V]) Remove(key string) {
	if _, ok := r.members[key]; !ok {
		return
	}
	delete(r.members, key)
	r.entries = slices.DeleteFunc(r.entries, func(e entry) bool {
		return e.key == key
	})
}

// Len returns the number of distinct members in the ring.
func (r *Ring[V]) Len() int {
	return len(r.members)
}

// Lookup returns the member that owns key. The boolean is false
// (and the returned value is the zero V) iff the ring has no
// members. Lookup may sort the underlying entry table the first
// time it is called after a mutation; subsequent lookups are
// O(probes * log N).
func (r *Ring[V]) Lookup(key string) (V, bool) {
	var zero V
	if len(r.entries) == 0 {
		return zero, false
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
