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

// Package rendezvous provides a generic, deterministic rendezvous
// (Highest-Random-Weight, "HRW") hash keyed by string with a generic
// value type.
//
// Like the sibling hashring package it answers "which member owns
// this key?" with minimal disruption when the member set changes,
// but with a different algorithm: each lookup scores every member as
// hash(member, key) and returns the member with the highest score.
//
// Compared to a consistent-hash ring, rendezvous hashing buys two
// things at the cost of an O(N) lookup (the ring is O(probes*log N)):
//
//   - Even distribution for free. There are no virtual nodes to
//     tune — every member is equally likely to win any given key, so
//     load is balanced to the Poisson floor without a replicas knob.
//   - A strictly stronger minimal-disruption guarantee. Removing a
//     member reassigns ONLY the keys that member used to win, spread
//     across the survivors; no key ever moves between two members
//     that both remain. Symmetrically, adding a member only steals
//     keys for itself and never shuffles keys between incumbents.
//
// The O(N) lookup makes this a good fit for modest member counts
// (tens to low hundreds) where the disruption guarantee matters more
// than lookup throughput.
//
// The default hash is XXH3-64 (github.com/zeebo/xxh3). Callers can
// swap in any deterministic byte-slice hasher via WithHash. Do not
// use hash/maphash: its seed is process-local.
//
// Lookup is deterministic regardless of insertion order or map
// iteration order: the highest score wins, and exact score ties
// (e.g. hash collisions) are broken by the lexicographically smaller
// member key.
//
// The Rendezvous is not safe for concurrent use. Callers sharing one
// across goroutines should wrap it in their own lock.
package rendezvous

import (
	"encoding/binary"

	"github.com/zeebo/xxh3"
)

// Hash hashes a byte slice to a uint64. Implementations must be
// deterministic across processes. Do not use hash/maphash (its
// seed is process-local).
//
// The Rendezvous may pass a buffer it owns and reuses; implementations
// must not retain or mutate the slice past the call.
type Hash func([]byte) uint64

// defaultHash is the default Hash used when no WithHash option is
// passed: XXH3-64 (github.com/zeebo/xxh3). XXH3 is stateless,
// allocation-free, and has much better avalanche than FNV-1a — for
// short or near-sequential inputs (consecutive IPs, etc.) FNV
// clusters scores badly, biasing ownership; XXH3 reaches the Poisson
// floor of uniform distribution.
var defaultHash Hash = xxh3.Hash

// Rendezvous is a rendezvous (HRW) hash keyed by string, owning values
// of type V. The zero value is not usable; construct one with New.
// Not safe for concurrent use.
type Rendezvous[V any] struct {
	hash    Hash
	members map[string]V
	scratch []byte // reused combine buffer; see combinedHash
}

// Option configures a Rendezvous at construction time.
type Option func(*config)

type config struct {
	hash Hash
}

// WithHash sets the hash function used by the Rendezvous. The default
// is XXH3-64 (github.com/zeebo/xxh3). The hasher MUST be deterministic
// across processes (do not use hash/maphash).
func WithHash(h Hash) Option {
	return func(c *config) { c.hash = h }
}

// New builds a Rendezvous. The default hash is XXH3-64; pass WithHash
// to swap the hasher. The hash must be non-nil; New panics otherwise.
func New[V any](opts ...Option) *Rendezvous[V] {
	// Pre-build the default hasher so options can override it; any
	// explicit WithHash(nil) lands as cfg.hash == nil after the loop
	// and is caught as a programmer error.
	cfg := config{hash: defaultHash}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.hash == nil {
		panic("rendezvous: hash must not be nil")
	}
	return &Rendezvous[V]{
		hash:    cfg.hash,
		members: make(map[string]V),
	}
}

// Insert adds (or updates) a member. If key is already present the
// value is replaced; a member's scores depend only on its key, so an
// update never changes which keys the member owns. O(1).
func (r *Rendezvous[V]) Insert(key string, value V) {
	r.members[key] = value
}

// Remove deletes a member. It is a no-op if key is not present. O(1).
func (r *Rendezvous[V]) Remove(key string) {
	delete(r.members, key)
}

// Len returns the number of members. O(1).
func (r *Rendezvous[V]) Len() int {
	return len(r.members)
}

// Lookup returns the member that owns key — the one whose
// hash(member, key) score is highest. The boolean is false (and the
// returned value is the zero V) iff the Rendezvous has no members.
// O(N) in the number of members.
func (r *Rendezvous[V]) Lookup(key string) (V, bool) {
	var zero V
	if len(r.members) == 0 {
		return zero, false
	}
	// The selection must be independent of map iteration order:
	// strictly-greater score wins, and an exact score tie is broken
	// by the lexicographically smaller member key. Without the
	// tiebreak, colliding scores would resolve by iteration order and
	// Lookup would be nondeterministic.
	var bestKey string
	var bestScore uint64
	first := true
	for k := range r.members {
		s := r.combinedHash(k, key)
		if first || s > bestScore || (s == bestScore && k < bestKey) {
			bestScore, bestKey, first = s, k, false
		}
	}
	return r.members[bestKey], true
}

// combinedHash scores member against key as hash(len(member) ||
// member || key). The length prefix makes the encoding injective in
// (member, key): without it ("a","bc") and ("ab","c") would hash the
// same buffer and collide. The 4-byte length is fixed-width so the
// member/key boundary is always recoverable.
func (r *Rendezvous[V]) combinedHash(member, key string) uint64 {
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(member)))
	r.scratch = append(r.scratch[:0], n[:]...)
	r.scratch = append(r.scratch, member...)
	r.scratch = append(r.scratch, key...)
	return r.hash(r.scratch)
}
