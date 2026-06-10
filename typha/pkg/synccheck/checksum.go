// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

// Package synccheck provides an order-independent, incremental integrity
// checksum over the set of live key/value pairs held in a Typha snapshot
// cache.  It is used to detect data corruption introduced by a hop in the
// Typha hierarchy (e.g. a dedupe-buffer reconciliation bug): the server tells
// the client the checksum of its current snapshot and the client compares it
// against a checksum computed over its own reconstructed state.
//
// # Algorithm (must agree forever between peers, or be versioned in the hello)
//
// Per-entry digest:
//
//	h(entry) = xxhash64( uint64-LE(len(key)) ‖ key-bytes ‖ value-bytes )
//
// where key is SerializedUpdate.Key (a string) and value is
// SerializedUpdate.Value (the JSON bytes carried on the wire).  The length
// prefix on the key makes the digest unambiguous so that distinct (key, value)
// pairs cannot alias by concatenation (e.g. key="ab"/value="c" vs
// key="a"/value="bc").
//
// Store checksum: the per-entry digests are combined with XOR.  XOR gives O(1)
// add/remove/clobber, which lets the cache maintain the checksum incrementally
// in publishBreadcrumb() rather than rescanning the B-tree:
//
//	insert key:   xor ^= h(new)
//	clobber key:  xor ^= h(old); xor ^= h(new)
//	delete key:   xor ^= h(old)
//
// Keys are unique in the store and the key is part of the digest, so XOR
// cancellation between two distinct live entries would require a 64-bit hash
// collision.  That is acceptable for an integrity (not security) check; we
// also carry KVCount alongside, which is cheap and catches gross errors (whole
// resources added/dropped) with a much clearer error message than a hash
// mismatch.
//
// # Hash choice
//
// github.com/cespare/xxhash/v2 — already in the module graph, fast, stable
// wire-format-independent output.  Both sides must use the same hash; if we
// ever need to change it, gate the new algorithm behind a hello flag.
package synccheck

import (
	"encoding/binary"

	"github.com/cespare/xxhash/v2"
)

// Checksum is an incremental, order-independent checksum over a set of live
// key/value entries.  The zero value is the checksum of the empty set.  It is
// not safe for concurrent use; callers serialise access (the snapcache main
// loop owns its instance, and each Breadcrumb carries an immutable snapshot of
// the value).
type Checksum struct {
	// XOR is the running XOR of the per-entry digests.
	XOR uint64
	// KVCount is the number of live entries contributing to XOR.
	KVCount int64
}

// EntryDigest returns the per-entry digest h(entry) for the given wire key and
// value.  value may be nil (treated as empty), which corresponds to a deletion
// tombstone; deletions are never added to the checksum so this is only used
// internally for symmetry.
func EntryDigest(key string, value []byte) uint64 {
	var d xxhash.Digest
	d.Reset()
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(key)))
	_, _ = d.Write(lenBuf[:])
	_, _ = d.WriteString(key)
	_, _ = d.Write(value)
	return d.Sum64()
}

// Add records a new live entry.  The caller must guarantee the key was not
// already present (publishBreadcrumb does this by checking the B-tree first).
func (c *Checksum) Add(key string, value []byte) {
	c.XOR ^= EntryDigest(key, value)
	c.KVCount++
}

// Remove records the deletion of a live entry.  The caller must guarantee the
// key was present with exactly this value (the old value is in hand in
// publishBreadcrumb).
func (c *Checksum) Remove(key string, value []byte) {
	c.XOR ^= EntryDigest(key, value)
	c.KVCount--
}

// Replace records an in-place change of an existing key from oldValue to
// newValue.  The KVCount is unchanged (the key was and remains live).  The
// caller must skip no-op writes (oldValue == newValue) before calling this:
// although a self-cancelling XOR would leave the checksum unchanged, skipping
// keeps the contract explicit and matches the cache's dedupe behaviour.
func (c *Checksum) Replace(key string, oldValue, newValue []byte) {
	c.XOR ^= EntryDigest(key, oldValue)
	c.XOR ^= EntryDigest(key, newValue)
}
