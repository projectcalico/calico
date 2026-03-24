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

package uniquelabels

import (
	"cmp"
	"encoding/json"
	"math/bits"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/projectcalico/calico/lib/std/uniquestr"
)

// maxKeyTableSize is the maximum number of distinct label keys tracked in the
// global key table.  Must be <= 63 because we use a uint64 bitfield with the
// top bit reserved as a tag.
const maxKeyTableSize = 63

// topBit is the tag in the first word of a compact map.  When set, the word
// _is_ the bitfield; when clear, the allocation is a fallbackMap.
const topBit = uint64(1) << 63

// globalKeyTable is the package-wide key table shared by all Maps.
var globalKeyTable keyTable

// ---- JSON encoding helpers ----

type kv struct{ key, val string }

// marshalSortedPairs sorts pairs by key and writes them as a JSON object.
func marshalSortedPairs(pairs []kv) ([]byte, error) {
	slices.SortFunc(pairs, func(a, b kv) int {
		return cmp.Compare(a.key, b.key)
	})
	buf := make([]byte, 0, len(pairs)*40)
	buf = append(buf, '{')
	for i, p := range pairs {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = appendJSONString(buf, p.key)
		buf = append(buf, ':')
		buf = appendJSONString(buf, p.val)
	}
	buf = append(buf, '}')
	return buf, nil
}

// appendJSONString appends a JSON-encoded string (with quotes) to buf.
// All printable ASCII except '"' and '\\' is safe to embed directly in
// a JSON string.  Falls back to json.Marshal for anything else.
//
// Fuzz-tested against encoding/json for correctness.
func appendJSONString(buf []byte, s string) []byte {
	if jsonSafe(s) {
		buf = append(buf, '"')
		buf = append(buf, s...)
		buf = append(buf, '"')
		return buf
	}
	// Slow path: delegate to encoding/json for correct escaping.
	quoted, _ := json.Marshal(s)
	return append(buf, quoted...)
}

// jsonSafe reports whether s contains only bytes that are safe to embed
// in a JSON string without escaping: printable ASCII (0x20..0x7E)
// excluding '"', '\\', and HTML-sensitive characters '&', '<', '>'
// (which json.Marshal escapes by default).
func jsonSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E || c == '"' || c == '\\' || c == '&' || c == '<' || c == '>' {
			return false
		}
	}
	return true
}

// ---- key table ----

// keyTableSnap is an immutable snapshot of the key table.
type keyTableSnap struct {
	byHandle map[uniquestr.Handle]uint8
	byIndex  [maxKeyTableSize]uniquestr.Handle
	len      int
}

func (s *keyTableSnap) clone() *keyTableSnap {
	c := &keyTableSnap{
		byHandle: make(map[uniquestr.Handle]uint8, len(s.byHandle)+8),
		len:      s.len,
	}
	for k, v := range s.byHandle {
		c.byHandle[k] = v
	}
	c.byIndex = s.byIndex
	return c
}

// keyTable maps frequently-seen label keys to bit positions.  The read path
// (snap.Load) is lock-free; writes take mu.
type keyTable struct {
	snap atomic.Pointer[keyTableSnap]
	mu   sync.Mutex
}

func init() {
	globalKeyTable.snap.Store(&keyTableSnap{
		byHandle: make(map[uniquestr.Handle]uint8),
	})
}

func (t *keyTable) currentSnap() *keyTableSnap {
	return t.snap.Load()
}

// registerKeys attempts to build a compact map from the pairs in the
// mapBuilder.  On success it returns the *compactMap and true.
// If the table is full and some keys can't be registered, it returns
// (nil, false).
func (t *keyTable) registerKeys(b mapBuilder) (*compactMap, bool) {
	snap := t.snap.Load()

	// Fast path (lock-free): all keys already known.
	var bf uint64
	for _, kv := range b {
		if pos, found := snap.byHandle[kv.k]; found {
			bf |= uint64(1) << pos
		} else {
			return t.registerKeysSlow(b)
		}
	}
	return buildCompact(snap, bf, b), true
}

// registerKeysSlow is the mutex-protected path for registering new keys.
func (t *keyTable) registerKeysSlow(b mapBuilder) (*compactMap, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	snap := t.snap.Load()

	// Count unknown keys.
	unknowns := 0
	for _, kv := range b {
		if _, found := snap.byHandle[kv.k]; !found {
			unknowns++
		}
	}
	if unknowns == 0 {
		// All keys now known (registered by another goroutine).
		var bf uint64
		for _, kv := range b {
			bf |= uint64(1) << snap.byHandle[kv.k]
		}
		return buildCompact(snap, bf, b), true
	}
	if snap.len+unknowns > maxKeyTableSize {
		return nil, false
	}

	// Clone and register new keys.
	snap = snap.clone()
	var bf uint64
	for _, kv := range b {
		if pos, found := snap.byHandle[kv.k]; found {
			bf |= uint64(1) << pos
		} else {
			pos := uint8(snap.len)
			snap.byHandle[kv.k] = pos
			snap.byIndex[pos] = kv.k
			snap.len++
			bf |= uint64(1) << pos
		}
	}
	t.snap.Store(snap)
	return buildCompact(snap, bf, b), true
}

// buildCompact allocates a compactMap and populates its values directly,
// avoiding an intermediate slice allocation.
func buildCompact(snap *keyTableSnap, bf uint64, b mapBuilder) *compactMap {
	cm := allocCompact(bf|topBit, len(b))
	vals := cm.slice()
	for _, kv := range b {
		pos := snap.byHandle[kv.k]
		arrayIdx := bits.OnesCount64(bf & ((uint64(1) << pos) - 1))
		vals[arrayIdx] = kv.v
	}
	return cm
}
