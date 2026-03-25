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

package uniquelabels

import (
	"cmp"
	"encoding/json"
	"fmt"
	"iter"
	"maps"
	"slices"

	"github.com/projectcalico/calico/lib/std/uniquestr"
)

type handleMap = map[uniquestr.Handle]uniquestr.Handle

var (
	Nil   = Map{m: nil}
	Empty = Map{m: map[uniquestr.Handle]uniquestr.Handle{}}
)

// Map is a *read only* string-to-string map that interns keys and values.
// When marshalled as JSON, uses the same representation as a normal
// map[string]string.  When unmarshalled, keys and values get interned/deduped.
//
// To allow drop-in replacement of a map[string]string, Map has unique
// representations of nil (Nil) and empty (Empty). The zero value of a Map is
// the Nil value; it can be detected with IsNil(). Map is a value type, which
// precludes using Go's normal nil.  Making Map a pointer type would increase
// overheads; making map an alias for map[uniquestr.Handle]uniquestr.Handle
// would break the read-only property, preventing future optimisations.
//
// Uses uniquestr.Handle internally, so it is most efficient to query the map
// using AllHandles() and GetHandle().
type Map struct {
	_ [0]func() // Explicitly non-comparable; must use Equals() method.
	m handleMap
}

// EquivalentTo reports whether this Map contains exactly the same entries as
// the given map[string]string. Iterates the Map's handles, converting back to
// strings via pointer dereference rather than iterating the input map (which
// would require uniquestr.Make per key lookup).
func (i Map) EquivalentTo(m map[string]string) bool {
	if i.IsNil() != (m == nil) {
		return false
	}
	if len(m) != i.Len() {
		return false
	}
	for k, v := range i.AllStrings() {
		if mv, ok := m[k]; !ok || mv != v {
			return false
		}
	}
	return true
}

// Make makes an interned copy of the given map.  In order to benefit from
// interning the map, the original map must be discarded and only the interned
// copy should be kept.
//
// If passed nil, returns the zero value of Map.  If passed an empty map,
// returns the singleton Empty.
//
// Make caches recently-returned Maps so that repeated calls with the same input
// return the same Map, avoiding redundant handleMap allocations.
func Make(m map[string]string) Map {
	if m == nil {
		return Nil
	}
	if len(m) == 0 {
		return Empty
	}

	if cached, hash, ok := recentCache.Lookup(m); ok {
		return cached
	} else {
		hm := make(handleMap, len(m))
		for k, v := range m {
			hm[uniquestr.Make(k)] = uniquestr.Make(v)
		}
		result := Map{m: hm}
		recentCache.Store(hash, result)
		return result
	}
}

// Equals returns true if the map contains the same key/value pairs as the
// other map.  In line with maps.Equal, Nil and Empty compare equal.
func (i Map) Equals(other Map) bool {
	return maps.Equal(i.m, other.m)
}

// MarshalJSON implements the json.Marshaler interface. Must be defined on the
// value receiver so that Map can be embedded in other structs.
//
// Writes JSON directly with sorted keys, avoiding encoding/json reflection
// on the handleMap (Go 1.26's encoding/json panics on unique.Handle map keys).
func (i Map) MarshalJSON() ([]byte, error) {
	if i.m == nil {
		return []byte("null"), nil
	}
	n := len(i.m)
	if n == 0 {
		return []byte("{}"), nil
	}
	// Stack-allocate space for up to 20 key-value pairs, which covers
	// the vast majority of Kubernetes label maps.  Maps with more entries
	// transparently spill to the heap via append.
	var pairsArr [20]keyVal
	pairs := pairsArr[:0]
	for k, v := range i.m {
		pairs = append(pairs, keyVal{key: k.Value(), val: v.Value()})
	}
	slices.SortFunc(pairs, func(a, b keyVal) int {
		return cmp.Compare(a.key, b.key)
	})
	buf := make([]byte, 0, n*40)
	buf = append(buf, '{')
	for j, p := range pairs {
		if j > 0 {
			buf = append(buf, ',')
		}
		buf = appendJSONString(buf, p.key)
		buf = append(buf, ':')
		buf = appendJSONString(buf, p.val)
	}
	buf = append(buf, '}')
	return buf, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.  Must be defined on
// the pointer receiver so that it can have side effects.
func (i *Map) UnmarshalJSON(data []byte) error {
	var hm handleMap
	if err := json.Unmarshal(data, &hm); err != nil {
		return err
	}
	i.m = hm
	return nil
}

func (i Map) AllHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return func(yield func(uniquestr.Handle, uniquestr.Handle) bool) {
		for k, v := range i.m {
			if !yield(k, v) {
				return
			}
		}
	}
}

func (i Map) AllStrings() iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for k, v := range i.m {
			if !yield(k.Value(), v.Value()) {
				return
			}
		}
	}
}

func (i Map) RecomputeOriginalMap() map[string]string {
	if i.m == nil {
		return nil
	}
	m := make(map[string]string, len(i.m))
	for k, v := range i.m {
		m[k.Value()] = v.Value()
	}
	return m
}

func (i Map) GetString(k string) (string, bool) {
	v, ok := (i.m)[uniquestr.Make(k)]
	if !ok {
		return "", false
	}
	return v.Value(), true
}

func (i Map) GetHandle(h uniquestr.Handle) (uniquestr.Handle, bool) {
	v, ok := (i.m)[h]
	if !ok {
		return uniquestr.Handle{}, false
	}
	return uniquestr.Handle(v), true
}

func (i Map) Len() int {
	return len(i.m)
}

func (i Map) IsNil() bool {
	return i.m == nil
}

func (i Map) String() string {
	return fmt.Sprint(i.RecomputeOriginalMap())
}

// IntersectAndFilter returns a Map that contains only the keys/value pairs that
// are both:
//
// - Common to both input Maps.
// - Match the include predicate.
//
// If either map is Nil, returns Nil.  Otherwise, returns a non-Nil, but
// possibly empty Map.  May return one of the input maps.
func IntersectAndFilter(a, b Map, include func(uniquestr.Handle, uniquestr.Handle) bool) Map {
	if a.IsNil() || b.IsNil() {
		return Nil
	}

	if b.Len() < a.Len() {
		// Always iterate over the shorter map. This reduces the number of
		// iterations and, if the shorter map is a subset of the larger, we
		// can return the smaller map rather than duplicating.
		return IntersectAndFilter(b, a, include)
	}

	if include == nil {
		include = noOpFilter
	}

	// Do a pass to determine if we need to allocate a new map.
	needToFilter := false
	for k, v := range a.m {
		if !include(k, v) {
			needToFilter = true
			break
		}
		if otherV, ok := b.GetHandle(k); !ok || otherV != v {
			needToFilter = true
			break
		}
	}
	if !needToFilter {
		// Map a _is_ the intersection.
		return a
	}

	// We _do_ need to make a new map, re-do the calculation.
	intersection := map[uniquestr.Handle]uniquestr.Handle{}
	for k, v := range a.m {
		if !include(k, v) {
			continue
		}
		if otherV, ok := b.GetHandle(k); !ok || otherV != v {
			continue
		}
		intersection[k] = v
	}
	if len(intersection) == 0 {
		return Empty
	}
	return Map{m: intersection}
}

func noOpFilter(uniquestr.Handle, uniquestr.Handle) bool {
	return true
}

// keyVal is a string key-value pair used for JSON marshalling.
type keyVal struct{ key, val string }

// appendJSONString appends a JSON-encoded string (with quotes) to buf.
// All printable ASCII except '"', '\\', '&', '<', and '>' is safe to embed
// directly in a JSON string.  Falls back to json.Marshal for anything else.
func appendJSONString(buf []byte, s string) []byte {
	if jsonSafe(s) {
		buf = append(buf, '"')
		buf = append(buf, s...)
		buf = append(buf, '"')
		return buf
	}
	// Slow path: delegate to encoding/json for correct escaping.
	quoted, err := json.Marshal(s)
	if err != nil {
		panic("appendJSONString: json.Marshal failed: " + err.Error())
	}
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

var _ json.Marshaler = Map{}
var _ json.Unmarshaler = (*Map)(nil)
