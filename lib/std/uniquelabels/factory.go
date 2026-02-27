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
	"hash/maphash"
	"unsafe"

	"github.com/projectcalico/calico/lib/std/uniquestr"
)

// Factory creates and manages uniquelabels.Map values.  Each Factory has
// its own key table and cache, providing isolation.  Use the package-level
// Make function for production code (it delegates to Global).  Tests can
// use NewFactory to get an isolated instance.
type Factory struct {
	kt    keyTable
	cache recentMapCache
}

// NewFactory creates a new Factory with an empty key table and cache.
func NewFactory() *Factory {
	f := &Factory{}
	f.kt.snap.Store(&keyTableSnap{
		byHandle: make(map[uniquestr.Handle]uint8),
	})
	f.cache.seed = maphash.MakeSeed()
	return f
}

// Global is the default Factory used by the package-level Make function
// and UnmarshalJSON.
var Global = NewFactory()

// Make makes an interned copy of the given map using this Factory's
// key table and cache.  In order to benefit from interning the map,
// the original map must be discarded and only the interned copy should
// be kept.
//
// If passed nil, returns the zero value of Map.  If passed an empty map,
// returns the singleton Empty.
//
// Make caches recently-returned Maps so that repeated calls with the same
// input return the same Map, avoiding redundant allocations.
func (f *Factory) Make(m map[string]string) Map {
	if m == nil {
		return Nil
	}
	if len(m) == 0 {
		return Empty
	}

	if cached, hash, ok := f.cache.Lookup(m); ok {
		return cached
	} else {
		result := f.makeInner(m)
		f.cache.Store(hash, result)
		return result
	}
}

// makeInner builds a Map from a non-nil, non-empty map[string]string.
// It tries the compact representation first; falls back to a Go map.
func (f *Factory) makeInner(m map[string]string) Map {
	if bf, vals, ok := f.kt.registerKeys(m); ok {
		return Map{f: f, ptr: allocCompact(bf, vals)}
	}
	hm := make(handleMap, len(m))
	for k, v := range m {
		hm[uniquestr.Make(k)] = uniquestr.Make(v)
	}
	return Map{f: f, ptr: unsafe.Pointer(&fallbackMap{m: hm})}
}
