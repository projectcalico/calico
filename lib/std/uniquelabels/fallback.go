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
	"github.com/projectcalico/calico/lib/std/uniquestr"
)

// fallbackMap is used when the key table is full or a map can't use the
// compact representation.  The sentinel field occupies the same position as
// the bitfield in the compact types; its top bit is always clear.
type fallbackMap struct {
	sentinel uint64 // always 0
	m        handleMap
}

func (fm *fallbackMap) len() int {
	return len(fm.m)
}

func (fm *fallbackMap) getHandle(h uniquestr.Handle) (uniquestr.Handle, bool) {
	v, ok := fm.m[h]
	return v, ok
}

// marshalJSON writes a JSON object from the fallback handle map.
func (fm *fallbackMap) marshalJSON() ([]byte, error) {
	n := len(fm.m)
	if n == 0 {
		return []byte("{}"), nil
	}
	var backing [maxKeyTableSize]kv
	// Fallback maps can exceed maxKeyTableSize; heap-allocate if needed.
	var pairs []kv
	if n <= maxKeyTableSize {
		pairs = backing[:n]
	} else {
		pairs = make([]kv, n)
	}
	i := 0
	for k, v := range fm.m {
		pairs[i] = kv{key: k.Value(), val: v.Value()}
		i++
	}
	return marshalSortedPairs(pairs)
}
