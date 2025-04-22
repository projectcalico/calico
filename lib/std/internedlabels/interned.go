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

package internedlabels

import (
	"encoding/json"
	"fmt"
	"github.com/projectcalico/calico/lib/std/unique"
	"iter"
	"maps"
)

type handleMap = map[unique.String]unique.String

// Map is a read only string-to-string map that interns keys and
// values so that each unique key and value string is only stored once.
//
// The current implementation uses unique.String internally, so
// it is most efficient to query the map using AllHandles() and GetHandle().
type Map struct {
	_ [0]func() // Explicitly non-comparable; must use Equals() method.
	m handleMap
}

// Make makes an interned copy of the given map.  In order to benefit from
// interning the map, the original map must be discarded and only the interned
// copy should be kept.
func Make(m map[string]string) Map {
	var hm handleMap
	if m == nil {
		return Map{}
	}
	hm = make(handleMap, len(m))
	for k, v := range m {
		hm[unique.Make(k)] = unique.Make(v)
	}
	return Map{m: hm}
}

func (i Map) Equals(other Map) bool {
	return maps.Equal(i.m, other.m)
}

// MarshalJSON implements the json.Marshaler interface. Must be defined on the
// value receiver so that Map can be embedded in other structs.
func (i Map) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.m)
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

func (i Map) AllHandles() iter.Seq2[unique.String, unique.String] {
	return func(yield func(unique.String, unique.String) bool) {
		for k, v := range i.m {
			if !yield(unique.String(k), unique.String(v)) {
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
	v, ok := (i.m)[unique.Make(k)]
	if !ok {
		return "", false
	}
	return v.Value(), true
}

func (i Map) GetHandle(h unique.String) (unique.String, bool) {
	v, ok := (i.m)[h]
	if !ok {
		return unique.String{}, false
	}
	return unique.String(v), true
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

var _ json.Marshaler = Map{}
var _ json.Unmarshaler = (*Map)(nil)
