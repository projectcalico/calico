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
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/projectcalico/calico/lib/std/uniquestr"
)

func TestInternedLabelsJSONRoundTrip(t *testing.T) {
	for _, m := range []map[string]string{
		nil,
		{},
		{"foo": "bar", "bar": "baz"},
	} {
		t.Run(fmt.Sprint(m), func(t *testing.T) {
			j, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}

			in := Make(m)
			j2, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(j, j2) {
				t.Errorf("Interned map should produce same JSON as normal map; got %s, want %s", j2, j)
			}

			var out Map
			err = json.Unmarshal(j2, &out)
			if err != nil {
				t.Fatal(err)
			}
			if !in.Equals(out) {
				t.Errorf("Interned map didn't round trip. Got %v, want %v", out, in)
			}
		})
	}
}

func TestUnmarshalBadJSON(t *testing.T) {
	var out Map
	err := json.Unmarshal([]byte("[]"), &out)
	if err == nil {
		t.Errorf("Unmarshal didn't fail on invalid JSON")
	}
}

func TestGetString(t *testing.T) {
	m := Make(map[string]string{"a": "b", "c": "d"})

	v, ok := m.GetString("a")
	if !ok || v != "b" {
		t.Errorf("GetString(\"a\") didn't return \"b\"")
	}
	v, ok = m.GetString("c")
	if !ok || v != "d" {
		t.Errorf("GetString(\"c\") didn't return \"d\"")
	}
	v, ok = m.GetString("foo")
	if ok || v != "" {
		t.Errorf("GetString(\"foo\") didn't return nil, false")
	}
}

func TestAllStrings(t *testing.T) {
	input := map[string]string{"a": "b", "c": "d"}
	m := Make(input)
	seen := map[string]string{}
	for k, v := range m.AllStrings() {
		if _, ok := seen[k]; ok {
			t.Errorf("AllStrings returned duplicate key %q", k)
		}
		seen[k] = v
	}
	if !reflect.DeepEqual(seen, input) {
		t.Errorf("AllStrings didn't produce same map; got %v, want %v", seen, input)
	}

	// Check that break is properly handled.
	for range m.AllStrings() {
		break
	}
}

func TestAllHandles(t *testing.T) {
	input := map[string]string{"a": "b", "c": "d"}
	m := Make(input)
	seen := map[string]string{}
	for k, v := range m.AllHandles() {
		if _, ok := seen[k.Value()]; ok {
			t.Errorf("AllStrings returned duplicate key %q", k.Value())
		}
		seen[k.Value()] = v.Value()
	}
	if !reflect.DeepEqual(seen, input) {
		t.Errorf("AllHandles didn't produce same map; got %v, want %v", seen, input)
	}

	// Check that break is properly handled.
	for range m.AllHandles() {
		break
	}
}

func TestIntersectAndFilter(t *testing.T) {
	for _, tc := range []struct {
		description      string
		m1, m2, expected map[string]string
		filter           func(uniquestr.Handle, uniquestr.Handle) bool
	}{
		{
			description: "nil with empty",
			m1:          nil,
			m2:          map[string]string{},
			expected:    nil,
		},
		{
			description: "empty with empty",
			m1:          map[string]string{},
			m2:          map[string]string{},
			expected:    map[string]string{},
		},
		{
			description: "empty with a:b",
			m1:          map[string]string{},
			m2:          map[string]string{"a": "b"},
			expected:    map[string]string{},
		},
		{
			description: "a:b with a:b",
			m1:          map[string]string{"a": "b"},
			m2:          map[string]string{"a": "b"},
			expected:    map[string]string{"a": "b"},
		},
		{
			description: "a:b with c:d",
			m1:          map[string]string{"a": "b"},
			m2:          map[string]string{"c": "d"},
			expected:    map[string]string{},
		},
		{
			description: "a:b with a:b c:d",
			m1:          map[string]string{"a": "b"},
			m2:          map[string]string{"a": "b", "c": "d"},
			expected:    map[string]string{"a": "b"},
		},
		{
			description: "a:b c:d with a:b c:e",
			m1:          map[string]string{"a": "b", "c": "d"},
			m2:          map[string]string{"a": "b", "c": "e"},
			expected:    map[string]string{"a": "b"},
		},
		{
			description: "a:b with a:b c:d filter on a",
			m1:          map[string]string{"a": "b", "c": "d"},
			m2:          map[string]string{"a": "b", "c": "d"},
			expected:    map[string]string{"a": "b"},
			filter: func(h uniquestr.Handle, _ uniquestr.Handle) bool {
				return h.Value() == "a"
			},
		},
		{
			description: "a:b with a:b c:d filter on c",
			m1:          map[string]string{"a": "b", "c": "d"},
			m2:          map[string]string{"a": "b", "c": "d"},
			expected:    map[string]string{"c": "d"},
			filter: func(h uniquestr.Handle, _ uniquestr.Handle) bool {
				return h.Value() == "c"
			},
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			um1 := Make(tc.m1)
			um2 := Make(tc.m2)
			out := IntersectAndFilter(um1, um2, tc.filter).RecomputeOriginalMap()
			if !reflect.DeepEqual(out, tc.expected) {
				t.Fatalf("IntersectAndFilter(%v,%v) returned unexpected result; got %v, want %v",
					tc.m1, tc.m2, out, tc.expected)
			}

			out = IntersectAndFilter(um2, um1, tc.filter).RecomputeOriginalMap()
			if !reflect.DeepEqual(out, tc.expected) {
				t.Errorf("IntersectAndFilter(%v,%v) returned unexpected result; got %v, want %v",
					tc.m2, tc.m1, out, tc.expected)
			}
		})
	}
}
