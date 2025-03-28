// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package packedmap

import (
	"reflect"
	"testing"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
)

type exampleStruct struct {
	Field1 string         `json:"field_one,omitempty"`
	Field2 bool           `json:"field_two,omitempty"`
	Field3 map[string]int `json:"field_three,omitemepty"`
}

func TestCompressedJSON(t *testing.T) {
	// Create a new map.
	m := MakeCompressedJSON[string, exampleStruct]()

	// Add some entries.
	empty := exampleStruct{}
	m.Set("empty", empty)
	simple := exampleStruct{Field1: "hello", Field2: true}
	m.Set("simple", simple)
	fullyLoaded := exampleStruct{
		Field1: "world",
		Field2: false,
		Field3: map[string]int{"aaaaaaaaaaaaa": 1, "bbbbbbbbbbbbb": 2},
	}
	m.Set("fullyLoaded", fullyLoaded)

	if m.Len() != 3 {
		t.Errorf("Expected 3 entries")
	}

	// Check the entries.
	if v, ok := m.Get("empty"); !ok || !reflect.DeepEqual(v, empty) {
		t.Errorf("Expected empty entry")
	}
	if v, ok := m.Get("simple"); !ok || !reflect.DeepEqual(v, simple) {
		t.Errorf("Expected simple entry")
	}
	if v, ok := m.Get("fullyLoaded"); !ok || !reflect.DeepEqual(v, fullyLoaded) {
		t.Errorf("Expected fullyLoaded entry")
	}
	if _, ok := m.Get("missing"); ok {
		t.Errorf("Expected missing entry")
	}

	// Check deletion.
	m.Delete("simple")
	if m.Len() != 2 {
		t.Errorf("Expected 2 entries after deletion")
	}

	// Check compression is working.
	rawJSON, err := json.Marshal(fullyLoaded)
	if err != nil {
		t.Errorf("Failed to marshal JSON: %v", err)
	}
	if len(rawJSON) <= len(m.m["fullyLoaded"]) {
		// The test JSON isn't too long but there's enough redundancy for snappy to make savings.
		t.Errorf("Expected compression")
	}
}

func TestDedupe(t *testing.T) {
	// Create a new map.
	m := MakeDedupedCompressedJSON[string, exampleStruct]()

	// Add some entries.
	fullyLoaded := exampleStruct{
		Field1: "world",
		Field2: false,
		Field3: map[string]int{"aaaaaaaaaaaaa": 1, "bbbbbbbbbbbbb": 2},
	}
	m.Set("fullyLoaded", fullyLoaded)
	m.Set("fullyLoadedCopy", fullyLoaded)

	if m.Len() != 2 {
		t.Errorf("Expected 3 entries")
	}

	// Check the entries.
	if v, ok := m.Get("fullyLoaded"); !ok || !reflect.DeepEqual(v, fullyLoaded) {
		t.Errorf("Expected fullyLoaded entry")
	}
	if v, ok := m.Get("fullyLoadedCopy"); !ok || !reflect.DeepEqual(v, fullyLoaded) {
		t.Errorf("Expected fullyLoaded entry")
	}

	// Check dedupe is working.
	h1 := m.m["fullyLoaded"]
	h2 := m.m["fullyLoadedCopy"]
	if h1 != h2 {
		t.Errorf("Expected dedupe")
	}
}
