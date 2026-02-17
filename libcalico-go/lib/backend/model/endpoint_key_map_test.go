// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package model

import (
	"testing"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func TestWorkloadEndpointKeyMap(t *testing.T) {
	var m WorkloadEndpointKeyMap[string]

	k8sDefault := MakeWorkloadEndpointKey("node1", "k8s", "ns/pod1", "eth0")
	k8sNonDefault := MakeWorkloadEndpointKey("node1", "k8s", "ns/pod2", "eth1")
	generic := MakeWorkloadEndpointKey("node1", "openstack", "vm1", "tap0")

	// Zero value should be usable (empty).
	if m.Len() != 0 {
		t.Fatalf("expected empty map, got %d", m.Len())
	}
	if _, ok := m.Get(k8sDefault); ok {
		t.Fatal("expected not found in empty map")
	}

	// Set and Get.
	m.Set(k8sDefault, "default")
	m.Set(k8sNonDefault, "nondefault")
	m.Set(generic, "generic")

	if m.Len() != 3 {
		t.Fatalf("expected 3, got %d", m.Len())
	}

	for _, tc := range []struct {
		key  WorkloadEndpointKey
		want string
	}{
		{k8sDefault, "default"},
		{k8sNonDefault, "nondefault"},
		{generic, "generic"},
	} {
		v, ok := m.Get(tc.key)
		if !ok || v != tc.want {
			t.Fatalf("Get(%v) = %q, %v; want %q, true", tc.key, v, ok, tc.want)
		}
	}

	// Delete.
	m.Delete(k8sNonDefault)
	if m.Len() != 2 {
		t.Fatalf("expected 2 after delete, got %d", m.Len())
	}
	if _, ok := m.Get(k8sNonDefault); ok {
		t.Fatal("expected not found after delete")
	}

	// All iteration.
	seen := set.New[string]()
	for _, v := range m.All() {
		seen.Add(v)
	}
	if seen.Len() != 2 || !seen.Contains("default") || !seen.Contains("generic") {
		t.Fatalf("unexpected All() results: %v", seen)
	}
}

func TestEndpointKeyMap(t *testing.T) {
	var m EndpointKeyMap[int]

	wep := MakeWorkloadEndpointKey("node1", "k8s", "ns/pod1", "eth0")
	hep := MakeHostEndpointKey("node1", "eth0")

	m.Set(wep, 1)
	m.Set(hep, 2)

	if m.Len() != 2 {
		t.Fatalf("expected 2, got %d", m.Len())
	}

	v, ok := m.Get(wep)
	if !ok || v != 1 {
		t.Fatalf("Get(wep) = %d, %v; want 1, true", v, ok)
	}
	v, ok = m.Get(hep)
	if !ok || v != 2 {
		t.Fatalf("Get(hep) = %d, %v; want 2, true", v, ok)
	}

	m.Delete(wep)
	if m.Len() != 1 {
		t.Fatalf("expected 1 after delete, got %d", m.Len())
	}

	// All iteration.
	count := 0
	for range m.All() {
		count++
	}
	if count != 1 {
		t.Fatalf("expected 1 item in All(), got %d", count)
	}
}

func TestEndpointKeySet(t *testing.T) {
	var s EndpointKeySet

	wep := MakeWorkloadEndpointKey("node1", "k8s", "ns/pod1", "eth0").(EndpointKey)
	hep := EndpointKey(MakeHostEndpointKey("node1", "eth0"))

	s.Add(wep)
	s.Add(hep)

	if s.Len() != 2 {
		t.Fatalf("expected 2, got %d", s.Len())
	}
	if !s.Contains(wep) {
		t.Fatal("expected contains wep")
	}
	if !s.Contains(hep) {
		t.Fatal("expected contains hep")
	}

	s.Discard(wep)
	if s.Contains(wep) {
		t.Fatal("expected not contains wep after discard")
	}
	if s.Len() != 1 {
		t.Fatalf("expected 1 after discard, got %d", s.Len())
	}

	// AllKeys iteration.
	count := 0
	for range s.AllKeys() {
		count++
	}
	if count != 1 {
		t.Fatalf("expected 1 key, got %d", count)
	}

	// Clear.
	s.Clear()
	if s.Len() != 0 {
		t.Fatalf("expected 0 after clear, got %d", s.Len())
	}
}

func TestWorkloadEndpointKeyMapDeleteFromNilMap(t *testing.T) {
	// Deleting from zero-value map should not panic.
	var m WorkloadEndpointKeyMap[string]
	m.Delete(MakeWorkloadEndpointKey("node1", "k8s", "ns/pod1", "eth0"))
}

func TestEndpointKeyMapGetMiss(t *testing.T) {
	// Get on zero-value map returns zero value.
	var m EndpointKeyMap[*int]
	v, ok := m.Get(MakeHostEndpointKey("node1", "eth0"))
	if ok || v != nil {
		t.Fatalf("expected nil, false; got %v, %v", v, ok)
	}
}
