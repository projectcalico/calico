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

package policystore

import (
	"testing"

	"github.com/projectcalico/calico/felix/proto"
)

func TestProcessUpdateBumpsGeneration(t *testing.T) {
	store := NewPolicyStore()
	wepID := &proto.WorkloadEndpointID{OrchestratorId: "k8s", WorkloadId: "ns/pod", EndpointId: "eth0"}
	updates := []*proto.ToDataplane{
		{Payload: &proto.ToDataplane_IpsetUpdate{IpsetUpdate: &proto.IPSetUpdate{Id: "s", Type: proto.IPSetUpdate_NET}}},
		{Payload: &proto.ToDataplane_IpsetDeltaUpdate{IpsetDeltaUpdate: &proto.IPSetDeltaUpdate{Id: "s", AddedMembers: []string{"10.0.0.1/32"}}}},
		{Payload: &proto.ToDataplane_ActivePolicyUpdate{ActivePolicyUpdate: &proto.ActivePolicyUpdate{Id: &proto.PolicyID{Name: "p"}, Policy: &proto.Policy{}}}},
		{Payload: &proto.ToDataplane_ActivePolicyRemove{ActivePolicyRemove: &proto.ActivePolicyRemove{Id: &proto.PolicyID{Name: "p"}}}},
		{Payload: &proto.ToDataplane_ActiveProfileUpdate{ActiveProfileUpdate: &proto.ActiveProfileUpdate{Id: &proto.ProfileID{Name: "pr"}, Profile: &proto.Profile{}}}},
		{Payload: &proto.ToDataplane_ActiveProfileRemove{ActiveProfileRemove: &proto.ActiveProfileRemove{Id: &proto.ProfileID{Name: "pr"}}}},
		{Payload: &proto.ToDataplane_WorkloadEndpointUpdate{WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{Id: wepID, Endpoint: &proto.WorkloadEndpoint{}}}},
		{Payload: &proto.ToDataplane_WorkloadEndpointRemove{WorkloadEndpointRemove: &proto.WorkloadEndpointRemove{Id: wepID}}},
		{Payload: &proto.ToDataplane_ServiceAccountUpdate{ServiceAccountUpdate: &proto.ServiceAccountUpdate{Id: &proto.ServiceAccountID{Name: "sa", Namespace: "ns"}}}},
		{Payload: &proto.ToDataplane_ServiceAccountRemove{ServiceAccountRemove: &proto.ServiceAccountRemove{Id: &proto.ServiceAccountID{Name: "sa", Namespace: "ns"}}}},
		{Payload: &proto.ToDataplane_NamespaceUpdate{NamespaceUpdate: &proto.NamespaceUpdate{Id: &proto.NamespaceID{Name: "ns"}}}},
		{Payload: &proto.ToDataplane_NamespaceRemove{NamespaceRemove: &proto.NamespaceRemove{Id: &proto.NamespaceID{Name: "ns"}}}},
		{Payload: &proto.ToDataplane_IpsetRemove{IpsetRemove: &proto.IPSetRemove{Id: "s"}}},
	}
	for i, u := range updates {
		store.ProcessUpdate("per-host-policies", u)
		if store.Generation != uint64(i+1) {
			t.Fatalf("after update %d (%T): generation %d", i, u.Payload, store.Generation)
		}
	}
	store.ProcessUpdate("per-host-policies", &proto.ToDataplane{Payload: &proto.ToDataplane_InSync{InSync: &proto.InSync{}}})
	if store.Generation != uint64(len(updates)) {
		t.Fatalf("InSync moved the generation to %d", store.Generation)
	}
}

func TestVerdictCacheGenerationAndCapacity(t *testing.T) {
	stats := &VerdictCacheStats{}
	c := NewVerdictCache(2, stats)
	k1, k2, k3 := VerdictKey{DstPort: 1}, VerdictKey{DstPort: 2}, VerdictKey{DstPort: 3}

	if _, ok := c.Lookup(1, k1); ok {
		t.Fatal("hit on an empty cache")
	}
	c.Store(1, k1, "a")
	if v, ok := c.Lookup(1, k1); !ok || v != "a" {
		t.Fatalf("lookup after store: %v %v", v, ok)
	}
	if stats.Hits.Load() != 1 || stats.Misses.Load() != 1 {
		t.Fatalf("stats after one miss and one hit: %+v", stats)
	}

	// At capacity the cache starts over.
	c.Store(1, k2, "b")
	if c.Len() != 2 {
		t.Fatalf("len %d, want 2", c.Len())
	}
	c.Store(1, k3, "c")
	if c.Len() != 1 || stats.Evictions.Load() != 1 {
		t.Fatalf("after eviction: len %d evictions %d", c.Len(), stats.Evictions.Load())
	}
	if _, ok := c.Lookup(1, k1); ok {
		t.Fatal("k1 survived the eviction")
	}
	if v, ok := c.Lookup(1, k3); !ok || v != "c" {
		t.Fatal("k3 was not kept")
	}

	// A new generation empties it.
	if _, ok := c.Lookup(2, k3); ok {
		t.Fatal("entry survived a generation change")
	}
	if c.Len() != 0 || stats.Resets.Load() != 1 {
		t.Fatalf("after generation change: len %d resets %d", c.Len(), stats.Resets.Load())
	}
	// Seeing the same new generation again is not a reset.
	c.Store(2, k1, "a")
	if _, ok := c.Lookup(2, k1); !ok || stats.Resets.Load() != 1 {
		t.Fatalf("second use of generation 2 reset the cache: resets %d", stats.Resets.Load())
	}

	// A zero-capacity cache stores nothing.
	z := NewVerdictCache(0, nil)
	z.Store(1, k1, "a")
	if _, ok := z.Lookup(1, k1); ok || z.Len() != 0 {
		t.Fatal("zero-capacity cache stored an entry")
	}
}

func TestVerdictCacheEndpointFlag(t *testing.T) {
	stats := &VerdictCacheStats{}
	c := NewVerdictCache(8, stats)
	ep, other := &proto.WorkloadEndpoint{Name: "a"}, &proto.WorkloadEndpoint{Name: "b"}
	calls := 0
	compute := func() bool { calls++; return calls%2 == 1 }

	if !c.EndpointFlag(1, ep, 0, 0, compute) || calls != 1 {
		t.Fatalf("first computation: calls %d", calls)
	}
	if !c.EndpointFlag(1, ep, 0, 0, compute) || calls != 1 {
		t.Fatalf("memoised value not returned: calls %d", calls)
	}
	// Direction, scope and endpoint are part of the memo key.
	c.EndpointFlag(1, ep, 0, 1, compute)
	c.EndpointFlag(1, ep, 1, 0, compute)
	c.EndpointFlag(1, other, 0, 0, compute)
	if calls != 4 {
		t.Fatalf("expected one computation per key, got %d", calls)
	}
	// A new generation recomputes.
	c.EndpointFlag(2, ep, 0, 0, compute)
	if calls != 5 || stats.Resets.Load() != 1 {
		t.Fatalf("after generation change: calls %d resets %d", calls, stats.Resets.Load())
	}
}

func TestWithVerdictCacheOnEveryStore(t *testing.T) {
	stats := &VerdictCacheStats{}
	m := NewPolicyStoreManagerWithOpts(WithVerdictCache(8, stats))
	var pending *PolicyStore
	m.DoWithLock(func(s *PolicyStore) {
		pending = s
		if s.Verdicts == nil || s.Verdicts.Stats() != stats {
			t.Fatal("pending store has no cache with the shared stats")
		}
	})
	m.OnInSync()
	m.DoWithReadLock(func(s *PolicyStore) {
		if s != pending || s.Verdicts == nil {
			t.Fatal("current store after sync is not the cached pending store")
		}
	})
	m.OnReconnecting()
	m.DoWithLock(func(s *PolicyStore) {
		if s == pending || s.Verdicts == nil || s.Verdicts.Stats() != stats {
			t.Fatal("store created on reconnect has no cache with the shared stats")
		}
	})

	NewPolicyStoreManager().DoWithReadLock(func(s *PolicyStore) {
		if s.Verdicts != nil {
			t.Fatal("default manager created a cache")
		}
	})
}
