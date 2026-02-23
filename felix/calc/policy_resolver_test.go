// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
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

package calc

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const (
	testComputedDataKindA EndpointComputedDataKind = "kindA"
	testComputedDataKindB EndpointComputedDataKind = "kindB"
)

type testComputedData struct {
	Value string
}

func (t *testComputedData) ApplyTo(wep *proto.WorkloadEndpoint) {
	// Append to Annotations as a simple way to observe the effect.
	if wep.Annotations == nil {
		wep.Annotations = map[string]string{}
	}
	wep.Annotations["test-computed"] = t.Value
}

func TestPolicyResolver_OnUpdate(t *testing.T) {
	pr, recorder := createPolicyResolver()

	polKey := model.PolicyKey{
		Name: "test-policy",
	}

	policy := model.Policy{Tier: "default"}

	kvp := model.KVPair{
		Key:   polKey,
		Value: &policy,
	}
	update := api.Update{}
	update.Key = kvp.Key
	update.Value = kvp.Value

	pr.OnUpdate(update)

	if _, found := pr.allPolicies[polKey]; !found {
		t.Error("Adding new inactive policy - expected policy to be in AllPolicies but it is not")
	}

	update.Value = nil

	pr.OnUpdate(update)

	if _, found := pr.allPolicies[polKey]; found {
		t.Error("Deleting inactive policy - expected AllPolicies not to contain policy but it does")
	}

	// Haven't sent any endpoints or matches so should get nothing out.
	pr.OnDatamodelStatus(api.InSync)
	pr.Flush()
	if len(recorder.updates) > 0 {
		t.Error("Unexpected updates from policy resolver:", recorder.updates)
	}
}

func createPolicyResolver() (*PolicyResolver, *policyResolverRecorder) {
	pr := NewPolicyResolver()
	recorder := newPolicyResolverRecorder()
	pr.RegisterCallback(recorder)
	return pr, recorder
}

type policyResolverUpdate struct {
	Key          model.Key
	Endpoint     any
	Tiers        []TierInfo
	ComputedData []EndpointComputedData
}

type policyResolverRecorder struct {
	updates []policyResolverUpdate
}

func (p *policyResolverRecorder) OnEndpointTierUpdate(endpointKey model.EndpointKey, endpoint model.Endpoint, computedData []EndpointComputedData, peerData *EndpointBGPPeer, filteredTiers []TierInfo) {
	p.updates = append(p.updates, policyResolverUpdate{
		Key:          endpointKey,
		Endpoint:     endpoint,
		ComputedData: computedData,
		Tiers:        filteredTiers,
	})
}

func newPolicyResolverRecorder() *policyResolverRecorder {
	return &policyResolverRecorder{}
}

func TestPolicyResolver_OnPolicyMatch(t *testing.T) {
	pr, recorder := createPolicyResolver()

	polKey := model.PolicyKey{
		Name: "test-policy",
		Kind: v3.KindNetworkPolicy,
	}

	pol := ExtractPolicyMetadata(&model.Policy{Tier: "default"})

	endpointKey := model.WorkloadEndpointKey{
		Hostname: "test-workload-ep",
	}
	wep := &model.WorkloadEndpoint{
		Name: "we1",
	}
	pr.endpoints[endpointKey] = wep

	pr.allPolicies[polKey] = pol

	// Haven't sent any matches so should get nothing out.
	pr.Flush()
	if len(recorder.updates) > 0 {
		t.Error("Unexpected updates from policy resolver:", recorder.updates)
	}

	pr.OnPolicyMatch(polKey, endpointKey)
	if len(recorder.updates) > 0 {
		// Shouldn't get any updates until we Flush()
		t.Error("Unexpected updates from policy resolver before calling Flush():", recorder.updates)
	}

	if !pr.policyIDToEndpointIDs.ContainsKey(polKey) {
		t.Error("Adding new policy - expected PolicyIDToEndpointIDs to contain new policy but it does not")
	}
	if !pr.endpointIDToPolicyIDs.ContainsKey(endpointKey) {
		t.Error("Adding new policy - expected EndpointIDToPolicyIDs to contain endpoint but it does not")
	}
	if !pr.dirtyEndpoints.Contains(endpointKey) {
		t.Error("Adding new policy - expected DirtyEndpoints to contain endpoint for policy but it does not")
	}

	pr.OnPolicyMatch(polKey, endpointKey)
	pr.OnDatamodelStatus(api.InSync)
	pr.Flush()
	if len(recorder.updates) != 1 {
		t.Fatal("Expected only one update after Flush:", recorder.updates)
	}
	if d := cmp.Diff(recorder.updates[0], policyResolverUpdate{
		Key:      endpointKey,
		Endpoint: wep,
		Tiers: []TierInfo{{
			Name:  "default",
			Valid: true,
			OrderedPolicies: []PolKV{
				{
					Key:   polKey,
					Value: &pol,
				},
			},
		}},
	},
		cmp.AllowUnexported(PolKV{}),
		cmp.Comparer(func(a, b uniquelabels.Map) bool { return a.Equals(b) }),
	); d != "" {
		t.Error("Incorrect update:", d)
	}
}

func TestPolicyResolver_OnPolicyMatchStopped(t *testing.T) {
	pr, recorder := createPolicyResolver()
	pr.OnDatamodelStatus(api.InSync)

	polKey := model.PolicyKey{
		Name: "test-policy",
		Kind: v3.KindNetworkPolicy,
	}

	pol := policyMetadata{}

	endpointKey := model.WorkloadEndpointKey{
		Hostname: "test-workload-ep",
	}

	pr.policySorter.UpdatePolicy(polKey, &pol)

	pr.OnPolicyMatch(polKey, endpointKey)
	pr.OnPolicyMatchStopped(polKey, endpointKey)

	if pr.policyIDToEndpointIDs.ContainsKey(polKey) {
		t.Error("Deleting existing policy - expected PolicyIDToEndpointIDs not to contain policy but it does")
	}
	if pr.endpointIDToPolicyIDs.ContainsKey(endpointKey) {
		t.Error("Deleting existing policy - expected EndpointIDToPolicyIDs not to contain endpoint but it does")
	}
	if !pr.dirtyEndpoints.Contains(endpointKey) {
		t.Error("Deleting existing policy - expected DirtyEndpoints to contain endpoint but it does not")
	}

	pr.OnPolicyMatchStopped(polKey, endpointKey)

	if len(recorder.updates) > 0 {
		// Shouldn't get any updates until we Flush()
		t.Error("Unexpected updates from policy resolver before calling Flush():", recorder.updates)
	}
	pr.Flush()
	if len(recorder.updates) != 1 {
		t.Fatal("Expected one update after Flush:", recorder.updates)
	}
	if d := cmp.Diff(recorder.updates[0], policyResolverUpdate{
		Key:      endpointKey,
		Endpoint: nil,
		Tiers:    []TierInfo{},
	}); d != "" {
		t.Error("Incorrect update:", d)
	}
}

func TestPolicyResolver_ComputedDataIncludedInFlush(t *testing.T) {
	pr, recorder := createPolicyResolver()
	pr.OnDatamodelStatus(api.InSync)

	endpointKey := model.WorkloadEndpointKey{Hostname: "host1"}
	wep := &model.WorkloadEndpoint{Name: "we1"}
	pr.endpoints[endpointKey] = wep

	// Need a policy match to get the endpoint into the flush path.
	polKey := model.PolicyKey{Name: "test-policy", Kind: v3.KindNetworkPolicy}
	pr.allPolicies[polKey] = ExtractPolicyMetadata(&model.Policy{Tier: "default"})
	pr.OnPolicyMatch(polKey, endpointKey)

	cd := &testComputedData{Value: "hello"}
	pr.OnEndpointComputedDataUpdate(endpointKey, testComputedDataKindA, cd)

	pr.Flush()

	if len(recorder.updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(recorder.updates))
	}
	if len(recorder.updates[0].ComputedData) != 1 {
		t.Fatalf("expected 1 computed data entry, got %d", len(recorder.updates[0].ComputedData))
	}
	if recorder.updates[0].ComputedData[0] != cd {
		t.Errorf("expected computed data %v, got %v", cd, recorder.updates[0].ComputedData[0])
	}
}

func TestPolicyResolver_ComputedDataNilRemoves(t *testing.T) {
	pr, recorder := createPolicyResolver()
	pr.OnDatamodelStatus(api.InSync)

	endpointKey := model.WorkloadEndpointKey{Hostname: "host1"}
	wep := &model.WorkloadEndpoint{Name: "we1"}
	pr.endpoints[endpointKey] = wep

	polKey := model.PolicyKey{Name: "test-policy", Kind: v3.KindNetworkPolicy}
	pr.allPolicies[polKey] = ExtractPolicyMetadata(&model.Policy{Tier: "default"})
	pr.OnPolicyMatch(polKey, endpointKey)

	// Add computed data.
	cd := &testComputedData{Value: "hello"}
	pr.OnEndpointComputedDataUpdate(endpointKey, testComputedDataKindA, cd)
	pr.Flush()
	recorder.updates = nil

	// Remove with nil.
	pr.OnEndpointComputedDataUpdate(endpointKey, testComputedDataKindA, nil)
	pr.Flush()

	if len(recorder.updates) != 1 {
		t.Fatalf("expected 1 update after nil removal, got %d", len(recorder.updates))
	}
	if len(recorder.updates[0].ComputedData) != 0 {
		t.Errorf("expected no computed data after nil update, got %d entries", len(recorder.updates[0].ComputedData))
	}

	// Internal map should be cleaned up.
	if _, exists := pr.endpointComputedData[endpointKey]; exists {
		t.Error("expected endpointComputedData entry to be cleaned up")
	}
}

func TestPolicyResolver_ComputedDataNilToNilIsNoOp(t *testing.T) {
	pr, _ := createPolicyResolver()
	pr.OnDatamodelStatus(api.InSync)

	endpointKey := model.WorkloadEndpointKey{Hostname: "host1"}
	wep := &model.WorkloadEndpoint{Name: "we1"}
	pr.endpoints[endpointKey] = wep

	polKey := model.PolicyKey{Name: "test-policy", Kind: v3.KindNetworkPolicy}
	pr.allPolicies[polKey] = ExtractPolicyMetadata(&model.Policy{Tier: "default"})
	pr.OnPolicyMatch(polKey, endpointKey)
	pr.Flush()

	// Clear dirty set after initial flush.
	pr.dirtyEndpoints.Clear()

	// nil → nil should not dirty the endpoint.
	pr.OnEndpointComputedDataUpdate(endpointKey, testComputedDataKindA, nil)

	if pr.dirtyEndpoints.Contains(endpointKey) {
		t.Error("nil-to-nil computed data update should not dirty the endpoint")
	}
}

func TestPolicyResolver_ComputedDataMultipleKinds(t *testing.T) {
	pr, recorder := createPolicyResolver()
	pr.OnDatamodelStatus(api.InSync)

	endpointKey := model.WorkloadEndpointKey{Hostname: "host1"}
	wep := &model.WorkloadEndpoint{Name: "we1"}
	pr.endpoints[endpointKey] = wep

	polKey := model.PolicyKey{Name: "test-policy", Kind: v3.KindNetworkPolicy}
	pr.allPolicies[polKey] = ExtractPolicyMetadata(&model.Policy{Tier: "default"})
	pr.OnPolicyMatch(polKey, endpointKey)

	cdA := &testComputedData{Value: "a"}
	cdB := &testComputedData{Value: "b"}
	pr.OnEndpointComputedDataUpdate(endpointKey, testComputedDataKindA, cdA)
	pr.OnEndpointComputedDataUpdate(endpointKey, testComputedDataKindB, cdB)

	pr.Flush()

	if len(recorder.updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(recorder.updates))
	}
	if len(recorder.updates[0].ComputedData) != 2 {
		t.Fatalf("expected 2 computed data entries, got %d", len(recorder.updates[0].ComputedData))
	}
	// Since map iteration order is non-deterministic, check both are present.
	found := map[string]bool{}
	for _, cd := range recorder.updates[0].ComputedData {
		found[cd.(*testComputedData).Value] = true
	}
	if !found["a"] || !found["b"] {
		t.Errorf("expected both computed data kinds, got %v", found)
	}
}

func TestPolicyResolver_EndpointDeleteClearsComputedData(t *testing.T) {
	pr, _ := createPolicyResolver()
	pr.OnDatamodelStatus(api.InSync)

	endpointKey := model.WorkloadEndpointKey{Hostname: "host1"}
	wep := &model.WorkloadEndpoint{Name: "we1"}
	pr.endpoints[endpointKey] = wep

	// Add computed data.
	cd := &testComputedData{Value: "hello"}
	pr.OnEndpointComputedDataUpdate(endpointKey, testComputedDataKindA, cd)

	// Delete the endpoint via OnUpdate.
	pr.OnUpdate(api.Update{
		KVPair: model.KVPair{
			Key:   endpointKey,
			Value: nil,
		},
	})

	if _, exists := pr.endpointComputedData[endpointKey]; exists {
		t.Error("expected endpointComputedData to be cleaned up after endpoint deletion")
	}
}
