package calc

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

func TestPolicyResolver_OnUpdate(t *testing.T) {
	pr, recorder := createPolicyResolver()

	polKey := model.PolicyKey{
		Name: "test-policy",
	}

	policy := model.Policy{}

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
	pr.Callbacks = recorder
	return pr, recorder
}

type policyResolverUpdate struct {
	Key      model.Key
	Endpoint interface{}
	Tiers    []TierInfo
}

type policyResolverRecorder struct {
	updates []policyResolverUpdate
}

func (p *policyResolverRecorder) OnEndpointTierUpdate(endpointKey model.Key, endpoint interface{}, filteredTiers []TierInfo) {
	p.updates = append(p.updates, policyResolverUpdate{
		Key:      endpointKey,
		Endpoint: endpoint,
		Tiers:    filteredTiers,
	})
}

func newPolicyResolverRecorder() *policyResolverRecorder {
	return &policyResolverRecorder{}
}

func TestPolicyResolver_OnPolicyMatch(t *testing.T) {
	pr, recorder := createPolicyResolver()

	polKey := model.PolicyKey{
		Name: "test-policy",
	}

	pol := model.Policy{}

	endpointKey := model.WorkloadEndpointKey{
		Hostname: "test-workload-ep",
	}
	pr.endpoints[endpointKey] = "the endpoint"

	pr.allPolicies[polKey] = &pol

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
		Endpoint: "the endpoint",
		Tiers: []TierInfo{{
			Name: "default",
			OrderedPolicies: []PolKV{
				{
					Key:   polKey,
					Value: &pol,
				},
			},
		}},
	}, cmp.AllowUnexported(PolKV{})); d != "" {
		t.Error("Incorrect update:", d)
	}
}

func TestPolicyResolver_OnPolicyMatchStopped(t *testing.T) {
	pr, recorder := createPolicyResolver()
	pr.OnDatamodelStatus(api.InSync)

	polKey := model.PolicyKey{
		Name: "test-policy",
	}

	pol := model.Policy{}

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
