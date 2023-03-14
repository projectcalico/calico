package calc

import (
	"testing"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

func TestPolicyResolver_OnUpdate(t *testing.T) {
	pr := NewPolicyResolver()

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
}

func TestPolicyResolver_OnPolicyMatch(t *testing.T) {
	pr := NewPolicyResolver()

	polKey := model.PolicyKey{
		Name: "test-policy",
	}

	pol := model.Policy{}

	endpointKey := model.WorkloadEndpointKey{
		Hostname: "test-workload-ep",
	}

	pr.allPolicies[polKey] = &pol
	pr.OnPolicyMatch(polKey, endpointKey)

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
}

func TestPolicyResolver_OnPolicyMatchStopped(t *testing.T) {
	pr := NewPolicyResolver()

	polKey := model.PolicyKey{
		Name: "test-policy",
	}

	pol := model.Policy{}

	endpointKey := model.WorkloadEndpointKey{
		Hostname: "test-workload-ep",
	}

	pr.policyIDToEndpointIDs.Put(polKey, endpointKey)
	pr.endpointIDToPolicyIDs.Put(endpointKey, polKey)
	pr.policySorter.UpdatePolicy(polKey, &pol)
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
}
