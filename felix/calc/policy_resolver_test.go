package calc_test

import (
	"testing"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

func TestPolicyResolver_OnUpdate(t *testing.T) {
	pr := calc.NewPolicyResolver()

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

	if _, found := pr.AllPolicies[polKey]; !found {
		t.Error("Adding new inactive policy - expected policy to be in AllPolicies but it is not")
	}

	update.Value = nil

	pr.OnUpdate(update)

	if _, found := pr.AllPolicies[polKey]; found {
		t.Error("Deleting inactive policy - expected AllPolicies not to contain policy but it does")
	}
}

func TestPolicyResolver_OnPolicyMatch(t *testing.T) {
	pr := calc.NewPolicyResolver()

	polKey := model.PolicyKey{
		Name: "test-policy",
	}

	pol := model.Policy{}

	endpointKey := model.WorkloadEndpointKey{
		Hostname: "test-workload-ep",
	}

	pr.AllPolicies[polKey] = &pol
	pr.OnPolicyMatch(polKey, endpointKey)

	if !pr.PolicyIDToEndpointIDs.ContainsKey(polKey) {
		t.Error("Adding new policy - expected PolicyIDToEndpointIDs to contain new policy but it does not")
	}
	if !pr.EndpointIDToPolicyIDs.ContainsKey(endpointKey) {
		t.Error("Adding new policy - expected EndpointIDToPolicyIDs to contain endpoint but it does not")
	}
	if !pr.DirtyEndpoints.Contains(endpointKey) {
		t.Error("Adding new policy - expected DirtyEndpoints to contain endpoint for policy but it does not")
	}

	pr.OnPolicyMatch(polKey, endpointKey)
}

func TestPolicyResolver_OnPolicyMatchStopped(t *testing.T) {
	pr := calc.NewPolicyResolver()

	polKey := model.PolicyKey{
		Name: "test-policy",
	}

	pol := model.Policy{}

	endpointKey := model.WorkloadEndpointKey{
		Hostname: "test-workload-ep",
	}

	pr.PolicyIDToEndpointIDs.Put(polKey, endpointKey)
	pr.EndpointIDToPolicyIDs.Put(endpointKey, polKey)
	pr.PolicySorter.UpdatePolicy(polKey, &pol)
	pr.OnPolicyMatchStopped(polKey, endpointKey)

	if pr.PolicyIDToEndpointIDs.ContainsKey(polKey) {
		t.Error("Deleting existing policy - expected PolicyIDToEndpointIDs not to contain policy but it does")
	}
	if pr.EndpointIDToPolicyIDs.ContainsKey(endpointKey) {
		t.Error("Deleting existing policy - expected EndpointIDToPolicyIDs not to contain endpoint but it does")
	}
	if !pr.DirtyEndpoints.Contains(endpointKey) {
		t.Error("Deleting existing policy - expected DirtyEndpoints to contain endpoint but it does not")
	}

	pr.OnPolicyMatchStopped(polKey, endpointKey)
}
