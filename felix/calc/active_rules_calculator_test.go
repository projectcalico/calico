// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// testPolicyMatchListener records calls to the PolicyMatchListener interface.
type testPolicyMatchListener struct {
	policyMatches              []policyMatchEvent
	policyMatchStops           []policyMatchEvent
	computedSelectorMatches    []computedSelectorMatchEvent
	computedSelectorMatchStops []computedSelectorMatchEvent
}

type policyMatchEvent struct {
	PolicyKey   model.PolicyKey
	EndpointKey model.EndpointKey
}

type computedSelectorMatchEvent struct {
	Selector    string
	EndpointKey model.EndpointKey
}

func (t *testPolicyMatchListener) OnPolicyMatch(policyKey model.PolicyKey, endpointKey model.EndpointKey) {
	t.policyMatches = append(t.policyMatches, policyMatchEvent{policyKey, endpointKey})
}

func (t *testPolicyMatchListener) OnPolicyMatchStopped(policyKey model.PolicyKey, endpointKey model.EndpointKey) {
	t.policyMatchStops = append(t.policyMatchStops, policyMatchEvent{policyKey, endpointKey})
}

func (t *testPolicyMatchListener) OnComputedSelectorMatch(cs string, endpointKey model.EndpointKey) {
	t.computedSelectorMatches = append(t.computedSelectorMatches, computedSelectorMatchEvent{cs, endpointKey})
}

func (t *testPolicyMatchListener) OnComputedSelectorMatchStopped(cs string, endpointKey model.EndpointKey) {
	t.computedSelectorMatchStops = append(t.computedSelectorMatchStops, computedSelectorMatchEvent{cs, endpointKey})
}

// noopRuleScanner satisfies the ruleScanner interface required by ActiveRulesCalculator.
type noopRuleScanner struct{}

func (n *noopRuleScanner) OnPolicyActive(model.PolicyKey, *model.Policy)              {}
func (n *noopRuleScanner) OnPolicyInactive(model.PolicyKey)                           {}
func (n *noopRuleScanner) OnProfileActive(model.ProfileRulesKey, *model.ProfileRules) {}
func (n *noopRuleScanner) OnProfileInactive(model.ProfileRulesKey)                    {}

func createARC() (*ActiveRulesCalculator, *testPolicyMatchListener) {
	arc := NewActiveRulesCalculator()
	arc.RuleScanner = &noopRuleScanner{}
	listener := &testPolicyMatchListener{}
	arc.RegisterPolicyMatchListener(listener)
	return arc, listener
}

func addEndpoint(arc *ActiveRulesCalculator, key model.WorkloadEndpointKey, labels map[string]string) {
	arc.OnUpdate(api.Update{
		KVPair: model.KVPair{
			Key: key,
			Value: &model.WorkloadEndpoint{
				Labels: uniquelabels.Make(labels),
			},
		},
	})
}

func deleteEndpoint(arc *ActiveRulesCalculator, key model.WorkloadEndpointKey) {
	arc.OnUpdate(api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: nil,
		},
	})
}

func TestARC_ComputedSelector_MatchOnEndpointAdd(t *testing.T) {
	arc, listener := createARC()

	arc.AddExtraComputedSelector("has(foo)")

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	if len(listener.computedSelectorMatches) != 1 {
		t.Fatalf("expected 1 computed selector match, got %d", len(listener.computedSelectorMatches))
	}
	ev := listener.computedSelectorMatches[0]
	if ev.Selector != "has(foo)" {
		t.Errorf("expected selector %q, got %q", "has(foo)", ev.Selector)
	}
	if ev.EndpointKey != epKey {
		t.Errorf("expected endpoint key %v, got %v", epKey, ev.EndpointKey)
	}
}

func TestARC_ComputedSelector_MatchStoppedOnEndpointRemove(t *testing.T) {
	arc, listener := createARC()

	arc.AddExtraComputedSelector("has(foo)")

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	deleteEndpoint(arc, epKey)

	if len(listener.computedSelectorMatchStops) != 1 {
		t.Fatalf("expected 1 computed selector match stop, got %d", len(listener.computedSelectorMatchStops))
	}
	ev := listener.computedSelectorMatchStops[0]
	if ev.Selector != "has(foo)" {
		t.Errorf("expected selector %q, got %q", "has(foo)", ev.Selector)
	}
	if ev.EndpointKey != epKey {
		t.Errorf("expected endpoint key %v, got %v", epKey, ev.EndpointKey)
	}
}

func TestARC_ComputedSelector_NoMatchForNonMatchingEndpoint(t *testing.T) {
	arc, listener := createARC()

	arc.AddExtraComputedSelector("has(foo)")

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	// Endpoint does NOT have the "foo" label.
	addEndpoint(arc, epKey, map[string]string{"bar": "baz"})

	if len(listener.computedSelectorMatches) != 0 {
		t.Errorf("expected no computed selector matches, got %d", len(listener.computedSelectorMatches))
	}
	if len(listener.computedSelectorMatchStops) != 0 {
		t.Errorf("expected no computed selector match stops, got %d", len(listener.computedSelectorMatchStops))
	}
}

func TestARC_RemoveComputedSelector(t *testing.T) {
	arc, listener := createARC()

	arc.AddExtraComputedSelector("has(foo)")

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	if len(listener.computedSelectorMatches) != 1 {
		t.Fatalf("expected 1 match after adding endpoint, got %d", len(listener.computedSelectorMatches))
	}

	// Remove the computed selector — should fire match-stopped.
	arc.RemoveExtraComputedSelector("has(foo)")

	if len(listener.computedSelectorMatchStops) != 1 {
		t.Fatalf("expected 1 match stop after removing selector, got %d", len(listener.computedSelectorMatchStops))
	}

	// Reset events.
	listener.computedSelectorMatches = nil
	listener.computedSelectorMatchStops = nil

	// Add another matching endpoint — no further events since selector is removed.
	epKey2 := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl2",
		EndpointID:     "ep2",
	}
	addEndpoint(arc, epKey2, map[string]string{"foo": "baz"})

	if len(listener.computedSelectorMatches) != 0 {
		t.Errorf("expected no matches after selector removed, got %d", len(listener.computedSelectorMatches))
	}
	if len(listener.computedSelectorMatchStops) != 0 {
		t.Errorf("expected no match stops after selector removed, got %d", len(listener.computedSelectorMatchStops))
	}
}

func TestARC_ComputedSelector_DoesNotTriggerPolicyCallbacks(t *testing.T) {
	arc, listener := createARC()

	arc.AddExtraComputedSelector("has(foo)")

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	// Computed selector match should NOT produce policy callbacks.
	if len(listener.policyMatches) != 0 {
		t.Errorf("expected no policy matches, got %d", len(listener.policyMatches))
	}
	if len(listener.policyMatchStops) != 0 {
		t.Errorf("expected no policy match stops, got %d", len(listener.policyMatchStops))
	}

	// policyIDToEndpointKeys should be empty — computed selectors don't create policy entries.
	if arc.policyIDToEndpointKeys.Len() != 0 {
		t.Errorf("expected policyIDToEndpointKeys to be empty, got len=%d", arc.policyIDToEndpointKeys.Len())
	}
}
