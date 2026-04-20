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

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// testComputedSelectorListener records calls to the ComputedSelectorListener interface.
type testComputedSelectorListener struct {
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

func (t *testComputedSelectorListener) OnComputedSelectorMatch(cs string, endpointKey model.EndpointKey) {
	t.computedSelectorMatches = append(t.computedSelectorMatches, computedSelectorMatchEvent{cs, endpointKey})
}

func (t *testComputedSelectorListener) OnComputedSelectorMatchStopped(cs string, endpointKey model.EndpointKey) {
	t.computedSelectorMatchStops = append(t.computedSelectorMatchStops, computedSelectorMatchEvent{cs, endpointKey})
}

// noopRuleScanner satisfies the ruleScanner interface required by ActiveRulesCalculator.
type noopRuleScanner struct{}

func (n *noopRuleScanner) OnPolicyActive(model.PolicyKey, *model.Policy)              {}
func (n *noopRuleScanner) OnPolicyInactive(model.PolicyKey)                           {}
func (n *noopRuleScanner) OnProfileActive(model.ProfileRulesKey, *model.ProfileRules) {}
func (n *noopRuleScanner) OnProfileInactive(model.ProfileRulesKey)                    {}

func createARC() (*ActiveRulesCalculator, *testComputedSelectorListener) {
	arc := NewActiveRulesCalculator()
	arc.RuleScanner = &noopRuleScanner{}
	listener := &testComputedSelectorListener{}
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

	arc.AddExtraComputedSelector("has(foo)", listener)

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

	arc.AddExtraComputedSelector("has(foo)", listener)

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

	arc.AddExtraComputedSelector("has(foo)", listener)

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

	arc.AddExtraComputedSelector("has(foo)", listener)

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
	arc.RemoveExtraComputedSelector("has(foo)", listener)

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

// --- Multi-listener AddExtraComputedSelector tests ---

func TestARC_MultiListener_BothGetCallbacks(t *testing.T) {
	arc, _ := createARC()
	listenerA := &testComputedSelectorListener{}
	listenerB := &testComputedSelectorListener{}

	// Two different components register the same selector.
	arc.AddExtraComputedSelector("has(foo)", listenerA)
	arc.AddExtraComputedSelector("has(foo)", listenerB)

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	// Both listeners get a callback.
	for name, l := range map[string]*testComputedSelectorListener{"A": listenerA, "B": listenerB} {
		if len(l.computedSelectorMatches) != 1 {
			t.Fatalf("listener %s: expected 1 match callbacks, got %d", name, len(l.computedSelectorMatches))
		}
		if l.computedSelectorMatches[0].Selector != "has(foo)" {
			t.Errorf("listener %s: expected selector %q, got %q", name, "has(foo)", l.computedSelectorMatches[0].Selector)
		}
	}
}

func TestARC_MultiListener_RemoveOneStillActive(t *testing.T) {
	RegisterTestingT(t)
	arc, _ := createARC()
	listenerA := &testComputedSelectorListener{}
	listenerB := &testComputedSelectorListener{}

	arc.AddExtraComputedSelector("has(foo)", listenerA)
	arc.AddExtraComputedSelector("has(foo)", listenerB)

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})
	listenerA.computedSelectorMatches = nil
	listenerB.computedSelectorMatches = nil

	// Remove listener A — B still holds a reference.
	arc.RemoveExtraComputedSelector("has(foo)", listenerA)

	// Expect match-stopped to listener A only
	Expect(listenerA.computedSelectorMatchStops).To(HaveLen(1))
	Expect(listenerB.computedSelectorMatchStops).To(HaveLen(0))

	// A new matching endpoint should still trigger a match on listenerB.
	epKey2 := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl2",
		EndpointID:     "ep2",
	}
	addEndpoint(arc, epKey2, map[string]string{"foo": "baz"})
	Expect(listenerB.computedSelectorMatches).To(HaveLen(1))
	Expect(listenerA.computedSelectorMatches).To(HaveLen(0))

	// Removing a matching endpoint should trigger a match-stopped on listenerB.
	listenerA.computedSelectorMatchStops = nil
	listenerB.computedSelectorMatchStops = nil
	deleteEndpoint(arc, epKey2)
	Expect(listenerA.computedSelectorMatchStops).To(HaveLen(0))
	Expect(listenerB.computedSelectorMatchStops).To(HaveLen(1))
}

func TestARC_MultiListener_RemoveBothDeactivates(t *testing.T) {
	arc, _ := createARC()
	listenerA := &testComputedSelectorListener{}
	listenerB := &testComputedSelectorListener{}

	arc.AddExtraComputedSelector("has(foo)", listenerA)
	arc.AddExtraComputedSelector("has(foo)", listenerB)

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	// Remove both listeners.
	arc.RemoveExtraComputedSelector("has(foo)", listenerA)
	arc.RemoveExtraComputedSelector("has(foo)", listenerB)

	// Both listeners should have match-stopped.
	for name, l := range map[string]*testComputedSelectorListener{"A": listenerA, "B": listenerB} {
		if len(l.computedSelectorMatchStops) != 1 {
			t.Fatalf("listener %s: expected 1 match stop after removing both listeners, got %d", name, len(l.computedSelectorMatchStops))
		}
	}

	// Reset and verify no further callbacks.
	listenerA.computedSelectorMatches = nil
	listenerA.computedSelectorMatchStops = nil
	listenerB.computedSelectorMatches = nil
	listenerB.computedSelectorMatchStops = nil

	epKey2 := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl2",
		EndpointID:     "ep2",
	}
	addEndpoint(arc, epKey2, map[string]string{"foo": "baz"})

	for name, l := range map[string]*testComputedSelectorListener{"A": listenerA, "B": listenerB} {
		if len(l.computedSelectorMatches) != 0 {
			t.Errorf("listener %s: expected no matches after both listeners removed, got %d", name, len(l.computedSelectorMatches))
		}
	}
}

func TestARC_MultiListener_DuplicateAddFromSameListener(t *testing.T) {
	arc, _ := createARC()
	listener := &testComputedSelectorListener{}

	// Same listener adds the same selector twice.
	arc.AddExtraComputedSelector("has(foo)", listener)
	arc.AddExtraComputedSelector("has(foo)", listener)

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	if len(listener.computedSelectorMatches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(listener.computedSelectorMatches))
	}

	// A single Remove should be enough since the set deduplicates the listener.
	arc.RemoveExtraComputedSelector("has(foo)", listener)

	if len(listener.computedSelectorMatchStops) != 1 {
		t.Fatalf("expected 1 match stop after single remove, got %d", len(listener.computedSelectorMatchStops))
	}
}

func TestARC_MultiListener_RemoveWithoutAdd(t *testing.T) {
	arc, _ := createARC()
	listener := &testComputedSelectorListener{}

	// Removing a selector that was never added should be a no-op.
	arc.RemoveExtraComputedSelector("has(foo)", listener)

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	if len(listener.computedSelectorMatches) != 0 {
		t.Errorf("expected no matches, got %d", len(listener.computedSelectorMatches))
	}
	if len(listener.computedSelectorMatchStops) != 0 {
		t.Errorf("expected no match stops, got %d", len(listener.computedSelectorMatchStops))
	}
}

func TestARC_ComputedSelector_DoesNotCreatePolicyEntries(t *testing.T) {
	arc, listener := createARC()

	arc.AddExtraComputedSelector("has(foo)", listener)

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	// policyIDToEndpointKeys should be empty — computed selectors don't create policy entries.
	if arc.policyIDToEndpointKeys.Len() != 0 {
		t.Errorf("expected policyIDToEndpointKeys to be empty, got len=%d", arc.policyIDToEndpointKeys.Len())
	}
}
