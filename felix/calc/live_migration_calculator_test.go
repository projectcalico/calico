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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// roleEvent records a single call to the EndpointComputedDataUpdater callback.
type roleEvent struct {
	key  model.WorkloadEndpointKey
	role proto.LiveMigrationRole
	uid  string
}

// testLMCEnv bundles the LMC under test together with its recording shims.
type testLMCEnv struct {
	arc        *ActiveRulesCalculator
	lmc        *LiveMigrationCalculator
	roleEvents []roleEvent
}

func newTestLMCEnv() *testLMCEnv {
	env := &testLMCEnv{}
	arc := NewActiveRulesCalculator()
	arc.RuleScanner = &noopRuleScanner{}
	env.arc = arc

	env.lmc = NewLiveMigrationCalculator(
		arc,
		func(key model.WorkloadEndpointKey, kind EndpointComputedDataKind, data EndpointComputedData) {
			lmr := data.(*liveMigrationRole)
			env.roleEvents = append(env.roleEvents, roleEvent{key: key, role: lmr.role, uid: lmr.uid})
		},
	)
	return env
}

// lastRole returns the most recent role emitted for a given WEP key, or NO_ROLE if none.
func (env *testLMCEnv) lastRole(key model.WorkloadEndpointKey) proto.LiveMigrationRole {
	for i := len(env.roleEvents) - 1; i >= 0; i-- {
		if env.roleEvents[i].key == key {
			return env.roleEvents[i].role
		}
	}
	return proto.LiveMigrationRole_NO_ROLE
}

// lastUID returns the most recent UID emitted for a given WEP key, or "" if none.
func (env *testLMCEnv) lastUID(key model.WorkloadEndpointKey) string {
	for i := len(env.roleEvents) - 1; i >= 0; i-- {
		if env.roleEvents[i].key == key {
			return env.roleEvents[i].uid
		}
	}
	return ""
}

// addLabeledEndpoint registers a labeled WEP with both the LMC and ARC so that
// selector-based matching works end-to-end.
func (env *testLMCEnv) addLabeledEndpoint(key model.WorkloadEndpointKey, labels map[string]string) {
	// Tell the LMC about the WEP.
	env.lmc.OnUpdate(makeWEPUpdate(key))
	// Tell the ARC about the WEP with labels so selectors can match.
	env.arc.OnUpdate(api.Update{
		KVPair: model.KVPair{
			Key: key,
			Value: &model.WorkloadEndpoint{
				Labels: uniquelabels.Make(labels),
			},
		},
	})
}

// removeLabeledEndpoint removes a WEP from both the LMC and ARC.
func (env *testLMCEnv) removeLabeledEndpoint(key model.WorkloadEndpointKey) {
	env.lmc.OnUpdate(makeWEPDelete(key))
	env.arc.OnUpdate(api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: nil,
		},
	})
}

// --- Helpers for constructing keys and updates ---

func makeWEPKey(namespace, name string) model.WorkloadEndpointKey {
	return model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "k8s",
		WorkloadID:     namespace + "/" + name,
		EndpointID:     "eth0",
	}
}

func makeWEPKeyWithEndpoint(namespace, name, endpointID string) model.WorkloadEndpointKey {
	return model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "k8s",
		WorkloadID:     namespace + "/" + name,
		EndpointID:     endpointID,
	}
}

func makeWEPUpdate(key model.WorkloadEndpointKey) api.Update {
	return api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: &model.WorkloadEndpoint{},
		},
	}
}

func makeWEPDelete(key model.WorkloadEndpointKey) api.Update {
	return api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: nil,
		},
	}
}

func makeLMKey(name string) model.ResourceKey {
	return model.ResourceKey{
		Kind:      internalapi.KindLiveMigration,
		Name:      name,
		Namespace: "default",
	}
}

// ptrWEI creates a WorkloadEndpointIdentifier pointer (endpoint-level matching).
func ptrWEI(hostname, orchestratorID, workloadID, endpointID string) *internalapi.WorkloadEndpointIdentifier {
	return &internalapi.WorkloadEndpointIdentifier{
		Hostname:       hostname,
		OrchestratorID: orchestratorID,
		WorkloadID:     workloadID,
		EndpointID:     endpointID,
	}
}

// ptrWI creates a WorkloadIdentifier pointer (workload-level matching).
func ptrWI(hostname, orchestratorID, workloadID string) *internalapi.WorkloadIdentifier {
	return &internalapi.WorkloadIdentifier{
		Hostname:       hostname,
		OrchestratorID: orchestratorID,
		WorkloadID:     workloadID,
	}
}

func ptrStr(s string) *string {
	return &s
}

// makeSourceWEI creates a LiveMigrationSource using WorkloadEndpoint (endpoint-level).
func makeSourceWEI(hostname, orchestratorID, workloadID, endpointID string) *internalapi.LiveMigrationSource {
	return &internalapi.LiveMigrationSource{
		WorkloadEndpoint: ptrWEI(hostname, orchestratorID, workloadID, endpointID),
	}
}

// makeSourceWI creates a LiveMigrationSource using Workload (workload-level).
func makeSourceWI(hostname, orchestratorID, workloadID string) *internalapi.LiveMigrationSource {
	return &internalapi.LiveMigrationSource{
		Workload: ptrWI(hostname, orchestratorID, workloadID),
	}
}

// makeTargetWEI creates a LiveMigrationTarget using WorkloadEndpoint (endpoint-level).
func makeTargetWEI(hostname, orchestratorID, workloadID, endpointID string) *internalapi.LiveMigrationTarget {
	return &internalapi.LiveMigrationTarget{
		WorkloadEndpoint: ptrWEI(hostname, orchestratorID, workloadID, endpointID),
	}
}

// makeTargetSelector creates a LiveMigrationTarget using a selector.
func makeTargetSelector(selector string) *internalapi.LiveMigrationTarget {
	return &internalapi.LiveMigrationTarget{
		Selector: ptrStr(selector),
	}
}

func makeLM(source *internalapi.LiveMigrationSource, target *internalapi.LiveMigrationTarget) *internalapi.LiveMigration {
	return &internalapi.LiveMigration{
		Spec: internalapi.LiveMigrationSpec{
			Source: source,
			Target: target,
		},
	}
}

func makeLMWithUID(source *internalapi.LiveMigrationSource, target *internalapi.LiveMigrationTarget, uid types.UID) *internalapi.LiveMigration {
	lm := makeLM(source, target)
	lm.ObjectMeta = metav1.ObjectMeta{UID: uid}
	return lm
}

func makeLMUpdate(key model.ResourceKey, lm *internalapi.LiveMigration) api.Update {
	return api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: lm,
		},
	}
}

func makeLMDelete(key model.ResourceKey) api.Update {
	return api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: nil,
		},
	}
}

// --- Tests using endpoint-level (WorkloadEndpointIdentifier) matching ---

func TestLiveMigrationCalculator_LMThenWEPs(t *testing.T) {
	env := newTestLMCEnv()

	lmKey := makeLMKey("lm1")
	lm := makeLM(
		makeSourceWEI("host1", "k8s", "ns/src-pod", "eth0"),
		makeTargetWEI("host1", "k8s", "ns/dst-pod", "eth0"),
	)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	// No WEPs yet, no role events.
	if len(env.roleEvents) != 0 {
		t.Fatalf("expected no role events before WEPs arrive, got %d", len(env.roleEvents))
	}

	// Source WEP arrives.
	srcKey := makeWEPKey("ns", "src-pod")
	env.lmc.OnUpdate(makeWEPUpdate(srcKey))
	if env.lastRole(srcKey) != proto.LiveMigrationRole_SOURCE {
		t.Errorf("expected SOURCE for src-pod, got %v", env.lastRole(srcKey))
	}

	// Target WEP arrives.
	dstKey := makeWEPKey("ns", "dst-pod")
	env.lmc.OnUpdate(makeWEPUpdate(dstKey))
	if env.lastRole(dstKey) != proto.LiveMigrationRole_TARGET {
		t.Errorf("expected TARGET for dst-pod, got %v", env.lastRole(dstKey))
	}
}

func TestLiveMigrationCalculator_WEPsThenLM(t *testing.T) {
	env := newTestLMCEnv()

	srcKey := makeWEPKey("ns", "src-pod")
	dstKey := makeWEPKey("ns", "dst-pod")
	env.lmc.OnUpdate(makeWEPUpdate(srcKey))
	env.lmc.OnUpdate(makeWEPUpdate(dstKey))

	// WEPs arrive with NO_ROLE initially.
	if got := env.lastRole(srcKey); got != proto.LiveMigrationRole_NO_ROLE {
		t.Errorf("expected NO_ROLE for src-pod before LM, got %v", got)
	}

	// LM arrives naming both WEPs.
	lmKey := makeLMKey("lm1")
	lm := makeLM(
		makeSourceWEI("host1", "k8s", "ns/src-pod", "eth0"),
		makeTargetWEI("host1", "k8s", "ns/dst-pod", "eth0"),
	)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	if env.lastRole(srcKey) != proto.LiveMigrationRole_SOURCE {
		t.Errorf("expected SOURCE for src-pod, got %v", env.lastRole(srcKey))
	}
	if env.lastRole(dstKey) != proto.LiveMigrationRole_TARGET {
		t.Errorf("expected TARGET for dst-pod, got %v", env.lastRole(dstKey))
	}

	// Delete the LM.
	env.lmc.OnUpdate(makeLMDelete(lmKey))

	if env.lastRole(srcKey) != proto.LiveMigrationRole_NO_ROLE {
		t.Errorf("expected NO_ROLE for src-pod after LM deleted, got %v", env.lastRole(srcKey))
	}
	if env.lastRole(dstKey) != proto.LiveMigrationRole_NO_ROLE {
		t.Errorf("expected NO_ROLE for dst-pod after LM deleted, got %v", env.lastRole(dstKey))
	}
}

// Note, this scenario isn't expected as part of mainline live migration.  But it might happen
// transiently if a newly migrated VM is quickly re-live-migrated to a new host and the control
// plane is slow to clean up resources for the first migration.
func TestLiveMigrationCalculator_TargetWinsOverSource(t *testing.T) {
	env := newTestLMCEnv()

	wepKey := makeWEPKey("ns", "pod-a")
	env.lmc.OnUpdate(makeWEPUpdate(wepKey))

	// LM1 names pod-a as source.
	lm1Key := makeLMKey("lm1")
	lm1 := makeLM(makeSourceWEI("host1", "k8s", "ns/pod-a", "eth0"), nil)
	env.lmc.OnUpdate(makeLMUpdate(lm1Key, lm1))

	if env.lastRole(wepKey) != proto.LiveMigrationRole_SOURCE {
		t.Errorf("expected SOURCE, got %v", env.lastRole(wepKey))
	}

	// LM2 names pod-a as target.
	lm2Key := makeLMKey("lm2")
	lm2 := makeLM(nil, makeTargetWEI("host1", "k8s", "ns/pod-a", "eth0"))
	env.lmc.OnUpdate(makeLMUpdate(lm2Key, lm2))

	if env.lastRole(wepKey) != proto.LiveMigrationRole_TARGET {
		t.Errorf("expected TARGET (target wins), got %v", env.lastRole(wepKey))
	}
}

// Note, this scenario isn't expected as part of mainline live migration.  Once a LiveMigration
// specifies a source, that should never change within the same LiveMigration resource.  But it's
// useful to test how the product code would respond if it did.
func TestLiveMigrationCalculator_LMUpdateChangesSourceName(t *testing.T) {
	env := newTestLMCEnv()

	wepAKey := makeWEPKey("ns", "pod-a")
	wepBKey := makeWEPKey("ns", "pod-b")
	env.lmc.OnUpdate(makeWEPUpdate(wepAKey))
	env.lmc.OnUpdate(makeWEPUpdate(wepBKey))

	lmKey := makeLMKey("lm1")
	lm := makeLM(makeSourceWEI("host1", "k8s", "ns/pod-a", "eth0"), nil)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	if env.lastRole(wepAKey) != proto.LiveMigrationRole_SOURCE {
		t.Fatalf("expected pod-a SOURCE, got %v", env.lastRole(wepAKey))
	}

	// Update LM to change source from pod-a to pod-b.
	lmUpdated := makeLM(makeSourceWEI("host1", "k8s", "ns/pod-b", "eth0"), nil)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lmUpdated))

	if env.lastRole(wepAKey) != proto.LiveMigrationRole_NO_ROLE {
		t.Errorf("expected pod-a NO_ROLE after source changed, got %v", env.lastRole(wepAKey))
	}
	if env.lastRole(wepBKey) != proto.LiveMigrationRole_SOURCE {
		t.Errorf("expected pod-b SOURCE after source changed, got %v", env.lastRole(wepBKey))
	}
}

func TestLiveMigrationCalculator_SelectorBasedTarget(t *testing.T) {
	env := newTestLMCEnv()

	// Create LM with target selector first.
	lmKey := makeLMKey("lm1")
	lm := makeLM(nil, makeTargetSelector("has(migrate)"))
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	// Add a labeled WEP through both LMC and ARC — the ARC will fire the selector
	// match callback to the LMC.
	wepKey := makeWEPKey("ns", "dst-pod")
	env.addLabeledEndpoint(wepKey, map[string]string{"migrate": "true"})

	if env.lastRole(wepKey) != proto.LiveMigrationRole_TARGET {
		t.Errorf("expected TARGET after selector match, got %v", env.lastRole(wepKey))
	}

	// Remove the endpoint — ARC fires match-stopped.
	env.removeLabeledEndpoint(wepKey)

	// WEP is deleted, so no explicit NO_ROLE event needed; just check no panic.
}

func TestLiveMigrationCalculator_SelectorMatchThenLMDeleted(t *testing.T) {
	env := newTestLMCEnv()

	wepKey := makeWEPKey("ns", "dst-pod")
	env.addLabeledEndpoint(wepKey, map[string]string{"migrate": "true"})

	lmKey := makeLMKey("lm1")
	lm := makeLM(nil, makeTargetSelector("has(migrate)"))
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	if env.lastRole(wepKey) != proto.LiveMigrationRole_TARGET {
		t.Fatalf("expected TARGET, got %v", env.lastRole(wepKey))
	}

	// Delete the LM — selector is removed, ARC fires match-stopped, WEP reverts.
	env.lmc.OnUpdate(makeLMDelete(lmKey))

	if env.lastRole(wepKey) != proto.LiveMigrationRole_NO_ROLE {
		t.Errorf("expected NO_ROLE after LM deleted, got %v", env.lastRole(wepKey))
	}
}

// Note, this scenario isn't expected as part of mainline live migration.  We would expect every
// unique LiveMigration resource to have its own unique selector.  But it's useful to test how the
// product code would respond.
func TestLiveMigrationCalculator_SelectorRefCounting(t *testing.T) {
	env := newTestLMCEnv()

	// Two LMs with the same selector.
	lm1Key := makeLMKey("lm1")
	lm1 := makeLM(nil, makeTargetSelector("has(migrate)"))
	env.lmc.OnUpdate(makeLMUpdate(lm1Key, lm1))

	lm2Key := makeLMKey("lm2")
	lm2 := makeLM(nil, makeTargetSelector("has(migrate)"))
	env.lmc.OnUpdate(makeLMUpdate(lm2Key, lm2))

	// Selector should be active (added once, ref count = 2).
	if _, ok := env.lmc.selectorKeys["has(migrate)"]; !ok {
		t.Fatal("expected selector to be tracked")
	}
	if env.lmc.selectorKeys["has(migrate)"].Len() != 2 {
		t.Fatalf("expected 2 LM refs, got %d", env.lmc.selectorKeys["has(migrate)"].Len())
	}

	// Add a matching endpoint — should get TARGET.
	wepKey := makeWEPKey("ns", "dst-pod")
	env.addLabeledEndpoint(wepKey, map[string]string{"migrate": "true"})

	if env.lastRole(wepKey) != proto.LiveMigrationRole_TARGET {
		t.Fatalf("expected TARGET, got %v", env.lastRole(wepKey))
	}
	eventCount := len(env.roleEvents)

	// Delete first LM — selector should still be active, WEP still TARGET.
	env.lmc.OnUpdate(makeLMDelete(lm1Key))
	if _, ok := env.lmc.selectorKeys["has(migrate)"]; !ok {
		t.Fatal("expected selector to still be tracked after first LM deleted")
	}
	// No role change event expected (still TARGET).
	if len(env.roleEvents) != eventCount {
		t.Errorf("expected no role change, got %v", env.roleEvents[eventCount:])
	}

	// Delete second LM — selector removed, WEP reverts to NO_ROLE.
	env.lmc.OnUpdate(makeLMDelete(lm2Key))
	if _, ok := env.lmc.selectorKeys["has(migrate)"]; ok {
		t.Fatal("expected selector to be removed after both LMs deleted")
	}
	if env.lastRole(wepKey) != proto.LiveMigrationRole_NO_ROLE {
		t.Errorf("expected NO_ROLE after all LMs deleted, got %v", env.lastRole(wepKey))
	}
}

// Note, this scenario isn't expected as part of mainline live migration.  Once a LiveMigration
// specifies a target, that should never change for the same LiveMigration resource.  But it's
// useful to test how the product code would respond.
func TestLiveMigrationCalculator_SelectorChangeOnUpdate(t *testing.T) {
	env := newTestLMCEnv()

	lmKey := makeLMKey("lm1")
	lm := makeLM(nil, makeTargetSelector("has(selectorA)"))
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	if _, ok := env.lmc.selectorKeys["has(selectorA)"]; !ok {
		t.Fatal("expected selectorA to be tracked")
	}

	// Add a WEP matching selectorA.
	wepKey := makeWEPKey("ns", "pod-a")
	env.addLabeledEndpoint(wepKey, map[string]string{"selectorA": "yes", "selectorB": "yes"})

	if env.lastRole(wepKey) != proto.LiveMigrationRole_TARGET {
		t.Fatalf("expected TARGET via selectorA, got %v", env.lastRole(wepKey))
	}

	// Update LM to change selector from A to B.
	lmUpdated := makeLM(nil, makeTargetSelector("has(selectorB)"))
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lmUpdated))

	if _, ok := env.lmc.selectorKeys["has(selectorA)"]; ok {
		t.Error("expected selectorA to be untracked after update")
	}
	if _, ok := env.lmc.selectorKeys["has(selectorB)"]; !ok {
		t.Error("expected selectorB to be tracked after update")
	}

	// WEP matches both selectors, so it should still be TARGET via selectorB.
	if env.lastRole(wepKey) != proto.LiveMigrationRole_TARGET {
		t.Errorf("expected TARGET via selectorB, got %v", env.lastRole(wepKey))
	}
}

func TestLiveMigrationCalculator_WEPDeleteRemovesTracking(t *testing.T) {
	env := newTestLMCEnv()

	wepKey := makeWEPKey("ns", "pod-a")
	env.lmc.OnUpdate(makeWEPUpdate(wepKey))

	lmKey := makeLMKey("lm1")
	lm := makeLM(makeSourceWEI("host1", "k8s", "ns/pod-a", "eth0"), nil)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	// Delete the WEP.
	env.lmc.OnUpdate(makeWEPDelete(wepKey))

	// Hostname is normalized to "" for k8s orchestrator.
	ownerID := wepOwnerID{orchestratorID: "k8s", workloadID: "ns/pod-a", endpointID: "eth0"}
	if _, ok := env.lmc.weps[ownerID]; ok {
		t.Error("expected WEP to be removed from tracking after delete")
	}
}

func TestLiveMigrationCalculator_WEPUpdateIsIdempotent(t *testing.T) {
	env := newTestLMCEnv()

	wepKey := makeWEPKey("ns", "pod-a")
	env.lmc.OnUpdate(makeWEPUpdate(wepKey))

	lmKey := makeLMKey("lm1")
	lm := makeLM(makeSourceWEI("host1", "k8s", "ns/pod-a", "eth0"), nil)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	// Send the same WEP update again — should be a no-op.
	eventCount := len(env.roleEvents)
	env.lmc.OnUpdate(makeWEPUpdate(wepKey))

	if len(env.roleEvents) != eventCount {
		t.Errorf("expected no role events on duplicate WEP update, got %d", len(env.roleEvents)-eventCount)
	}
}

func TestLiveMigrationCalculator_IgnoresNonLMResourceKey(t *testing.T) {
	env := newTestLMCEnv()

	// Send a non-LiveMigration ResourceKey update — should be ignored.
	update := api.Update{
		KVPair: model.KVPair{
			Key:   model.ResourceKey{Kind: "SomeOtherKind", Name: "foo"},
			Value: nil,
		},
	}
	env.lmc.OnUpdate(update)

	if len(env.roleEvents) != 0 {
		t.Errorf("expected no role events for non-LM resource, got %d", len(env.roleEvents))
	}
}

func TestLiveMigrationCalculator_IgnoresHostEndpointKey(t *testing.T) {
	env := newTestLMCEnv()

	update := api.Update{
		KVPair: model.KVPair{
			Key:   model.HostEndpointKey{Hostname: "host1", EndpointID: "ep1"},
			Value: &model.HostEndpoint{},
		},
	}
	env.lmc.OnUpdate(update)

	if len(env.roleEvents) != 0 {
		t.Errorf("expected no role events for host endpoint, got %d", len(env.roleEvents))
	}
}

func TestLiveMigrationCalculator_NilSourceAndTarget(t *testing.T) {
	env := newTestLMCEnv()

	wepKey := makeWEPKey("ns", "pod-a")
	env.lmc.OnUpdate(makeWEPUpdate(wepKey))

	// LM with nil source and nil target.
	lmKey := makeLMKey("lm1")
	lm := makeLM(nil, nil)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	if env.lastRole(wepKey) != proto.LiveMigrationRole_NO_ROLE {
		t.Errorf("expected NO_ROLE with nil source/target, got %v", env.lastRole(wepKey))
	}
}

func TestLiveMigrationCalculator_TargetWithNilFieldsInside(t *testing.T) {
	env := newTestLMCEnv()

	// LM with a Target struct but nil WorkloadEndpoint and nil Selector.
	lmKey := makeLMKey("lm1")
	lm := &internalapi.LiveMigration{
		Spec: internalapi.LiveMigrationSpec{
			Target: &internalapi.LiveMigrationTarget{},
		},
	}
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	// Should not crash and should have no selector tracked.
	if len(env.lmc.selectorKeys) != 0 {
		t.Errorf("expected no selectors tracked, got %d", len(env.lmc.selectorKeys))
	}
}

func TestLiveMigrationCalculator_EndToEndSourceHost(t *testing.T) {
	env := newTestLMCEnv()

	// Source host: WEP exists, LM arrives, LM deleted.
	srcKey := makeWEPKey("ns", "src-pod")
	env.lmc.OnUpdate(makeWEPUpdate(srcKey))

	lmKey := makeLMKey("lm1")
	lm := makeLM(
		makeSourceWEI("host1", "k8s", "ns/src-pod", "eth0"),
		makeTargetWEI("host1", "k8s", "ns/dst-pod", "eth0"),
	)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	if env.lastRole(srcKey) != proto.LiveMigrationRole_SOURCE {
		t.Errorf("expected SOURCE, got %v", env.lastRole(srcKey))
	}

	env.lmc.OnUpdate(makeLMDelete(lmKey))
	if env.lastRole(srcKey) != proto.LiveMigrationRole_NO_ROLE {
		t.Errorf("expected NO_ROLE after LM delete, got %v", env.lastRole(srcKey))
	}
}

// Note, this scenario isn't expected as part of mainline live migration.  It shouldn't be the case
// that there are two LiveMigrations specifying the same source at the same time.  But it's useful
// to test how the product code would respond.  Perhaps could happen in the case of a first live
// migration failing and then been retried?
func TestLiveMigrationCalculator_TransientOverlap(t *testing.T) {
	env := newTestLMCEnv()

	wepKey := makeWEPKey("ns", "pod-a")
	env.lmc.OnUpdate(makeWEPUpdate(wepKey))

	// Two LMs both name pod-a as source.
	lm1Key := makeLMKey("lm1")
	lm1 := makeLM(makeSourceWEI("host1", "k8s", "ns/pod-a", "eth0"), nil)
	env.lmc.OnUpdate(makeLMUpdate(lm1Key, lm1))

	lm2Key := makeLMKey("lm2")
	lm2 := makeLM(makeSourceWEI("host1", "k8s", "ns/pod-a", "eth0"), nil)
	env.lmc.OnUpdate(makeLMUpdate(lm2Key, lm2))

	if env.lastRole(wepKey) != proto.LiveMigrationRole_SOURCE {
		t.Errorf("expected SOURCE with two LMs, got %v", env.lastRole(wepKey))
	}

	// Delete LM1 — still SOURCE because LM2 remains.
	eventCount := len(env.roleEvents)
	env.lmc.OnUpdate(makeLMDelete(lm1Key))
	// Role should not have changed (still SOURCE), so no event should be emitted.
	if len(env.roleEvents) != eventCount {
		t.Errorf("expected no role change when one of two overlapping LMs deleted, got %v", env.roleEvents[eventCount:])
	}

	// Delete LM2 — now NO_ROLE.
	env.lmc.OnUpdate(makeLMDelete(lm2Key))
	if env.lastRole(wepKey) != proto.LiveMigrationRole_NO_ROLE {
		t.Errorf("expected NO_ROLE after both LMs deleted, got %v", env.lastRole(wepKey))
	}
}

// Note, this scenario isn't expected as part of mainline live migration.  KubeVirt always uses
// selector and OpenStack always uses the direct name, and never the twain should meet.  But it's
// useful to test how the product code would respond.
func TestLiveMigrationCalculator_SelectorWinsOverDirectTarget(t *testing.T) {
	env := newTestLMCEnv()

	// Set up a WEP with a label that a selector can match.
	wepKey := makeWEPKey("ns", "pod-a")
	env.addLabeledEndpoint(wepKey, map[string]string{"migrate": "true"})

	// LM1 names pod-a as direct target.
	lm1Key := makeLMKey("lm1")
	lm1 := makeLM(nil, makeTargetWEI("host1", "k8s", "ns/pod-a", "eth0"))
	env.lmc.OnUpdate(makeLMUpdate(lm1Key, lm1))

	if env.lastRole(wepKey) != proto.LiveMigrationRole_TARGET {
		t.Fatalf("expected TARGET via direct name, got %v", env.lastRole(wepKey))
	}

	// LM2 uses a selector that also matches pod-a — still TARGET, no redundant event.
	eventsBefore := len(env.roleEvents)
	lm2Key := makeLMKey("lm2")
	lm2 := makeLM(nil, makeTargetSelector("has(migrate)"))
	env.lmc.OnUpdate(makeLMUpdate(lm2Key, lm2))

	if len(env.roleEvents) != eventsBefore {
		t.Errorf("expected no new event when role stays TARGET, got new events")
	}
	if env.lastRole(wepKey) != proto.LiveMigrationRole_TARGET {
		t.Errorf("expected TARGET with both direct and selector, got %v", env.lastRole(wepKey))
	}

	// Remove direct target LM — still TARGET because selector matching persists.
	env.lmc.OnUpdate(makeLMDelete(lm1Key))
	if env.lastRole(wepKey) != proto.LiveMigrationRole_TARGET {
		t.Errorf("expected TARGET still from selector after direct LM removed, got %v", env.lastRole(wepKey))
	}

	// Remove selector LM — now NO_ROLE.
	env.lmc.OnUpdate(makeLMDelete(lm2Key))
	if env.lastRole(wepKey) != proto.LiveMigrationRole_NO_ROLE {
		t.Errorf("expected NO_ROLE after all LMs removed, got %v", env.lastRole(wepKey))
	}
}

func TestLiveMigrationCalculator_WEPRecreated(t *testing.T) {
	env := newTestLMCEnv()

	lmKey := makeLMKey("lm1")
	lm := makeLM(makeSourceWEI("host1", "k8s", "ns/pod-a", "eth0"), nil)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	wepKey := makeWEPKey("ns", "pod-a")
	env.lmc.OnUpdate(makeWEPUpdate(wepKey))

	if env.lastRole(wepKey) != proto.LiveMigrationRole_SOURCE {
		t.Fatalf("expected SOURCE, got %v", env.lastRole(wepKey))
	}

	// Delete and re-create WEP.
	env.lmc.OnUpdate(makeWEPDelete(wepKey))
	env.lmc.OnUpdate(makeWEPUpdate(wepKey))

	// Should pick up existing LM role again.
	if env.lastRole(wepKey) != proto.LiveMigrationRole_SOURCE {
		t.Errorf("expected SOURCE after WEP re-created, got %v", env.lastRole(wepKey))
	}
}

func TestLiveMigrationCalculator_UIDPropagation(t *testing.T) {
	env := newTestLMCEnv()

	srcKey := makeWEPKey("ns", "src-pod")
	dstKey := makeWEPKey("ns", "dst-pod")
	env.lmc.OnUpdate(makeWEPUpdate(srcKey))
	env.lmc.OnUpdate(makeWEPUpdate(dstKey))

	// LM with a UID.
	lmKey := makeLMKey("lm1")
	lm := makeLMWithUID(
		makeSourceWEI("host1", "k8s", "ns/src-pod", "eth0"),
		makeTargetWEI("host1", "k8s", "ns/dst-pod", "eth0"),
		"test-uid-12345",
	)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	if env.lastUID(srcKey) != "test-uid-12345" {
		t.Errorf("expected UID test-uid-12345 for src-pod, got %q", env.lastUID(srcKey))
	}
	if env.lastUID(dstKey) != "test-uid-12345" {
		t.Errorf("expected UID test-uid-12345 for dst-pod, got %q", env.lastUID(dstKey))
	}

	// Delete the LM — UID should be empty.
	env.lmc.OnUpdate(makeLMDelete(lmKey))
	if env.lastUID(srcKey) != "" {
		t.Errorf("expected empty UID for src-pod after LM deleted, got %q", env.lastUID(srcKey))
	}
	if env.lastUID(dstKey) != "" {
		t.Errorf("expected empty UID for dst-pod after LM deleted, got %q", env.lastUID(dstKey))
	}
}

func TestLiveMigrationCalculator_UIDWithSelector(t *testing.T) {
	env := newTestLMCEnv()

	// LM with UID and selector.
	lmKey := makeLMKey("lm1")
	lm := makeLMWithUID(nil, makeTargetSelector("has(migrate)"), "selector-uid-999")
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	// Add a matching WEP.
	wepKey := makeWEPKey("ns", "dst-pod")
	env.addLabeledEndpoint(wepKey, map[string]string{"migrate": "true"})

	if env.lastRole(wepKey) != proto.LiveMigrationRole_TARGET {
		t.Fatalf("expected TARGET, got %v", env.lastRole(wepKey))
	}
	if env.lastUID(wepKey) != "selector-uid-999" {
		t.Errorf("expected UID selector-uid-999, got %q", env.lastUID(wepKey))
	}
}

// --- Tests for workload-level (WorkloadIdentifier) matching ---

func TestLiveMigrationCalculator_WorkloadLevelSource(t *testing.T) {
	env := newTestLMCEnv()

	// Two WEPs for the same workload with different endpoint IDs.
	wepEth0 := makeWEPKeyWithEndpoint("ns", "src-pod", "eth0")
	wepEth1 := makeWEPKeyWithEndpoint("ns", "src-pod", "eth1")
	env.lmc.OnUpdate(makeWEPUpdate(wepEth0))
	env.lmc.OnUpdate(makeWEPUpdate(wepEth1))

	// LM with workload-level source (matches all endpoints for the workload).
	lmKey := makeLMKey("lm1")
	lm := makeLM(makeSourceWI("host1", "k8s", "ns/src-pod"), nil)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	// Both WEPs should get SOURCE role.
	if env.lastRole(wepEth0) != proto.LiveMigrationRole_SOURCE {
		t.Errorf("expected SOURCE for eth0, got %v", env.lastRole(wepEth0))
	}
	if env.lastRole(wepEth1) != proto.LiveMigrationRole_SOURCE {
		t.Errorf("expected SOURCE for eth1, got %v", env.lastRole(wepEth1))
	}

	// Delete the LM — both revert to NO_ROLE.
	env.lmc.OnUpdate(makeLMDelete(lmKey))
	if env.lastRole(wepEth0) != proto.LiveMigrationRole_NO_ROLE {
		t.Errorf("expected NO_ROLE for eth0 after LM delete, got %v", env.lastRole(wepEth0))
	}
	if env.lastRole(wepEth1) != proto.LiveMigrationRole_NO_ROLE {
		t.Errorf("expected NO_ROLE for eth1 after LM delete, got %v", env.lastRole(wepEth1))
	}
}

func TestLiveMigrationCalculator_WorkloadLevelSourceWEPsArriveAfterLM(t *testing.T) {
	env := newTestLMCEnv()

	// LM arrives first with workload-level source.
	lmKey := makeLMKey("lm1")
	lm := makeLM(makeSourceWI("host1", "k8s", "ns/src-pod"), nil)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	// No events yet.
	if len(env.roleEvents) != 0 {
		t.Fatalf("expected no role events before WEPs arrive, got %d", len(env.roleEvents))
	}

	// WEPs arrive after LM.
	wepEth0 := makeWEPKeyWithEndpoint("ns", "src-pod", "eth0")
	wepEth1 := makeWEPKeyWithEndpoint("ns", "src-pod", "eth1")
	env.lmc.OnUpdate(makeWEPUpdate(wepEth0))
	env.lmc.OnUpdate(makeWEPUpdate(wepEth1))

	// Both should get SOURCE.
	if env.lastRole(wepEth0) != proto.LiveMigrationRole_SOURCE {
		t.Errorf("expected SOURCE for eth0, got %v", env.lastRole(wepEth0))
	}
	if env.lastRole(wepEth1) != proto.LiveMigrationRole_SOURCE {
		t.Errorf("expected SOURCE for eth1, got %v", env.lastRole(wepEth1))
	}
}

func TestLiveMigrationCalculator_WorkloadLevelSourcePartialDelete(t *testing.T) {
	env := newTestLMCEnv()

	// Two WEPs, workload-level LM.
	wepEth0 := makeWEPKeyWithEndpoint("ns", "src-pod", "eth0")
	wepEth1 := makeWEPKeyWithEndpoint("ns", "src-pod", "eth1")
	env.lmc.OnUpdate(makeWEPUpdate(wepEth0))
	env.lmc.OnUpdate(makeWEPUpdate(wepEth1))

	lmKey := makeLMKey("lm1")
	lm := makeLM(makeSourceWI("host1", "k8s", "ns/src-pod"), nil)
	env.lmc.OnUpdate(makeLMUpdate(lmKey, lm))

	// Both should have SOURCE.
	if env.lastRole(wepEth0) != proto.LiveMigrationRole_SOURCE {
		t.Fatalf("expected SOURCE for eth0, got %v", env.lastRole(wepEth0))
	}
	if env.lastRole(wepEth1) != proto.LiveMigrationRole_SOURCE {
		t.Fatalf("expected SOURCE for eth1, got %v", env.lastRole(wepEth1))
	}

	// Delete one WEP — the other should retain SOURCE.
	env.lmc.OnUpdate(makeWEPDelete(wepEth0))

	if env.lastRole(wepEth1) != proto.LiveMigrationRole_SOURCE {
		t.Errorf("expected SOURCE for eth1 after eth0 deleted, got %v", env.lastRole(wepEth1))
	}
}
