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

package intdataplane

import (
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

// testFSM creates a liveMigrationFSM in the given state, wired to a monitor for
// pendingUpdates capture.
func testFSM(state liveMigrationState) (*liveMigrationFSM, *liveMigrationMonitor) {
	m := newLiveMigrationMonitor()
	id := types.WorkloadEndpointID{OrchestratorId: "k8s", WorkloadId: "test-pod", EndpointId: "ep"}
	fsm := &liveMigrationFSM{
		logCtx:       logrus.WithField("id", id),
		id:           id,
		monitor:      m,
		currentState: state,
	}
	return fsm, m
}

var wepID1 = types.WorkloadEndpointID{OrchestratorId: "k8s", WorkloadId: "pod-1", EndpointId: "ep-1"}
var wepID2 = types.WorkloadEndpointID{OrchestratorId: "k8s", WorkloadId: "pod-2", EndpointId: "ep-2"}

func protoWEPID(id types.WorkloadEndpointID) *proto.WorkloadEndpointID {
	return &proto.WorkloadEndpointID{
		OrchestratorId: id.OrchestratorId,
		WorkloadId:     id.WorkloadId,
		EndpointId:     id.EndpointId,
	}
}

func wepUpdate(id types.WorkloadEndpointID, role proto.LiveMigrationRole) *proto.WorkloadEndpointUpdate {
	return &proto.WorkloadEndpointUpdate{
		Id: protoWEPID(id),
		Endpoint: &proto.WorkloadEndpoint{
			LiveMigrationRole: role,
		},
	}
}

func wepRemove(id types.WorkloadEndpointID) *proto.WorkloadEndpointRemove {
	return &proto.WorkloadEndpointRemove{
		Id: protoWEPID(id),
	}
}

// --- Section 1: Exhaustive FSM transition table ---

func TestFSMTransitionTable(t *testing.T) {
	g := NewWithT(t)

	tests := []struct {
		name      string
		from      liveMigrationState
		input     liveMigrationInput
		wantState liveMigrationState
	}{
		// Base state
		{"Base+Target→Target", liveMigrationStateBase, liveMigrationInputTarget, liveMigrationStateTarget},
		{"Base+GARPDetected→Base", liveMigrationStateBase, liveMigrationInputGARPDetected, liveMigrationStateBase},
		{"Base+NoRole→Base", liveMigrationStateBase, liveMigrationInputNoRole, liveMigrationStateBase},
		{"Base+TimerPop→Base", liveMigrationStateBase, liveMigrationInputTimerPop, liveMigrationStateBase},
		{"Base+Source→Base", liveMigrationStateBase, liveMigrationInputSource, liveMigrationStateBase},
		{"Base+Deleted→Base", liveMigrationStateBase, liveMigrationInputDeleted, liveMigrationStateBase},

		// Target state
		{"Target+Target→Target", liveMigrationStateTarget, liveMigrationInputTarget, liveMigrationStateTarget},
		{"Target+GARPDetected→Live", liveMigrationStateTarget, liveMigrationInputGARPDetected, liveMigrationStateLive},
		{"Target+NoRole→TimeWait", liveMigrationStateTarget, liveMigrationInputNoRole, liveMigrationStateTimeWait},
		{"Target+TimerPop→Target", liveMigrationStateTarget, liveMigrationInputTimerPop, liveMigrationStateTarget},
		{"Target+Source→Base", liveMigrationStateTarget, liveMigrationInputSource, liveMigrationStateBase},
		{"Target+Deleted→Base", liveMigrationStateTarget, liveMigrationInputDeleted, liveMigrationStateBase},

		// Live state
		{"Live+Target→Live", liveMigrationStateLive, liveMigrationInputTarget, liveMigrationStateLive},
		{"Live+GARPDetected→Live", liveMigrationStateLive, liveMigrationInputGARPDetected, liveMigrationStateLive},
		{"Live+NoRole→TimeWait", liveMigrationStateLive, liveMigrationInputNoRole, liveMigrationStateTimeWait},
		{"Live+TimerPop→Live", liveMigrationStateLive, liveMigrationInputTimerPop, liveMigrationStateLive},
		{"Live+Source→Base", liveMigrationStateLive, liveMigrationInputSource, liveMigrationStateBase},
		{"Live+Deleted→Base", liveMigrationStateLive, liveMigrationInputDeleted, liveMigrationStateBase},

		// TimeWait state
		{"TimeWait+Target→TimeWait", liveMigrationStateTimeWait, liveMigrationInputTarget, liveMigrationStateTimeWait},
		{"TimeWait+GARPDetected→TimeWait", liveMigrationStateTimeWait, liveMigrationInputGARPDetected, liveMigrationStateTimeWait},
		{"TimeWait+NoRole→TimeWait", liveMigrationStateTimeWait, liveMigrationInputNoRole, liveMigrationStateTimeWait},
		{"TimeWait+TimerPop→Base", liveMigrationStateTimeWait, liveMigrationInputTimerPop, liveMigrationStateBase},
		{"TimeWait+Source→Base", liveMigrationStateTimeWait, liveMigrationInputSource, liveMigrationStateBase},
		{"TimeWait+Deleted→Base", liveMigrationStateTimeWait, liveMigrationInputDeleted, liveMigrationStateBase},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsm, m := testFSM(tt.from)
			fsm.handleInput(tt.input)

			g.Expect(fsm.currentState).To(Equal(tt.wantState), "FSM state")
			if tt.wantState != tt.from {
				g.Expect(m.pendingUpdates).To(HaveLen(1), "should emit one update")
				g.Expect(m.pendingUpdates[0].State).To(Equal(tt.wantState), "emitted state")
			} else {
				g.Expect(m.pendingUpdates).To(BeEmpty(), "should not emit any updates")
			}
		})
	}
}

// --- Section 2: Monitor OnUpdate → FSM routing ---

func TestMonitorOnUpdate(t *testing.T) {
	t.Run("WEP with TARGET role creates FSM and emits Target", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))

		updates := m.PendingUpdates()
		g.Expect(updates).To(HaveLen(1))
		g.Expect(updates[0].State).To(Equal(liveMigrationStateTarget))
		g.Expect(updates[0].ID).To(Equal(wepID1))
	})

	t.Run("role change TARGET→NO_ROLE drives NoRole input", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		m.PendingUpdates() // drain

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
		updates := m.PendingUpdates()
		g.Expect(updates).To(HaveLen(1))
		// Target + NoRole → TimeWait
		g.Expect(updates[0].State).To(Equal(liveMigrationStateTimeWait))
	})

	t.Run("role change TARGET→SOURCE drives Source input", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		m.PendingUpdates()

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_SOURCE))
		updates := m.PendingUpdates()
		g.Expect(updates).To(HaveLen(1))
		// Target + Source → Base
		g.Expect(updates[0].State).To(Equal(liveMigrationStateBase))
	})

	t.Run("same role repeated is no-op", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		m.PendingUpdates()

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(m.PendingUpdates()).To(BeEmpty())
	})

	t.Run("unrelated message type is ignored", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()
		m.OnUpdate(&proto.HostEndpointUpdate{})
		g.Expect(m.fsms).To(BeEmpty())
	})

	t.Run("WorkloadEndpointRemove drives Deleted input", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		m.PendingUpdates()

		m.OnUpdate(wepRemove(wepID1))
		updates := m.PendingUpdates()
		g.Expect(updates).To(HaveLen(1))
		// Target + Deleted → Base
		g.Expect(updates[0].State).To(Equal(liveMigrationStateBase))
		// Role should be cleaned up.
		g.Expect(m.roles).NotTo(HaveKey(wepID1))
	})

	t.Run("WorkloadEndpointRemove for unknown WEP is safe", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()
		// Should not panic; FSM is created at Base, gets Deleted (no-op), cleaned up.
		m.OnUpdate(wepRemove(wepID1))
		g.Expect(m.PendingUpdates()).To(BeEmpty())
		g.Expect(m.fsms).To(BeEmpty())
	})
}

// --- Section 3: FSM lifecycle management ---

func TestFSMLifecycle(t *testing.T) {
	t.Run("FSM created on first input and cleaned up on return to Base", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(m.fsms).To(HaveLen(1))

		// Drive back to Base: Target + Source → Base.
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_SOURCE))
		g.Expect(m.fsms).To(BeEmpty())
	})

	t.Run("multiple inputs to same ID reuse FSM", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		m.PendingUpdates()

		// Inject GARP directly (async input, bypasses OnUpdate).
		m.executeFSM(wepID1, liveMigrationInputGARPDetected)
		g.Expect(m.fsms).To(HaveLen(1))
		updates := m.PendingUpdates()
		g.Expect(updates).To(HaveLen(1))
		g.Expect(updates[0].State).To(Equal(liveMigrationStateLive))
	})

	t.Run("PendingUpdates drains and clears buffer", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))

		g.Expect(m.PendingUpdates()).To(HaveLen(1))
		g.Expect(m.PendingUpdates()).To(BeEmpty())
	})
}

// --- Section 4: Multi-step scenarios ---

func TestLiveMigrationScenarios(t *testing.T) {
	t.Run("missed GARP path: TARGET → NO_ROLE", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		expectUpdate(g, m, liveMigrationStateTarget)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
		expectUpdate(g, m, liveMigrationStateTimeWait)
	})

	t.Run("happy path with GARP: TARGET → GARP → NO_ROLE", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		expectUpdate(g, m, liveMigrationStateTarget)

		m.executeFSM(wepID1, liveMigrationInputGARPDetected)
		expectUpdate(g, m, liveMigrationStateLive)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
		expectUpdate(g, m, liveMigrationStateTimeWait)
	})

	t.Run("re-migration: TARGET → SOURCE", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		expectUpdate(g, m, liveMigrationStateTarget)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_SOURCE))
		expectUpdate(g, m, liveMigrationStateBase)
	})

	t.Run("delete during migration: TARGET → Remove", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		expectUpdate(g, m, liveMigrationStateTarget)

		m.OnUpdate(wepRemove(wepID1))
		expectUpdate(g, m, liveMigrationStateBase)
	})

	t.Run("two independent WEPs", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		m.OnUpdate(wepUpdate(wepID2, proto.LiveMigrationRole_TARGET))
		updates := m.PendingUpdates()
		g.Expect(updates).To(HaveLen(2))
		g.Expect(updates[0]).To(Equal(liveMigrationStateUpdate{ID: wepID1, State: liveMigrationStateTarget}))
		g.Expect(updates[1]).To(Equal(liveMigrationStateUpdate{ID: wepID2, State: liveMigrationStateTarget}))

		// Drive WEP1 to Live via GARP, WEP2 stays in Target.
		m.executeFSM(wepID1, liveMigrationInputGARPDetected)
		updates = m.PendingUpdates()
		g.Expect(updates).To(HaveLen(1))
		g.Expect(updates[0]).To(Equal(liveMigrationStateUpdate{ID: wepID1, State: liveMigrationStateLive}))
		// WEP2 FSM should still exist in Target.
		g.Expect(m.fsms).To(HaveKey(wepID2))
		g.Expect(m.fsms[wepID2].currentState).To(Equal(liveMigrationStateTarget))
	})

	t.Run("idempotent role update", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		m.PendingUpdates()

		// Same role again.
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(m.PendingUpdates()).To(BeEmpty())
	})

	t.Run("full lifecycle: TARGET → GARP → NO_ROLE → TimerPop", func(t *testing.T) {
		g := NewWithT(t)
		m := newLiveMigrationMonitor()

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		expectUpdate(g, m, liveMigrationStateTarget)

		m.executeFSM(wepID1, liveMigrationInputGARPDetected)
		expectUpdate(g, m, liveMigrationStateLive)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
		expectUpdate(g, m, liveMigrationStateTimeWait)

		m.executeFSM(wepID1, liveMigrationInputTimerPop)
		expectUpdate(g, m, liveMigrationStateBase)

		// FSM should be cleaned up.
		g.Expect(m.fsms).To(BeEmpty())
	})
}

// expectUpdate drains PendingUpdates and checks that exactly one update was emitted with
// the given state.
func expectUpdate(g Gomega, m *liveMigrationMonitor, expectedState liveMigrationState) {
	updates := m.PendingUpdates()
	g.Expect(updates).To(HaveLen(1), "expected exactly one pending update")
	g.Expect(updates[0].State).To(Equal(expectedState))
}
