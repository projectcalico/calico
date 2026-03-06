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
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

// liveMigrationStateUpdate is a pseudo-proto message emitted by the liveMigrationMonitor
// when a per-workload FSM changes state.  It is fanned out to all managers (like
// ifaceStateUpdate) so that the endpoint manager can adjust routing for live-migrating
// workloads.
type liveMigrationStateUpdate struct {
	ID    types.WorkloadEndpointID
	State liveMigrationState
}

// liveMigrationMonitor tracks per-workload live migration state that cannot be inferred
// statelessly from the datastore.  It sees WorkloadEndpoint updates, extracts the live
// migration role, and drives a per-workload FSM whose state changes are signalled to the
// rest of the dataplane as liveMigrationStateUpdate messages.
type liveMigrationMonitor struct {
	roles          map[types.WorkloadEndpointID]proto.LiveMigrationRole
	fsms           map[types.WorkloadEndpointID]*liveMigrationFSM
	pendingUpdates []liveMigrationStateUpdate
}

func newLiveMigrationMonitor() *liveMigrationMonitor {
	return &liveMigrationMonitor{
		roles: make(map[types.WorkloadEndpointID]proto.LiveMigrationRole),
		fsms:  make(map[types.WorkloadEndpointID]*liveMigrationFSM),
	}
}

// PendingUpdates returns the accumulated FSM state changes and clears the buffer.
func (m *liveMigrationMonitor) PendingUpdates() []liveMigrationStateUpdate {
	updates := m.pendingUpdates
	m.pendingUpdates = nil
	return updates
}

func (m *liveMigrationMonitor) OnUpdate(protoBufMsg any) {
	switch msg := protoBufMsg.(type) {
	case *proto.WorkloadEndpointUpdate:
		id := types.ProtoToWorkloadEndpointID(msg.GetId())
		oldRole := m.roles[id]
		newRole := msg.Endpoint.LiveMigrationRole
		m.roles[id] = newRole
		if oldRole != newRole {
			switch newRole {
			case proto.LiveMigrationRole_NO_ROLE:
				m.executeFSM(id, liveMigrationInputNoRole)
			case proto.LiveMigrationRole_SOURCE:
				m.executeFSM(id, liveMigrationInputSource)
			case proto.LiveMigrationRole_TARGET:
				m.executeFSM(id, liveMigrationInputTarget)
			}
		}
	case *proto.WorkloadEndpointRemove:
		id := types.ProtoToWorkloadEndpointID(msg.GetId())
		delete(m.roles, id)
		m.executeFSM(id, liveMigrationInputDeleted)
	}
}

func (m *liveMigrationMonitor) executeFSM(id types.WorkloadEndpointID, input liveMigrationInput) {
	fsm, exists := m.fsms[id]
	if !exists {
		fsm = &liveMigrationFSM{
			logCtx:       logrus.WithField("id", id),
			id:           id,
			monitor:      m,
			currentState: liveMigrationStateBase,
		}
		m.fsms[id] = fsm
	}
	fsm.handleInput(input)
	if fsm.currentState == liveMigrationStateBase {
		delete(m.fsms, id)
	}
}

// liveMigrationInput represents an input event to the per-workload FSM.
type liveMigrationInput int

const (
	liveMigrationInputNoRole liveMigrationInput = iota
	liveMigrationInputSource
	liveMigrationInputTarget
	liveMigrationInputGARPDetected
	liveMigrationInputTimerPop
	liveMigrationInputDeleted
)

// liveMigrationState represents the current state of the per-workload FSM.
//
// FSM table (rows = inputs, columns = current state, cells = next state, empty = no-op):
//
//	              Base      Target    Live      TimeWait
//	Target        Target
//	GARPDetected            Live
//	NoRole                            TimeWait  TimeWait
//	TimerPop                                    Base
//	Source                  Base      Base      Base
//	Deleted                 Base      Base      Base
type liveMigrationState int

const (
	liveMigrationStateBase liveMigrationState = iota
	liveMigrationStateTarget
	liveMigrationStateLive
	liveMigrationStateTimeWait
)

type liveMigrationFSM struct {
	logCtx       *logrus.Entry
	id           types.WorkloadEndpointID
	monitor      *liveMigrationMonitor
	currentState liveMigrationState
}

func (f *liveMigrationFSM) handleInput(input liveMigrationInput) {
	logCtx := f.logCtx.WithField("input", input)
	logCtx.Debug("Handle FSM input")

	next := f.currentState
	switch f.currentState {
	case liveMigrationStateBase:
		switch input {
		case liveMigrationInputTarget:
			next = liveMigrationStateTarget
			f.startGARPDetection()
		}
	case liveMigrationStateTarget:
		switch input {
		case liveMigrationInputGARPDetected:
			next = liveMigrationStateLive
			f.stopGARPDetection()
		case liveMigrationInputNoRole:
			// Live migration completed but we missed the GARP.  Go straight to
			// TimeWait to allow routing to settle before reverting to normal.
			next = liveMigrationStateTimeWait
			f.stopGARPDetection()
			f.startElevatedRoutingTimer()
		case liveMigrationInputSource:
			next = liveMigrationStateBase
			f.stopGARPDetection()
		case liveMigrationInputDeleted:
			next = liveMigrationStateBase
			f.stopGARPDetection()
		}
	case liveMigrationStateLive:
		switch input {
		case liveMigrationInputNoRole:
			// Live migration complete.  Start the timer to allow routing to
			// settle everywhere before reverting to normal routing.
			next = liveMigrationStateTimeWait
			f.startElevatedRoutingTimer()
		case liveMigrationInputSource:
			// Re-migration: this WEP is now the source of a new live migration.
			next = liveMigrationStateBase
		case liveMigrationInputDeleted:
			next = liveMigrationStateBase
		}
	case liveMigrationStateTimeWait:
		switch input {
		case liveMigrationInputNoRole:
			// Already in TimeWait; no-op (timer is already running).
		case liveMigrationInputTimerPop:
			next = liveMigrationStateBase
		case liveMigrationInputSource:
			// Re-migration: this WEP is now the source of a new live migration.
			next = liveMigrationStateBase
			f.stopElevatedRoutingTimer()
		case liveMigrationInputDeleted:
			next = liveMigrationStateBase
			f.stopElevatedRoutingTimer()
		}
	}

	if next != f.currentState {
		logCtx.WithField("next", next).Debug("FSM state change")
		f.currentState = next
		f.emitStateChange(next)
	} else {
		logCtx.Debug("FSM state unchanged")
	}
}

func (f *liveMigrationFSM) emitStateChange(next liveMigrationState) {
	f.monitor.pendingUpdates = append(f.monitor.pendingUpdates, liveMigrationStateUpdate{
		ID:    f.id,
		State: next,
	})
}

func (f *liveMigrationFSM) startGARPDetection() {}

func (f *liveMigrationFSM) stopGARPDetection() {}

func (f *liveMigrationFSM) startElevatedRoutingTimer() {}

func (f *liveMigrationFSM) stopElevatedRoutingTimer() {}

func (m *liveMigrationMonitor) CompleteDeferredWork() error {
	// Nothing to do; state changes are emitted synchronously via pendingUpdates
	// and drained by the main loop.
	return nil
}
