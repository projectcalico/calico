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

// Live Migration Monitor.
type liveMigrationMonitor struct {
	roles map[types.WorkloadEndpointID]proto.LiveMigrationRole
	fsms  map[types.WorkloadEndpointID]*liveMigrationFSM
}

func newLiveMigrationMonitor() *liveMigrationMonitor {
	return &liveMigrationMonitor{
		roles: make(map[types.WorkloadEndpointID]proto.LiveMigrationRole),
		fsms:  make(map[types.WorkloadEndpointID]*liveMigrationFSM),
	}
}

func (m *liveMigrationMonitor) OnUpdate(protoBufMsg any) {
	switch msg := protoBufMsg.(type) {
	case *proto.WorkloadEndpointUpdate:
		id := types.ProtoToWorkloadEndpointID(msg.GetId())
		oldRole, known := m.roles[id]
		newRole := msg.Endpoint.LiveMigrationRole
		m.roles[id] = newRole
		changed := (!known) || (oldRole != newRole)
		if changed {
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
		oldRole, known := m.roles[id]
		delete(m.roles, id)
		m.executeFSM(id, liveMigrationInputDeleted)
	}
}

func (m *liveMigrationMonitor) executeFSM(id types.WorkloadEndpointID, input liveMigrationInput) {
	fsm, exists := m.fsms[id]
	if !exists {
		fsm = &liveMigrationFSM{
			logCtx:       logrus.WithField("id", id),
			currentState: liveMigrationStateBase,
		}
	}
	fsm.handleInput(input)
}

// Live Migration FSM.
type liveMigrationInput int

const (
	liveMigrationInputNoRole liveMigrationInput = iota
	liveMigrationInputSource
	liveMigrationInputTarget
	liveMigrationInputGARPDetected
	liveMigrationInputTimerPop
	liveMigrationInputDeleted
)

type liveMigrationState int

const (
	liveMigrationStateBase liveMigrationState = iota
	liveMigrationStateTarget
	liveMigrationStateLive
	liveMigrationStateDone
)

type liveMigrationFSM struct {
	logCtx       *logrus.Entry
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
			next = liveMigrationStateLive
			f.stopGARPDetection()
			f.startElevatedRoutingTimer()
		}
	case liveMigrationStateLive:
		switch input {
		case liveMigrationInputNoRole:
			next = liveMigrationStateLive
			f.startElevatedRoutingTimer()
		case liveMigrationInputTimerPop:
			next = liveMigrationStateDone
		case liveMigrationInputSource:
			next = liveMigrationStateDone
		}
	case liveMigrationStateDone:
		// No-op for all inputs.
	}

	if next != f.currentState {
		logCtx.WithField("next", next).Debug("FSM state change")
		f.currentState = next
		f.emitStateChange(next)
	} else {
		logCtx.Debug("FSM state unchanged")
	}
}

func (f *liveMigrationFSM) emitStateChange(next liveMigrationState) {}

func (f *liveMigrationFSM) startGARPDetection() {}

func (f *liveMigrationFSM) stopGARPDetection() {}

func (f *liveMigrationFSM) startElevatedRoutingTimer() {}
