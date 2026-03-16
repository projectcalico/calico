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
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

const etherTypeRARP = layers.EthernetType(0x8035)

// garpHandle abstracts an AF_PACKET handle for GARP/RARP detection.
// Production code uses *pcapgo.EthernetHandle; tests inject fakes.
type garpHandle interface {
	io.Closer
	gopacket.PacketDataSource
}

// liveMigrationStateUpdate records a per-workload FSM state change that the
// liveMigrationMonitor needs to forward to its listener (the endpoint manager).
type liveMigrationStateUpdate struct {
	ID    types.WorkloadEndpointID
	State liveMigrationState
}

// liveMigrationMonitor tracks per-workload live migration state that cannot be inferred
// statelessly from the datastore.  It sees WorkloadEndpoint updates, extracts the live
// migration role, and drives a per-workload FSM whose state changes are forwarded to
// the endpoint manager via the liveMigrationListener interface during ResolveUpdateBatch.
type liveMigrationMonitor struct {
	roles           map[types.WorkloadEndpointID]proto.LiveMigrationRole
	fsms            map[types.WorkloadEndpointID]*liveMigrationFSM
	pendingUpdates  []liveMigrationStateUpdate
	listener        liveMigrationListener
	timerC          chan types.WorkloadEndpointID
	garpC           chan types.WorkloadEndpointID
	ifaceNames      map[types.WorkloadEndpointID]string
	migrationUIDs   map[types.WorkloadEndpointID]string
	newGARPHandle   func(string) (garpHandle, error)
	convergenceTime time.Duration
}

func newLiveMigrationMonitor(convergenceTime time.Duration) *liveMigrationMonitor {
	return &liveMigrationMonitor{
		roles:         make(map[types.WorkloadEndpointID]proto.LiveMigrationRole),
		fsms:          make(map[types.WorkloadEndpointID]*liveMigrationFSM),
		timerC:        make(chan types.WorkloadEndpointID),
		garpC:         make(chan types.WorkloadEndpointID),
		ifaceNames:    make(map[types.WorkloadEndpointID]string),
		migrationUIDs: make(map[types.WorkloadEndpointID]string),
		newGARPHandle: func(ifaceName string) (garpHandle, error) {
			return pcapgo.NewEthernetHandle(ifaceName)
		},
		convergenceTime: convergenceTime,
	}
}

// ResolveUpdateBatch drains accumulated FSM state changes and forwards them
// to the endpoint manager via the liveMigrationListener interface.  This runs
// before CompleteDeferredWork, so the endpoint manager sees the state changes
// before it programs the dataplane.
func (m *liveMigrationMonitor) ResolveUpdateBatch() error {
	for _, update := range m.pendingUpdates {
		m.listener.OnLiveMigrationStateUpdate(update.ID, update.State)
	}
	m.pendingUpdates = m.pendingUpdates[:0]
	return nil
}

func (m *liveMigrationMonitor) OnUpdate(protoBufMsg any) {
	switch msg := protoBufMsg.(type) {
	case *proto.WorkloadEndpointUpdate:
		id := types.ProtoToWorkloadEndpointID(msg.GetId())
		m.ifaceNames[id] = msg.Endpoint.Name
		if uid := msg.Endpoint.LiveMigrationUid; uid != "" {
			m.migrationUIDs[id] = uid
		}
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
		delete(m.ifaceNames, id)
		delete(m.migrationUIDs, id)
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
	if uid := m.migrationUIDs[id]; uid != "" {
		fsm.migrationUID = uid
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

func (i liveMigrationInput) String() string {
	switch i {
	case liveMigrationInputNoRole:
		return "NoRole"
	case liveMigrationInputSource:
		return "Source"
	case liveMigrationInputTarget:
		return "Target"
	case liveMigrationInputGARPDetected:
		return "GARPDetected"
	case liveMigrationInputTimerPop:
		return "TimerPop"
	case liveMigrationInputDeleted:
		return "Deleted"
	default:
		return fmt.Sprintf("Unknown(%d)", int(i))
	}
}

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

func (s liveMigrationState) String() string {
	switch s {
	case liveMigrationStateBase:
		return "Base"
	case liveMigrationStateTarget:
		return "Target"
	case liveMigrationStateLive:
		return "Live"
	case liveMigrationStateTimeWait:
		return "TimeWait"
	default:
		return fmt.Sprintf("Unknown(%d)", int(s))
	}
}

type liveMigrationFSM struct {
	logCtx       *logrus.Entry
	id           types.WorkloadEndpointID
	monitor      *liveMigrationMonitor
	currentState liveMigrationState
	migrationUID string
	timer        *time.Timer
	pcapHandle   garpHandle
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
		}
	case liveMigrationStateTarget:
		switch input {
		case liveMigrationInputGARPDetected:
			next = liveMigrationStateLive
		case liveMigrationInputNoRole:
			// Live migration completed but we missed the GARP.  Go straight to
			// TimeWait to allow routing to settle before reverting to normal.
			next = liveMigrationStateTimeWait
		case liveMigrationInputSource:
			next = liveMigrationStateBase
		case liveMigrationInputDeleted:
			next = liveMigrationStateBase
		}
	case liveMigrationStateLive:
		switch input {
		case liveMigrationInputNoRole:
			// Live migration complete.  Start the timer to allow routing to
			// settle everywhere before reverting to normal routing.
			next = liveMigrationStateTimeWait
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
		case liveMigrationInputDeleted:
			next = liveMigrationStateBase
		}
	}

	if next != f.currentState {
		logCtx.WithFields(logrus.Fields{
			"migrationUID": f.migrationUID,
			"from":         f.currentState,
			"to":           next,
		}).Info("Live migration state transition")

		// Do actions that we should always do when leaving a state.
		switch f.currentState {
		case liveMigrationStateTarget:
			f.stopGARPDetection()
		case liveMigrationStateTimeWait:
			f.stopElevatedRoutingTimer()
		}

		// Do actions that we should always do when entering a state.
		switch next {
		case liveMigrationStateTarget:
			f.startGARPDetection()
		case liveMigrationStateTimeWait:
			f.startElevatedRoutingTimer()
		}

		// Update state.
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

func (f *liveMigrationFSM) startGARPDetection() {
	ifaceName := f.monitor.ifaceNames[f.id]
	if ifaceName == "" {
		f.logCtx.Warn("No interface name for workload, skipping GARP detection")
		return
	}
	handle, err := f.monitor.newGARPHandle(ifaceName)
	if err != nil {
		f.logCtx.WithError(err).Warn("Failed to open packet capture for GARP detection")
		return
	}
	f.pcapHandle = handle
	go detectGARP(f.logCtx, f.id, handle, f.monitor.garpC)
}

func (f *liveMigrationFSM) stopGARPDetection() {
	if f.pcapHandle != nil {
		if err := f.pcapHandle.Close(); err != nil {
			f.logCtx.WithError(err).Debug("Error closing GARP detection handle")
		}
		f.pcapHandle = nil
	}
}

func (f *liveMigrationFSM) startElevatedRoutingTimer() {
	f.logCtx.WithField("duration", f.monitor.convergenceTime).Debug("Starting elevated routing timer")
	id := f.id
	f.timer = time.AfterFunc(f.monitor.convergenceTime, func() {
		f.monitor.timerC <- id
	})
}

func (f *liveMigrationFSM) stopElevatedRoutingTimer() {
	if f.timer != nil {
		f.logCtx.Debug("Stopping elevated routing timer")
		f.timer.Stop()
		f.timer = nil
	}
}

// OnGARPDetected is called by the main loop when a GARP/RARP packet is
// detected on a workload's interface.
func (m *liveMigrationMonitor) OnGARPDetected(id types.WorkloadEndpointID) {
	m.executeFSM(id, liveMigrationInputGARPDetected)
}

// OnTimerPop is called by the main loop when a timer fires for a workload.
// The timer may fire just before stopElevatedRoutingTimer() is called, so we
// guard against stale deliveries by checking the FSM still exists and is in
// TimeWait before driving it.
func (m *liveMigrationMonitor) OnTimerPop(id types.WorkloadEndpointID) {
	fsm, exists := m.fsms[id]
	if !exists || fsm.currentState != liveMigrationStateTimeWait {
		logrus.WithField("id", id).Debug("Ignoring stale timer pop for workload not in TimeWait")
		return
	}
	m.executeFSM(id, liveMigrationInputTimerPop)
}

// detectGARP reads packets from the given handle and sends the workload ID
// to garpC when a GARP or RARP packet is detected.  It is a one-shot
// goroutine: it returns after the first detection or when the handle is closed.
func detectGARP(logCtx *logrus.Entry, id types.WorkloadEndpointID,
	handle garpHandle, garpC chan<- types.WorkloadEndpointID) {
	// Note: handle is NOT defer-closed here. The FSM owns the handle lifecycle via
	// stopGARPDetection(), which closes the handle and causes packetSource.Packets() to return,
	// ending this goroutine.
	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for packet := range packetSource.Packets() {
		if isGARPOrRARP(packet) {
			logCtx.Info("Detected GARP/RARP packet on workload interface")
			garpC <- id
			return
		}
	}
}

// isGARPOrRARP returns true if the packet is a RARP (EtherType 0x8035)
// or a gratuitous ARP (sender IP == target IP).
func isGARPOrRARP(packet gopacket.Packet) bool {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return false
	}
	eth := ethLayer.(*layers.Ethernet)

	if eth.EthernetType == etherTypeRARP {
		return true
	}

	if eth.EthernetType == layers.EthernetTypeARP {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if bytes.Equal(arp.SourceProtAddress, arp.DstProtAddress) {
				return true
			}
		}
	}

	return false
}

func (m *liveMigrationMonitor) CompleteDeferredWork() error {
	// Nothing to do; state changes are forwarded in ResolveUpdateBatch.
	return nil
}
