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
	roles           map[types.WorkloadEndpointID]proto.LiveMigrationRole
	fsms            map[types.WorkloadEndpointID]*liveMigrationFSM
	pendingUpdates  []liveMigrationStateUpdate
	timerC          chan types.WorkloadEndpointID
	garpC           chan types.WorkloadEndpointID
	ifaceNames      map[types.WorkloadEndpointID]string
	newGARPHandle   func(string) (garpHandle, error)
	convergenceTime time.Duration
}

func newLiveMigrationMonitor(convergenceTime time.Duration) *liveMigrationMonitor {
	return &liveMigrationMonitor{
		roles:      make(map[types.WorkloadEndpointID]proto.LiveMigrationRole),
		fsms:       make(map[types.WorkloadEndpointID]*liveMigrationFSM),
		timerC:     make(chan types.WorkloadEndpointID, 100),
		garpC:      make(chan types.WorkloadEndpointID, 100),
		ifaceNames: make(map[types.WorkloadEndpointID]string),
		newGARPHandle: func(ifaceName string) (garpHandle, error) {
			return pcapgo.NewEthernetHandle(ifaceName)
		},
		convergenceTime: convergenceTime,
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
		m.ifaceNames[id] = msg.Endpoint.Name
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
		select {
		case f.monitor.timerC <- id:
		default:
			logrus.WithField("id", id).Warn("Live migration timer channel full, dropping timer pop")
		}
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
func (m *liveMigrationMonitor) OnTimerPop(id types.WorkloadEndpointID) {
	m.executeFSM(id, liveMigrationInputTimerPop)
}

// detectGARP reads packets from the given handle and sends the workload ID
// to garpC when a GARP or RARP packet is detected.  It is a one-shot
// goroutine: it returns after the first detection or when the handle is closed.
func detectGARP(logCtx *logrus.Entry, id types.WorkloadEndpointID,
	handle garpHandle, garpC chan<- types.WorkloadEndpointID) {
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for packet := range packetSource.Packets() {
		if isGARPOrRARP(packet) {
			logCtx.Info("Detected GARP/RARP packet on workload interface")
			select {
			case garpC <- id:
			default:
				logCtx.Warn("GARP detection channel full, dropping notification")
			}
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
	// Nothing to do; state changes are emitted synchronously via pendingUpdates
	// and drained by the main loop.
	return nil
}
