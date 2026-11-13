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
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/vmipam"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const etherTypeRARP = layers.EthernetType(0x8035)

// garpHandle abstracts an AF_PACKET handle for GARP/RARP detection.
// Production code uses *pcapgo.EthernetHandle; tests inject fakes.
type garpHandle interface {
	io.Closer
	gopacket.PacketDataSource
}

// liveMigrationStateUpdate records a per-workload FSM state change that the
// liveMigrationMonitor needs to forward to its listeners (the endpoint managers).
type liveMigrationStateUpdate struct {
	ID    types.WorkloadEndpointID
	State liveMigrationState
}

// liveMigrationMonitor tracks per-workload live migration state that cannot be inferred
// statelessly from the datastore.  It sees WorkloadEndpoint updates, extracts the live
// migration role, and drives a per-workload FSM whose state changes are forwarded to the
// endpoint managers via the liveMigrationListener interface during ResolveUpdateBatch.
//
// There is one endpoint manager per IP version, and each keeps its own live migration state,
// so every state change must be forwarded to all of them: a monitor with only the IPv4
// manager registered would leave IPv6 workload routes unsuppressed and unelevated.
type liveMigrationMonitor struct {
	roles           map[types.WorkloadEndpointID]proto.LiveMigrationRole
	fsms            map[types.WorkloadEndpointID]*liveMigrationFSM
	pendingUpdates  []liveMigrationStateUpdate
	listeners       []liveMigrationListener
	timerC          chan types.WorkloadEndpointID
	garpC           chan types.WorkloadEndpointID
	ifaceNames      map[types.WorkloadEndpointID]string
	migrationUIDs   map[types.WorkloadEndpointID]string
	vmiNames        map[types.WorkloadEndpointID]string
	newGARPHandle   func(string) (garpHandle, error)
	convergenceTime time.Duration

	// vmOwners keeps each VM's IPAM owner attributes naming the pod that the VM runs in.  It is
	// fed from roles and vmiNames, never from the FSMs, so that it still converges when an FSM is
	// lost or interrupted - for example by a Felix restart at the end of a migration.
	vmOwners      *vmOwnerReconciler
	vmOwnersDirty set.Set[types.WorkloadEndpointID]
}

func newLiveMigrationMonitor(convergenceTime time.Duration, ipamClient ipam.Interface) *liveMigrationMonitor {
	return &liveMigrationMonitor{
		roles:         make(map[types.WorkloadEndpointID]proto.LiveMigrationRole),
		fsms:          make(map[types.WorkloadEndpointID]*liveMigrationFSM),
		timerC:        make(chan types.WorkloadEndpointID),
		garpC:         make(chan types.WorkloadEndpointID),
		ifaceNames:    make(map[types.WorkloadEndpointID]string),
		migrationUIDs: make(map[types.WorkloadEndpointID]string),
		vmiNames:      make(map[types.WorkloadEndpointID]string),
		newGARPHandle: func(ifaceName string) (garpHandle, error) {
			return pcapgo.NewEthernetHandle(ifaceName)
		},
		convergenceTime: convergenceTime,
		vmOwners:        newVMOwnerReconciler(ipamClient),
		vmOwnersDirty:   set.New[types.WorkloadEndpointID](),
	}
}

// registerListener adds a listener - in production, one endpoint manager per IP version -
// that should be told about every FSM state change.
func (m *liveMigrationMonitor) registerListener(l liveMigrationListener) {
	m.listeners = append(m.listeners, l)
}

// ResolveUpdateBatch drains accumulated FSM state changes and forwards them to each
// registered listener via the liveMigrationListener interface.  This runs before
// CompleteDeferredWork, so the endpoint managers see the state changes before they
// program the dataplane.
func (m *liveMigrationMonitor) ResolveUpdateBatch() error {
	for _, update := range m.pendingUpdates {
		for _, l := range m.listeners {
			l.OnLiveMigrationStateUpdate(update.ID, update.State)
		}
	}
	m.pendingUpdates = m.pendingUpdates[:0]
	return nil
}

func (m *liveMigrationMonitor) OnUpdate(protoBufMsg any) {
	switch msg := protoBufMsg.(type) {
	case *proto.WorkloadEndpointUpdate:
		id := types.ProtoToWorkloadEndpointID(msg.GetId())
		m.ifaceNames[id] = msg.Endpoint.Name
		// Intentionally we don't clear the UID when the LiveMigration resource
		// is deleted (i.e. when uid becomes "").  If there are any remaining FSM
		// transitions for this workload, it's clearer for the logs to continue
		// showing the UID that was associated with the migration.
		if uid := msg.Endpoint.LiveMigrationUid; uid != "" {
			m.migrationUIDs[id] = uid
		}
		if vmiName := msg.Endpoint.LiveMigrationVmiName; vmiName != "" {
			m.vmiNames[id] = vmiName
		}
		oldRole := m.roles[id]
		newRole := msg.Endpoint.LiveMigrationRole
		m.roles[id] = newRole
		m.vmOwnersDirty.Add(id)
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
		delete(m.vmiNames, id)
		m.executeFSM(id, liveMigrationInputDeleted)
		m.vmOwnersDirty.Add(id)
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
//    |              | Base   | Target   | Live     | TimeWait |
//    |--------------|--------|----------|----------|----------|
//    | Target       | Target |          |          |          |
//    | GARPDetected |        | Live     |          |          |
//    | NoRole       |        | TimeWait | TimeWait |          |
//    | TimerPop     |        |          |          | Base     |
//    | Source       |        | Base     | Base     | Base     |
//    | Deleted      |        | Base     | Base     | Base     |

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
	timerStopC   chan struct{}
	timerWG      sync.WaitGroup
	pcapHandle   garpHandle
	garpStopC    chan struct{}
	garpWG       sync.WaitGroup
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
		case liveMigrationStateLive:
			// The GARP shows that the VM is now running here, so promote this pod in IPAM
			// straight away, without waiting for the source pod to be torn down.  There is no
			// such promotion for Target -> TimeWait: NoRole can also mean the migration was
			// cancelled, and promoting this pod then would take the address away from the VM
			// still running on the source.  If the migration did succeed, the reconciler
			// promotes this pod once the source's CNI DEL has cleared the active owner.
			f.monitor.requestVMOwnerPromotion(f.id)
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
	f.garpStopC = make(chan struct{})
	f.garpWG.Add(1)
	go func() {
		defer f.garpWG.Done()
		detectGARP(f.logCtx, f.id, handle, f.monitor.garpC, f.garpStopC)
	}()
}

func (f *liveMigrationFSM) stopGARPDetection() {
	if f.pcapHandle != nil {
		if err := f.pcapHandle.Close(); err != nil {
			f.logCtx.WithError(err).Debug("Error closing GARP detection handle")
		}
		// Closing garpStopC aborts any in-progress send to garpC.  This is
		// essential to avoid a deadlock: garpC's only reader is the dataplane
		// main loop, and stopGARPDetection itself runs on the main loop (via
		// OnUpdate) when the FSM leaves the Target state.  If a GARP arrived
		// just before the workload update that ends the Target state - e.g. a
		// cutover RARP racing with the migration-complete update - then
		// detectGARP would be blocked mid-send with no reader, and the Wait()
		// below would block the main loop forever.
		close(f.garpStopC)
		// Wait for the detectGARP goroutine to exit.  Closing the handle causes
		// packetSource.Packets() to return, so this should complete almost immediately.
		f.garpWG.Wait()
		f.pcapHandle = nil
		f.garpStopC = nil
	}
}

func (f *liveMigrationFSM) startElevatedRoutingTimer() {
	f.logCtx.WithField("duration", f.monitor.convergenceTime).Debug("Starting elevated routing timer")
	id := f.id

	if f.timerStopC != nil {
		// This shouldn't happen: the FSM never enters TimeWait twice without leaving it in
		// between.  But an overwritten stop channel would leave the previous goroutine
		// unstoppable and wedge a later Wait(), so stop the old one properly rather than
		// leak it.
		f.logCtx.Warn("Elevated routing timer already running; stopping it before restart")
		f.stopElevatedRoutingTimer()
	}

	// Deliver the pop from a goroutine whose send stopElevatedRoutingTimer() can
	// cancel and reap, so that a stale pop can never be delivered after TimeWait
	// is exited and misattributed to a later TimeWait episode (see OnTimerPop).
	stopC := make(chan struct{})
	f.timerStopC = stopC
	f.timerWG.Add(1)
	go func() {
		defer f.timerWG.Done()
		fireC := time.After(f.monitor.convergenceTime)

		// The send case is disabled (nil channel) until the timer fires.
		var popC chan<- types.WorkloadEndpointID
		for {
			select {
			case <-fireC:
				popC = f.monitor.timerC
			case popC <- id:
				return
			case <-stopC:
				return
			}
		}
	}()
}

func (f *liveMigrationFSM) stopElevatedRoutingTimer() {
	if f.timerStopC != nil {
		f.logCtx.Debug("Stopping elevated routing timer")
		close(f.timerStopC)

		// Must wait for the goroutine to exit, to stop a just-cancelled timer from
		// delivering a stale pop: with both stopC and a pop receiver ready, select
		// picks at random.  Waiting here is what closes that race - we run on the
		// main loop, timerC's only reader, so no receiver exists until we return.
		f.timerWG.Wait()
		f.timerStopC = nil
	}
}

// OnGARPDetected is called by the main loop when a GARP/RARP packet is
// detected on a workload's interface.
func (m *liveMigrationMonitor) OnGARPDetected(id types.WorkloadEndpointID) {
	m.executeFSM(id, liveMigrationInputGARPDetected)
}

// OnTimerPop is called by the main loop when a timer fires for a workload.  Stale deliveries are
// prevented at source: stopElevatedRoutingTimer() waits for the timer goroutine to exit before
// returning, so a pop that does get through here was sent by a timer that had not been stopped.
// The state check here is kept as cheap defence in depth.
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
// goroutine: it returns after the first detection, when the handle is closed,
// or when stopC is closed.
func detectGARP(logCtx *logrus.Entry, id types.WorkloadEndpointID,
	handle garpHandle, garpC chan<- types.WorkloadEndpointID, stopC <-chan struct{}) {
	// Note: handle is NOT defer-closed here. The FSM owns the handle lifecycle via
	// stopGARPDetection(), which closes the handle and causes packetSource.Packets() to return,
	// ending this goroutine.
	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for packet := range packetSource.Packets() {
		if isGARPOrRARP(packet) {
			logCtx.Info("Detected GARP/RARP packet on workload interface")
			// garpC is unbuffered and its only reader is the dataplane main
			// loop, which may currently be inside stopGARPDetection() waiting
			// for this goroutine to exit; stopC guarantees this send cannot
			// block forever in that case.
			select {
			case garpC <- id:
			case <-stopC:
				logCtx.Debug("GARP detection stopped while reporting detection")
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

// CompleteDeferredWork passes workload changes on to the VM owner reconciler.  This only runs once
// the datastore is in sync, so the reconciler never acts on a partial set of workloads.
func (m *liveMigrationMonitor) CompleteDeferredWork() error {
	for id := range m.vmOwnersDirty.All() {
		owner, ok := m.vmOwnerFor(id)
		if !ok {
			m.vmOwners.remove(id)
			continue
		}

		// A migration target must not take the address over until the migration is known to
		// have succeeded, and the FSM handles that case with requestVMOwnerPromotion.
		m.vmOwners.set(id, owner, m.roles[id] != proto.LiveMigrationRole_TARGET)
	}
	m.vmOwnersDirty.Clear()
	return nil
}

func (m *liveMigrationMonitor) requestVMOwnerPromotion(id types.WorkloadEndpointID) {
	owner, ok := m.vmOwnerFor(id)
	if !ok {
		logrus.WithField("id", id).Debug("Not a VM with a known VMI name, skipping IPAM owner promotion")
		return
	}
	m.vmOwners.requestPromotion(id, owner)
}

// vmOwnerFor returns the IPAM owner identity of a workload that is a KubeVirt VM pod, or false for
// any other workload.
func (m *liveMigrationMonitor) vmOwnerFor(id types.WorkloadEndpointID) (vmOwner, bool) {
	vmiName := m.vmiNames[id]
	if vmiName == "" {
		return vmOwner{}, false
	}
	namespace, podName, ok := strings.Cut(id.WorkloadId, "/")
	if !ok {
		logrus.WithField("workloadID", id.WorkloadId).Warn("Cannot parse workload ID of VM pod")
		return vmOwner{}, false
	}
	return vmOwner{namespace: namespace, podName: podName, vmiName: vmiName}, true
}

// vmOwner identifies a KubeVirt VM pod as an IPAM owner of its VM's addresses.
type vmOwner struct {
	namespace string
	podName   string
	vmiName   string
}

// vmOwnerReconciler makes the pod that a VM is running in the active IPAM owner of the VM's
// addresses.  Nothing else does that when a migration's completion is missed, and without an active
// owner, no node is recorded for the address and any routes that Felix derives from IPAM disappear.
//
// It works on the IPAM owner attributes and never on FSM state: a pod that isn't a migration target
// and is the alternate owner, with no active owner, is the only claimant left, and it is promoted
// however it got there.  Any other state is left alone, and rechecked with backoff while the pod is
// the alternate owner of an address with an active owner, which is how it looks until the source
// pod's CNI DEL has run.
//
// IPAM calls block, so they run on a worker goroutine.  The main loop only updates entries under
// the lock and kicks the worker.
type vmOwnerReconciler struct {
	ipamClient ipam.Interface

	// Promotes the pod whatever the active owner is.  Only for a migration known to have
	// succeeded.
	ensureActiveVMOwnerAttrs func(ctx context.Context, ipamClient ipam.Interface,
		networkName, namespace, vmiName, podName string) error

	// Promotes the pod only where there is no active owner.
	promoteIfActiveEmpty func(ctx context.Context, ipamClient ipam.Interface,
		networkName, namespace, vmiName, podName string) (bool, error)

	initialBackoff time.Duration
	maxBackoff     time.Duration
	callTimeout    time.Duration

	lock    sync.Mutex
	entries map[types.WorkloadEndpointID]*vmOwnerEntry

	kickC     chan struct{}
	startOnce sync.Once
}

type vmOwnerEntry struct {
	owner vmOwner

	// reconcile is set while the pod isn't a migration target, so may be promoted if it's the
	// only claimant.
	reconcile bool

	// promotionRequested is set when the migration to this pod is known to have succeeded.
	promotionRequested bool

	// generation changes whenever the main loop changes the entry, so that the worker can discard
	// the result of a call that started before the change.
	generation uint64

	// Owned by the worker.  idle means there is nothing to do until the main loop changes the
	// entry.
	idle    bool
	due     time.Time
	backoff time.Duration
}

func newVMOwnerReconciler(ipamClient ipam.Interface) *vmOwnerReconciler {
	return &vmOwnerReconciler{
		ipamClient:               ipamClient,
		ensureActiveVMOwnerAttrs: vmipam.EnsureActiveVMOwnerAttrs,
		promoteIfActiveEmpty:     vmipam.PromoteAlternateVMOwnerIfActiveEmpty,
		initialBackoff:           100 * time.Millisecond,
		maxBackoff:               30 * time.Second,
		callTimeout:              30 * time.Second,
		entries:                  map[types.WorkloadEndpointID]*vmOwnerEntry{},
		kickC:                    make(chan struct{}, 1),
	}
}

// set records a VM pod and whether it may be promoted as the only claimant.  An unchanged
// workload doesn't trigger a recheck.
func (r *vmOwnerReconciler) set(id types.WorkloadEndpointID, owner vmOwner, reconcile bool) {
	r.lock.Lock()
	defer r.lock.Unlock()

	e := r.entries[id]
	if e == nil {
		if !reconcile {
			return
		}
		e = &vmOwnerEntry{}
		r.entries[id] = e
	} else if e.owner == owner && e.reconcile == reconcile {
		return
	}
	e.owner = owner
	e.reconcile = reconcile
	if !e.reconcile && !e.promotionRequested {
		delete(r.entries, id)
		return
	}
	r.resetLocked(e)
}

// requestPromotion promotes the pod even if another owner is still active.
func (r *vmOwnerReconciler) requestPromotion(id types.WorkloadEndpointID, owner vmOwner) {
	r.lock.Lock()
	defer r.lock.Unlock()

	e := r.entries[id]
	if e == nil {
		e = &vmOwnerEntry{}
		r.entries[id] = e
	}
	e.owner = owner
	e.promotionRequested = true
	r.resetLocked(e)
}

func (r *vmOwnerReconciler) remove(id types.WorkloadEndpointID) {
	r.lock.Lock()
	defer r.lock.Unlock()
	delete(r.entries, id)
}

func (r *vmOwnerReconciler) resetLocked(e *vmOwnerEntry) {
	e.generation++
	e.idle = false
	e.due = time.Time{}
	e.backoff = 0
	r.startOnce.Do(func() { go r.loop() })
	select {
	case r.kickC <- struct{}{}:
	default:
	}
}

func (r *vmOwnerReconciler) loop() {
	for {
		var timerC <-chan time.Time
		if wait, ok := r.reconcileDueEntries(); ok {
			timer := time.NewTimer(wait)
			timerC = timer.C
			select {
			case <-r.kickC:
			case <-timerC:
			}
			timer.Stop()
		} else {
			<-r.kickC
		}
	}
}

type vmOwnerWork struct {
	id         types.WorkloadEndpointID
	entry      *vmOwnerEntry
	generation uint64
	owner      vmOwner
	promote    bool
}

// reconcileDueEntries does the IPAM work for every entry that is due, and returns how long until
// the next one is due, or false if none is pending.
func (r *vmOwnerReconciler) reconcileDueEntries() (time.Duration, bool) {
	now := time.Now()
	var work []vmOwnerWork
	r.lock.Lock()
	for id, e := range r.entries {
		if e.idle || e.due.After(now) {
			continue
		}
		work = append(work, vmOwnerWork{
			id:         id,
			entry:      e,
			generation: e.generation,
			owner:      e.owner,
			promote:    e.promotionRequested,
		})
	}
	r.lock.Unlock()

	for _, w := range work {
		r.reconcileOne(w)
	}

	r.lock.Lock()
	defer r.lock.Unlock()
	var next time.Time
	for _, e := range r.entries {
		if e.idle {
			continue
		}
		if next.IsZero() || e.due.Before(next) {
			next = e.due
		}
	}
	if next.IsZero() {
		return 0, false
	}
	return max(time.Until(next), 0), true
}

func (r *vmOwnerReconciler) reconcileOne(w vmOwnerWork) {
	logCtx := logrus.WithFields(logrus.Fields{
		"id":        w.id,
		"namespace": w.owner.namespace,
		"pod":       w.owner.podName,
		"vmiName":   w.owner.vmiName,
	})
	ctx, cancel := context.WithTimeout(context.Background(), r.callTimeout)
	defer cancel()

	var err error
	promoted := false
	if w.promote {
		err = r.ensureActiveVMOwnerAttrs(ctx, r.ipamClient, "", w.owner.namespace, w.owner.vmiName, w.owner.podName)
		promoted = err == nil
	} else {
		promoted, err = r.promoteIfActiveEmpty(ctx, r.ipamClient, "", w.owner.namespace, w.owner.vmiName, w.owner.podName)
	}

	r.lock.Lock()
	defer r.lock.Unlock()
	if r.entries[w.id] != w.entry || w.entry.generation != w.generation {
		logCtx.Debug("VM pod changed during IPAM owner update, discarding result")
		return
	}
	e := w.entry

	switch {
	case err == nil:
		if promoted && w.promote {
			logCtx.Info("Promoted live-migrated VM pod to active IPAM owner")
		} else if promoted {
			logCtx.Info("Promoted VM pod to active IPAM owner after a missed live migration completion")
		} else {
			logCtx.Debug("VM pod is already the active IPAM owner")
		}
		r.doneLocked(w.id, e)
	case errors.Is(err, vmipam.ErrActiveOwnerPresent):
		// Expected until the source pod's CNI DEL has cleared the active owner.
		logCtx.WithError(err).Debug("VM pod is waiting for the active IPAM owner to be cleared")
		r.backoffLocked(e)
	case errors.Is(err, vmipam.ErrAlternateOwnerEmpty),
		errors.Is(err, vmipam.ErrAlternateOwnerMismatch),
		errors.Is(err, vmipam.ErrNoVMAddresses):
		if w.promote {
			logCtx.WithError(err).Warn("Cannot promote live-migrated VM pod to active IPAM owner")
		} else {
			logCtx.WithError(err).Debug("VM pod is not an IPAM owner to promote")
		}
		r.doneLocked(w.id, e)
	default:
		r.backoffLocked(e)
		logCtx.WithError(err).WithField("retryIn", e.backoff).Warn(
			"Failed to update IPAM owner of VM pod, will retry")
	}
}

// doneLocked finishes a promotion request, if there was one.  An entry that may still be promoted
// as the only claimant goes on to be checked for that straight away, and otherwise is finished
// with.
func (r *vmOwnerReconciler) doneLocked(id types.WorkloadEndpointID, e *vmOwnerEntry) {
	if e.promotionRequested {
		e.promotionRequested = false
		if !e.reconcile {
			delete(r.entries, id)
			return
		}
		e.due = time.Time{}
		e.backoff = 0
		return
	}
	e.idle = true
}

func (r *vmOwnerReconciler) backoffLocked(e *vmOwnerEntry) {
	if e.backoff == 0 {
		e.backoff = r.initialBackoff
	} else {
		e.backoff = min(2*e.backoff, r.maxBackoff)
	}
	e.due = time.Now().Add(e.backoff)
}
