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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/vmipam"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const etherTypeRARP = layers.EthernetType(0x8035)

// Values of the "outcome" label on countLiveMigrationCompletions.
const (
	liveMigrationOutcomeCompletedWithGARP = "completed_with_garp"
	liveMigrationOutcomeCompletedNoGARP   = "completed_no_garp"
	liveMigrationOutcomeAborted           = "aborted"
)

var (
	histogramLiveMigrationRouteProgramming = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "felix_live_migration_route_programming_seconds",
		Help: "Time from Felix detecting a migrated VM's GARP/RARP on the destination host to Felix " +
			"writing the VM's elevated-priority route into the kernel.  One observation per route.",
		// Healthy migrations take tens of milliseconds; the tail of interest is around 1-5s.
		Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1, 1.5, 2, 3, 5, 10},
	})
	countLiveMigrationCompletions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_live_migration_completions_total",
		Help: "Number of live migrations to this host that have finished, by outcome: " +
			"completed_with_garp (Felix saw the VM's GARP/RARP), completed_no_garp (the migration " +
			"completed without Felix seeing a GARP/RARP), or aborted.",
	}, []string{"outcome"})
)

func init() {
	prometheus.MustRegister(histogramLiveMigrationRouteProgramming)
	prometheus.MustRegister(countLiveMigrationCompletions)
}

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

	// OnRouteProgrammed is set in the Live and TimeWait states, for the endpoint managers to
	// call when they have written one of the workload's elevated-priority routes into the
	// kernel.
	OnRouteProgrammed func(cidr ip.CIDR)
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
	vmiNames        map[types.WorkloadEndpointID]string
	newGARPHandle   func(string) (garpHandle, error)
	convergenceTime time.Duration

	// ipamClient is the Calico IPAM client used to swap owner attributes
	// when live migration completes.
	ipamClient               ipam.Interface
	ensureActiveVMOwnerAttrs func(
		ctx context.Context,
		ipamClient ipam.Interface,
		networkName string,
		namespace string,
		vmiName string,
		targetPodName string,
	) error
}

func newLiveMigrationMonitor(convergenceTime time.Duration, ipamClient ipam.Interface) *liveMigrationMonitor {
	return &liveMigrationMonitor{
		roles:      make(map[types.WorkloadEndpointID]proto.LiveMigrationRole),
		fsms:       make(map[types.WorkloadEndpointID]*liveMigrationFSM),
		timerC:     make(chan types.WorkloadEndpointID),
		garpC:      make(chan types.WorkloadEndpointID),
		ifaceNames: make(map[types.WorkloadEndpointID]string),
		vmiNames:   make(map[types.WorkloadEndpointID]string),
		newGARPHandle: func(ifaceName string) (garpHandle, error) {
			return pcapgo.NewEthernetHandle(ifaceName)
		},
		convergenceTime:          convergenceTime,
		ipamClient:               ipamClient,
		ensureActiveVMOwnerAttrs: vmipam.EnsureActiveVMOwnerAttrs,
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
			l.OnLiveMigrationStateUpdate(update.ID, update.State, update.OnRouteProgrammed)
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
		if vmiName := msg.Endpoint.LiveMigrationVmiName; vmiName != "" {
			m.vmiNames[id] = vmiName
		}
		oldRole := m.roles[id]
		newRole := msg.Endpoint.LiveMigrationRole
		m.roles[id] = newRole
		if oldRole != newRole {
			switch newRole {
			case proto.LiveMigrationRole_NO_ROLE:
				m.executeFSM(id, liveMigrationInputNoRole, "")
			case proto.LiveMigrationRole_SOURCE:
				m.executeFSM(id, liveMigrationInputSource, "")
			case proto.LiveMigrationRole_TARGET:
				m.executeFSM(id, liveMigrationInputTarget, msg.Endpoint.LiveMigrationUid)
			}
		}
	case *proto.WorkloadEndpointRemove:
		id := types.ProtoToWorkloadEndpointID(msg.GetId())
		delete(m.roles, id)
		delete(m.ifaceNames, id)
		delete(m.vmiNames, id)
		m.executeFSM(id, liveMigrationInputDeleted, "")
	}
}

// newFSM creates the FSM for a workload that is becoming the target of a live migration.  The FSM
// is discarded when it returns to the Base state, so it normally lives for one migration, and the
// migration's UID can be fixed in its log context.  That way the UID is still logged after the
// LiveMigration resource has been deleted, which clears it from the workload.
func (m *liveMigrationMonitor) newFSM(id types.WorkloadEndpointID, migrationUID string) *liveMigrationFSM {
	return &liveMigrationFSM{
		logCtx: logrus.WithFields(logrus.Fields{
			"id":           id,
			"migrationUID": migrationUID,
		}),
		id:           id,
		monitor:      m,
		currentState: liveMigrationStateBase,
	}
}

// executeFSM delivers an input to the workload's FSM.  No FSM means the Base state, where only a
// Target input does anything, so only a Target input creates an FSM, with the given migrationUID.
// For any other input, migrationUID is ignored.
func (m *liveMigrationMonitor) executeFSM(
	id types.WorkloadEndpointID,
	input liveMigrationInput,
	migrationUID string,
) {
	fsm, exists := m.fsms[id]
	if !exists {
		if input != liveMigrationInputTarget {
			logrus.WithFields(logrus.Fields{
				"id":    id,
				"input": input,
			}).Debug("Ignoring live migration input for workload with no FSM")
			return
		}
		fsm = m.newFSM(id, migrationUID)
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
	timerStopC   chan struct{}
	timerWG      sync.WaitGroup
	pcapHandle   garpHandle
	garpStopC    chan struct{}
	garpWG       sync.WaitGroup
	ipamSwapOnce sync.Once

	// garpDetectedAt is when the GARP detection goroutine saw a GARP/RARP, or zero if it hasn't.
	// That goroutine writes it before exiting, so it is safe to read once stopGARPDetection has
	// waited for the goroutine.  It is recorded even when the main loop never gets to process
	// the GARP, because the end of the migration overtakes it.
	garpDetectedAt time.Time

	// routeReporter exists in the Live and TimeWait states.
	routeReporter *liveMigrationRouteReporter
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
			"from": f.currentState,
			"to":   next,
		}).Info("Live migration state transition")

		// Do actions that we should always do when leaving a state.
		switch f.currentState {
		case liveMigrationStateTarget:
			f.stopGARPDetection()
			f.recordCompletion(next)
		case liveMigrationStateTimeWait:
			f.stopElevatedRoutingTimer()
		}

		// Do actions that we should always do when entering a state.
		switch next {
		case liveMigrationStateBase:
			f.routeReporter = nil
		case liveMigrationStateTarget:
			f.startGARPDetection()
		case liveMigrationStateLive:
			f.startIPAMOwnerSwap()
		case liveMigrationStateTimeWait:
			f.startIPAMOwnerSwap()
			f.startElevatedRoutingTimer()
		}

		// Update state.
		f.currentState = next
		f.emitStateChange(next)
	} else {
		logCtx.Debug("FSM state unchanged")
	}
}

// recordCompletion is called when the FSM leaves the Target state, i.e. when the migration of
// the workload to this host has either completed or been aborted.  It counts the outcome and, for
// a completion, creates the reporter that the endpoint managers call as they write the
// workload's elevated-priority routes.
func (f *liveMigrationFSM) recordCompletion(next liveMigrationState) {
	if next == liveMigrationStateBase {
		countLiveMigrationCompletions.WithLabelValues(liveMigrationOutcomeAborted).Inc()
		return
	}
	if f.garpDetectedAt.IsZero() {
		countLiveMigrationCompletions.WithLabelValues(liveMigrationOutcomeCompletedNoGARP).Inc()
	} else {
		countLiveMigrationCompletions.WithLabelValues(liveMigrationOutcomeCompletedWithGARP).Inc()
	}
	f.routeReporter = newLiveMigrationRouteReporter(f.logCtx, f.garpDetectedAt)
}

func (f *liveMigrationFSM) emitStateChange(next liveMigrationState) {
	update := liveMigrationStateUpdate{
		ID:    f.id,
		State: next,
	}
	if f.routeReporter != nil {
		update.OnRouteProgrammed = f.routeReporter.onRouteProgrammed
	}
	f.monitor.pendingUpdates = append(f.monitor.pendingUpdates, update)
}

func (f *liveMigrationFSM) startGARPDetection() {
	f.garpDetectedAt = time.Time{}
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
		f.detectGARP(handle, f.garpStopC)
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
	m.executeFSM(id, liveMigrationInputGARPDetected, "")
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
	m.executeFSM(id, liveMigrationInputTimerPop, "")
}

// detectGARP reads packets from the given handle, and records the time and sends the workload ID
// to garpC when a GARP or RARP packet is detected.  It is a one-shot goroutine: it returns after
// the first detection, when the handle is closed, or when stopC is closed.
func (f *liveMigrationFSM) detectGARP(handle garpHandle, stopC <-chan struct{}) {
	// Note: handle is NOT defer-closed here. The FSM owns the handle lifecycle via
	// stopGARPDetection(), which closes the handle and causes packetSource.Packets() to return,
	// ending this goroutine.
	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for packet := range packetSource.Packets() {
		if isGARPOrRARP(packet) {
			// Timestamp before the send to garpC, which can wait for as long as the main loop is
			// busy.
			f.garpDetectedAt = time.Now()
			f.logCtx.Info("Detected GARP/RARP packet on workload interface")
			// garpC is unbuffered and its only reader is the dataplane main
			// loop, which may currently be inside stopGARPDetection() waiting
			// for this goroutine to exit; stopC guarantees this send cannot
			// block forever in that case.
			select {
			case f.monitor.garpC <- f.id:
			case <-stopC:
				f.logCtx.Debug("GARP detection stopped while reporting detection")
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

// startIPAMOwnerSwap begins an asynchronous IPAM owner attribute swap when a
// live migration completes.  It is called when entering both the Live state
// (happy path: GARP detected) and the TimeWait state (missed GARP path:
// Target→TimeWait).  sync.Once ensures the swap is initiated at most once per
// FSM lifecycle, so the Live→TimeWait transition does not trigger a duplicate.
func (f *liveMigrationFSM) startIPAMOwnerSwap() {
	f.ipamSwapOnce.Do(f.doIPAMOwnerSwap)
}

// doIPAMOwnerSwap performs the actual IPAM owner attribute swap.  It uses the
// VMI name from the proto.WorkloadEndpoint (extracted from the pod's labels by
// the calc graph) and calls vmipam.EnsureActiveVMOwnerAttrs to atomically
// promote the alternate (target) owner attributes to active.  Transient errors
// are retried with backoff.  This runs in a goroutine to avoid blocking the
// dataplane main loop.
func (f *liveMigrationFSM) doIPAMOwnerSwap() {
	vmiName := f.monitor.vmiNames[f.id]
	if vmiName == "" {
		f.logCtx.Debug("No VMI name available, skipping IPAM owner swap")
		return
	}

	// Parse namespace and pod name from the workload ID (format: "namespace/podName").
	parts := strings.SplitN(f.id.WorkloadId, "/", 2)
	if len(parts) != 2 {
		f.logCtx.WithField("workloadID", f.id.WorkloadId).Warn(
			"Cannot parse workload ID for IPAM owner swap")
		return
	}
	namespace := parts[0]
	podName := parts[1]

	logCtx := f.logCtx.WithFields(logrus.Fields{
		"namespace": namespace,
		"pod":       podName,
		"vmiName":   vmiName,
	})
	logCtx.Info("Starting IPAM owner attribute swap for live migration")

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		const maxRetries = 5
		backoff := 100 * time.Millisecond
		for attempt := 1; attempt <= maxRetries; attempt++ {
			err := f.monitor.ensureActiveVMOwnerAttrs(ctx, f.monitor.ipamClient, "", namespace, vmiName, podName)
			if err == nil {
				logCtx.Info("Successfully swapped IPAM owner attributes")
				return
			}
			if errors.Is(err, vmipam.ErrAlternateOwnerEmpty) || errors.Is(err, vmipam.ErrAlternateOwnerMismatch) {
				logCtx.WithError(err).Warn("Non-retryable error swapping IPAM owner attributes")
				return
			}
			logCtx.WithError(err).WithField("attempt", attempt).Warn(
				"Transient error swapping IPAM owner attributes, will retry")
			if attempt < maxRetries {
				select {
				case <-time.After(backoff):
					backoff *= 2
				case <-ctx.Done():
					logCtx.Warn("Context cancelled while retrying IPAM owner swap")
					return
				}
			}
		}
		logCtx.Warn("Exhausted retries for IPAM owner attribute swap")
	}()
}

func (m *liveMigrationMonitor) CompleteDeferredWork() error {
	// Nothing to do; state changes are forwarded in ResolveUpdateBatch.
	return nil
}

// liveMigrationRouteReporter logs, and records in the route programming histogram, when each of a
// migrated workload's elevated-priority routes is first written into the kernel on this host.
// There can be several such routes - for each IP version, and for floating IPs - and each is
// reported once per migration, even if a later resync has to rewrite it.
//
// onRouteProgrammed is called from RouteTable apply goroutines, which run concurrently with the
// dataplane main loop and with each other (IPv4 and IPv6), hence the lock.
type liveMigrationRouteReporter struct {
	logCtx         *logrus.Entry
	garpDetectedAt time.Time

	lock     sync.Mutex
	reported set.Set[ip.CIDR]
}

func newLiveMigrationRouteReporter(logCtx *logrus.Entry, garpDetectedAt time.Time) *liveMigrationRouteReporter {
	return &liveMigrationRouteReporter{
		logCtx:         logCtx,
		garpDetectedAt: garpDetectedAt,
		reported:       set.New[ip.CIDR](),
	}
}

func (r *liveMigrationRouteReporter) onRouteProgrammed(cidr ip.CIDR) {
	programmedAt := time.Now()

	r.lock.Lock()
	alreadyReported := r.reported.Contains(cidr)
	r.reported.Add(cidr)
	r.lock.Unlock()
	if alreadyReported {
		return
	}

	logCtx := r.logCtx.WithField("cidr", cidr)
	if r.garpDetectedAt.IsZero() {
		logCtx.Info("Live migration route programmed (no GARP/RARP was detected)")
		return
	}
	sinceGARP := programmedAt.Sub(r.garpDetectedAt)
	histogramLiveMigrationRouteProgramming.Observe(sinceGARP.Seconds())
	logCtx.WithField("sinceGARP", sinceGARP).Info("Live migration route programmed")
}
