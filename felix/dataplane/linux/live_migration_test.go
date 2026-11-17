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
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/vmipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var testConvergenceTime = 30 * time.Second

// fakeLiveMigrationListener captures state updates for test assertions.
type fakeLiveMigrationListener struct {
	updates []liveMigrationStateUpdate
}

func (f *fakeLiveMigrationListener) OnLiveMigrationStateUpdate(id types.WorkloadEndpointID, state liveMigrationState) {
	f.updates = append(f.updates, liveMigrationStateUpdate{ID: id, State: state})
}

func (f *fakeLiveMigrationListener) drain() []liveMigrationStateUpdate {
	updates := f.updates
	f.updates = nil
	return updates
}

// newTestMonitor creates a liveMigrationMonitor with a no-op GARP handle factory
// and a fake listener, preventing tests from opening real AF_PACKET sockets.
func newTestMonitor(convergenceTime time.Duration) *liveMigrationMonitor {
	m := newLiveMigrationMonitor(convergenceTime, &fakeIPAM{})
	m.newGARPHandle = func(ifaceName string) (garpHandle, error) {
		return newFakeGARPHandle(), nil
	}
	m.registerListener(&fakeLiveMigrationListener{})
	return m
}

// testListener returns the fake listener from a test monitor.
func testListener(m *liveMigrationMonitor) *fakeLiveMigrationListener {
	return m.listeners[0].(*fakeLiveMigrationListener)
}

// drainUpdates resolves the current batch and returns the updates delivered to
// the fake listener.  This replaces the old PendingUpdates() method in tests.
func drainUpdates(m *liveMigrationMonitor) []liveMigrationStateUpdate {
	_ = m.ResolveUpdateBatch()
	return testListener(m).drain()
}

// testFSM creates a liveMigrationFSM in the given state, wired to a monitor for
// pendingUpdates capture.
func testFSM(state liveMigrationState) (*liveMigrationFSM, *liveMigrationMonitor) {
	m := newTestMonitor(testConvergenceTime)
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
			Name:              "cali" + id.EndpointId,
			LiveMigrationRole: role,
		},
	}
}

func wepUpdateWithUID(id types.WorkloadEndpointID, role proto.LiveMigrationRole, uid string) *proto.WorkloadEndpointUpdate {
	return &proto.WorkloadEndpointUpdate{
		Id: protoWEPID(id),
		Endpoint: &proto.WorkloadEndpoint{
			Name:              "cali" + id.EndpointId,
			LiveMigrationRole: role,
			LiveMigrationUid:  uid,
		},
	}
}

func wepUpdateWithVMIName(id types.WorkloadEndpointID, role proto.LiveMigrationRole, uid, vmiName string) *proto.WorkloadEndpointUpdate {
	return &proto.WorkloadEndpointUpdate{
		Id: protoWEPID(id),
		Endpoint: &proto.WorkloadEndpoint{
			Name:                 "cali" + id.EndpointId,
			LiveMigrationRole:    role,
			LiveMigrationUid:     uid,
			LiveMigrationVmiName: vmiName,
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
			g := NewWithT(t)
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
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))

		updates := drainUpdates(m)
		g.Expect(updates).To(HaveLen(1))
		g.Expect(updates[0].State).To(Equal(liveMigrationStateTarget))
		g.Expect(updates[0].ID).To(Equal(wepID1))
	})

	t.Run("role change TARGET→NO_ROLE drives NoRole input", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		drainUpdates(m) // drain

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
		updates := drainUpdates(m)
		g.Expect(updates).To(HaveLen(1))
		// Target + NoRole → TimeWait
		g.Expect(updates[0].State).To(Equal(liveMigrationStateTimeWait))
	})

	t.Run("role change TARGET→SOURCE drives Source input", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		drainUpdates(m)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_SOURCE))
		updates := drainUpdates(m)
		g.Expect(updates).To(HaveLen(1))
		// Target + Source → Base
		g.Expect(updates[0].State).To(Equal(liveMigrationStateBase))
	})

	t.Run("same role repeated is no-op", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		drainUpdates(m)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(drainUpdates(m)).To(BeEmpty())
	})

	t.Run("unrelated message type is ignored", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(&proto.HostEndpointUpdate{})
		g.Expect(m.fsms).To(BeEmpty())
	})

	t.Run("WorkloadEndpointRemove drives Deleted input", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		drainUpdates(m)

		m.OnUpdate(wepRemove(wepID1))
		updates := drainUpdates(m)
		g.Expect(updates).To(HaveLen(1))
		// Target + Deleted → Base
		g.Expect(updates[0].State).To(Equal(liveMigrationStateBase))
		// Role and iface name should be cleaned up.
		g.Expect(m.roles).NotTo(HaveKey(wepID1))
		g.Expect(m.ifaceNames).NotTo(HaveKey(wepID1))
	})

	t.Run("WorkloadEndpointRemove for unknown WEP is safe", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
		// Should not panic; FSM is created at Base, gets Deleted (no-op), cleaned up.
		m.OnUpdate(wepRemove(wepID1))
		g.Expect(drainUpdates(m)).To(BeEmpty())
		g.Expect(m.fsms).To(BeEmpty())
	})

	t.Run("OnUpdate stores interface name", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(m.ifaceNames[wepID1]).To(Equal("cali" + wepID1.EndpointId))
	})
}

func TestMonitorMultipleListeners(t *testing.T) {
	t.Run("state changes are forwarded to every registered listener", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		// In production the monitor has one listener per IP version; a second
		// listener here stands in for the IPv6 endpoint manager.
		second := &fakeLiveMigrationListener{}
		m.registerListener(second)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(m.ResolveUpdateBatch()).NotTo(HaveOccurred())

		expected := []liveMigrationStateUpdate{{ID: wepID1, State: liveMigrationStateTarget}}
		g.Expect(testListener(m).drain()).To(Equal(expected))
		g.Expect(second.drain()).To(Equal(expected))
	})
}

// --- Section 3: FSM lifecycle management ---

func TestFSMLifecycle(t *testing.T) {
	t.Run("FSM created on first input and cleaned up on return to Base", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(m.fsms).To(HaveLen(1))

		// Drive back to Base: Target + Source → Base.
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_SOURCE))
		g.Expect(m.fsms).To(BeEmpty())
	})

	t.Run("multiple inputs to same ID reuse FSM", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		drainUpdates(m)

		m.OnGARPDetected(wepID1)
		g.Expect(m.fsms).To(HaveLen(1))
		updates := drainUpdates(m)
		g.Expect(updates).To(HaveLen(1))
		g.Expect(updates[0].State).To(Equal(liveMigrationStateLive))
	})

	t.Run("ResolveUpdateBatch drains and clears buffer", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))

		g.Expect(drainUpdates(m)).To(HaveLen(1))
		g.Expect(drainUpdates(m)).To(BeEmpty())
	})

	t.Run("stopGARPDetection closes handle when leaving Target", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		// Override so we can hold a reference to verify closure.
		fakeHandle := newFakeGARPHandle()
		m.newGARPHandle = func(ifaceName string) (garpHandle, error) {
			return fakeHandle, nil
		}

		// Drive to Target (starts detection).
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		drainUpdates(m)

		// Drive to Base via Source input (calls stopGARPDetection).
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_SOURCE))
		drainUpdates(m)

		// Verify the handle was closed and goroutine exited.
		g.Eventually(fakeHandle.IsClosed, 2*time.Second, 10*time.Millisecond).Should(BeTrue())

		// No GARP should be delivered.
		select {
		case <-m.garpC:
			t.Fatal("unexpected GARP detection after stop")
		case <-time.After(100 * time.Millisecond):
			// Expected.
		}
	})

	t.Run("empty interface name skips GARP detection", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		handleCreated := false
		m.newGARPHandle = func(ifaceName string) (garpHandle, error) {
			handleCreated = true
			return newFakeGARPHandle(), nil
		}

		// Send update with empty interface name.
		m.OnUpdate(&proto.WorkloadEndpointUpdate{
			Id: protoWEPID(wepID1),
			Endpoint: &proto.WorkloadEndpoint{
				LiveMigrationRole: proto.LiveMigrationRole_TARGET,
			},
		})
		drainUpdates(m)

		// startGARPDetection should skip because ifaceName is empty.
		g.Expect(handleCreated).To(BeFalse())
		g.Expect(m.fsms[wepID1].currentState).To(Equal(liveMigrationStateTarget))
	})
}

// --- Section 4: Multi-step scenarios ---

func TestLiveMigrationScenarios(t *testing.T) {
	t.Run("missed GARP path: TARGET → NO_ROLE", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		expectUpdate(g, m, liveMigrationStateTarget)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
		expectUpdate(g, m, liveMigrationStateTimeWait)
	})

	t.Run("happy path with GARP: TARGET → GARP → NO_ROLE", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		expectUpdate(g, m, liveMigrationStateTarget)

		m.OnGARPDetected(wepID1)
		expectUpdate(g, m, liveMigrationStateLive)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
		expectUpdate(g, m, liveMigrationStateTimeWait)
	})

	t.Run("re-migration: TARGET → SOURCE", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		expectUpdate(g, m, liveMigrationStateTarget)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_SOURCE))
		expectUpdate(g, m, liveMigrationStateBase)
	})

	t.Run("delete during migration: TARGET → Remove", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		expectUpdate(g, m, liveMigrationStateTarget)

		m.OnUpdate(wepRemove(wepID1))
		expectUpdate(g, m, liveMigrationStateBase)
	})

	t.Run("two independent WEPs", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		m.OnUpdate(wepUpdate(wepID2, proto.LiveMigrationRole_TARGET))
		updates := drainUpdates(m)
		g.Expect(updates).To(HaveLen(2))
		g.Expect(updates[0]).To(Equal(liveMigrationStateUpdate{ID: wepID1, State: liveMigrationStateTarget}))
		g.Expect(updates[1]).To(Equal(liveMigrationStateUpdate{ID: wepID2, State: liveMigrationStateTarget}))

		// Drive WEP1 to Live via GARP, WEP2 stays in Target.
		m.OnGARPDetected(wepID1)
		updates = drainUpdates(m)
		g.Expect(updates).To(HaveLen(1))
		g.Expect(updates[0]).To(Equal(liveMigrationStateUpdate{ID: wepID1, State: liveMigrationStateLive}))
		// WEP2 FSM should still exist in Target.
		g.Expect(m.fsms).To(HaveKey(wepID2))
		g.Expect(m.fsms[wepID2].currentState).To(Equal(liveMigrationStateTarget))
	})

	t.Run("idempotent role update", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		drainUpdates(m)

		// Same role again.
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(drainUpdates(m)).To(BeEmpty())
	})

	t.Run("full lifecycle: TARGET → GARP → NO_ROLE → TimerPop", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		expectUpdate(g, m, liveMigrationStateTarget)

		m.OnGARPDetected(wepID1)
		expectUpdate(g, m, liveMigrationStateLive)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
		expectUpdate(g, m, liveMigrationStateTimeWait)

		m.OnTimerPop(wepID1)
		expectUpdate(g, m, liveMigrationStateBase)

		// FSM should be cleaned up.
		g.Expect(m.fsms).To(BeEmpty())
	})
}

// --- Section 5: Async channel delivery (timer and GARP) ---

func TestLiveMigrationTimer(t *testing.T) {
	t.Run("timer fires and delivers workload ID to channel", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(50 * time.Millisecond)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		drainUpdates(m) // drain

		// Drive to TimeWait via NoRole (starts the timer).
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
		drainUpdates(m) // drain

		// Wait for timer to fire and deliver the ID.
		select {
		case id := <-m.timerC:
			g.Expect(id).To(Equal(wepID1))
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for timer channel delivery")
		}

		// Simulate main loop calling OnTimerPop.
		m.OnTimerPop(wepID1)
		updates := drainUpdates(m)
		g.Expect(updates).To(HaveLen(1))
		g.Expect(updates[0].State).To(Equal(liveMigrationStateBase))
		g.Expect(m.fsms).To(BeEmpty())
	})

	t.Run("stopElevatedRoutingTimer prevents channel delivery", func(t *testing.T) {
		m := newTestMonitor(500 * time.Millisecond)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		drainUpdates(m)

		// Drive to TimeWait (starts timer).
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
		drainUpdates(m)

		// Now drive to Base via Source (stops timer).
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_SOURCE))
		drainUpdates(m)

		// Timer should not fire.
		select {
		case <-m.timerC:
			t.Fatal("timer should not have fired after stop")
		case <-time.After(700 * time.Millisecond):
			// Expected: no delivery.
		}
	})
}

func TestLiveMigrationGARPChannel(t *testing.T) {
	t.Run("GARP detection delivers workload ID to channel", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		garpBytes := buildGARPPacketBytes(t)
		fakeHandle := newFakeGARPHandle(garpBytes)
		m.newGARPHandle = func(ifaceName string) (garpHandle, error) {
			return fakeHandle, nil
		}

		// Drive to Target state (triggers startGARPDetection).
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		expectUpdate(g, m, liveMigrationStateTarget)

		// Wait for the detection goroutine to deliver the workload ID.
		select {
		case id := <-m.garpC:
			g.Expect(id).To(Equal(wepID1))
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for GARP detection")
		}

		// Simulate main loop calling OnGARPDetected.
		m.OnGARPDetected(wepID1)
		updates := drainUpdates(m)
		g.Expect(updates).To(HaveLen(1))
		g.Expect(updates[0].State).To(Equal(liveMigrationStateLive))
	})
}

// senderParkedIn reports whether some goroutine whose stack mentions fnSubstring is currently
// parked in a channel send.  Lets the regression tests below wait deterministically for a sender to
// be blocked delivering to the monitor's (unbuffered, main-loop-read) channels.  The goroutine
// state is "select" for a select-based send (which can be aborted via a stop channel) and "chan
// send" for a plain send (the pre-fix code); we match both so a test observes the blocked sender
// either way and then proves whether the code under test can get past it.  The senders' only other
// park points - e.g. detectGARP waiting for a packet - show as "chan receive", so these two states
// are unambiguous.
func senderParkedIn(fnSubstring string) bool {
	// Grow the buffer until the full goroutine dump fits: runtime.Stack truncates (n ==
	// len(buf)) when the buffer is too small, which could hide the target goroutine and time
	// out the caller's Eventually.
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	for n == len(buf) {
		buf = make([]byte, 2*len(buf))
		n = runtime.Stack(buf, true)
	}
	for _, gr := range strings.Split(string(buf[:n]), "\n\n") {
		if !strings.Contains(gr, fnSubstring) {
			continue
		}
		if strings.Contains(gr, "[select]") || strings.Contains(gr, "[chan send]") {
			return true
		}
	}
	return false
}

// garpSenderBlocked reports whether some goroutine is currently parked in detectGARP's
// report-detection send.
func garpSenderBlocked() bool {
	return senderParkedIn("detectGARP")
}

// timerSenderBlocked reports whether some elevated-routing-timer goroutine is currently parked
// in its select - either waiting for the timer to fire or sending its pop on timerC.
func timerSenderBlocked() bool {
	return senderParkedIn("startElevatedRoutingTimer")
}

// TestGARPRaceWithTargetExit is a regression test for a dataplane main-loop
// deadlock.  Scenario: the FSM is in Target with GARP detection running, and a
// GARP/RARP is detected on the workload interface just before the main loop
// processes an update that ends the Target state (e.g. the migration-complete
// update flipping the role TARGET -> NO_ROLE, which can arrive within the same
// scheduling window as the cutover RARP).  detectGARP is then blocked sending
// on the unbuffered garpC - whose only reader is the main loop - while the
// main loop is inside stopGARPDetection() waiting for detectGARP to exit.
// Neither can proceed, wedging the dataplane loop permanently.
//
// The test simulates the main loop by calling OnUpdate directly, with nothing
// reading garpC (just as the real main loop cannot read garpC while it is
// inside OnUpdate).  Without the garpStopC abort mechanism, OnUpdate would
// block forever and the test would fail by timeout.
func TestGARPRaceWithTargetExit(t *testing.T) {
	tests := []struct {
		name       string
		exitInput  func(m *liveMigrationMonitor)
		wantStates []liveMigrationState
	}{
		{
			name: "migration completes (NO_ROLE)",
			exitInput: func(m *liveMigrationMonitor) {
				m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
			},
			wantStates: []liveMigrationState{liveMigrationStateTimeWait},
		},
		{
			name: "re-migration (SOURCE)",
			exitInput: func(m *liveMigrationMonitor) {
				m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_SOURCE))
			},
			wantStates: []liveMigrationState{liveMigrationStateBase},
		},
		{
			name: "workload removed",
			exitInput: func(m *liveMigrationMonitor) {
				m.OnUpdate(wepRemove(wepID1))
			},
			wantStates: []liveMigrationState{liveMigrationStateBase},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			m := newTestMonitor(testConvergenceTime)

			garpBytes := buildGARPPacketBytes(t)
			fakeHandle := newFakeGARPHandle(garpBytes)
			m.newGARPHandle = func(ifaceName string) (garpHandle, error) {
				return fakeHandle, nil
			}

			// Drive to Target; GARP detection starts and the fake handle
			// delivers a GARP immediately, so detectGARP commits to the
			// (blocking) garpC send.
			m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
			expectUpdate(g, m, liveMigrationStateTarget)

			// Wait until detectGARP is parked in the garpC send.  This pins
			// the test to the exact interleaving from the field report - the
			// sender already blocked when the Target-exit update is processed
			// - which would also catch a broken variant of the fix that
			// checks the stop channel before a plain send instead of
			// selecting over both.
			g.Eventually(garpSenderBlocked, time.Second, time.Millisecond).Should(BeTrue())

			// Process the Target-exiting update as the main loop would, with
			// nothing reading garpC.  Run it in a goroutine purely so that a
			// regression fails the test by timeout instead of hanging the
			// whole test binary.
			done := make(chan struct{})
			go func() {
				defer close(done)
				tt.exitInput(m)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("deadlock: OnUpdate blocked in stopGARPDetection while detectGARP blocked sending on garpC")
			}

			updates := drainUpdates(m)
			g.Expect(updates).To(HaveLen(len(tt.wantStates)))
			for i, want := range tt.wantStates {
				g.Expect(updates[i].State).To(Equal(want))
			}

			// The aborted detection must not deliver a stale GARP.
			select {
			case <-m.garpC:
				t.Fatal("unexpected GARP delivery after GARP detection was stopped")
			case <-time.After(100 * time.Millisecond):
				// Expected: no delivery.
			}
		})
	}
}

// TestTimerPopRaceWithTimeWaitExit is a regression test for stale timer-pop misattribution.
// Scenario: the FSM is in TimeWait and its elevated-routing timer fires while the main loop is
// busy, so the pop parks on the unbuffered timerC.  Before the main loop drains it, the same batch
// re-migrates the workload: a SOURCE update exits TimeWait (discarding the FSM) and a subsequent
// TARGET -> NO_ROLE sequence enters TimeWait again with a fresh timer.  When the parked episode-1
// pop is finally drained, OnTimerPop's state check ("FSM exists and is in TimeWait") cannot tell it
// from a genuine pop for the new episode, so it would cut the new TimeWait short - reverting the
// workload's route to normal priority before routing has converged.
//
// stopElevatedRoutingTimer must therefore abort a parked pop via the timer's stop channel when
// TimeWait is exited, so a stale pop can never be delivered.  The test simulates the main loop by
// calling OnUpdate directly, with nothing reading timerC (just as the real main loop cannot read
// timerC while it is processing a batch).
func TestTimerPopRaceWithTimeWaitExit(t *testing.T) {
	g := NewWithT(t)
	// Short convergence so episode 1's timer fires promptly.
	m := newTestMonitor(10 * time.Millisecond)

	// Episode 1: drive to TimeWait via the missed-GARP path; the timer fires
	// and its pop parks on timerC.  The timer goroutine parks in a select both
	// before and after the timer fires, so also wait out several convergence
	// times to make it overwhelmingly likely the fired-pop-parked-in-send
	// interleaving from the field scenario is the one we exercise; the exit
	// path below must reap the goroutine in either interleaving regardless.
	start := time.Now()
	m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
	drainUpdates(m)
	m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
	drainUpdates(m)
	g.Eventually(func() bool {
		return time.Since(start) > 50*time.Millisecond && timerSenderBlocked()
	}, time.Second, time.Millisecond).Should(BeTrue())

	// Hold a reference to the episode-1 FSM: the TimeWait exit below discards it
	// from the monitor's map, but we need it to verify its goroutine is reaped.
	fsm1 := m.fsms[wepID1]
	g.Expect(fsm1).NotTo(BeNil())

	// Exit TimeWait while the pop is parked, as the main loop would when processing a
	// re-migration batch.  This must abort the parked pop.
	m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_SOURCE))
	drainUpdates(m)

	// stopElevatedRoutingTimer waits for the timer goroutine to exit before returning, so by
	// the time the exit update has been processed the goroutine must already be gone -
	// synchronously, not eventually.  Verify via the FSM's own WaitGroup (a global stack scan
	// would be polluted by TimeWait timer goroutines leaked by other tests in this package).
	reaped := make(chan struct{})
	go func() {
		fsm1.timerWG.Wait()
		close(reaped)
	}()
	select {
	case <-reaped:
	case <-time.After(time.Second):
		t.Fatal("timer goroutine still running after the TimeWait-exiting update returned")
	}
	g.Expect(fsm1.timerStopC).To(BeNil(), "stopElevatedRoutingTimer should have cleared timerStopC")

	// Episode 2: re-enter TimeWait with a convergence time long enough that its own timer
	// cannot fire during the test, so any pop delivered below can only be the stale one from
	// episode 1.
	m.convergenceTime = time.Hour
	m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
	drainUpdates(m)
	m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
	drainUpdates(m)
	g.Expect(m.fsms[wepID1].currentState).To(Equal(liveMigrationStateTimeWait))

	// Drain timerC as the main loop would.  The stale episode-1 pop must not arrive; if it did,
	// OnTimerPop would misattribute it to episode 2 and end its TimeWait prematurely.
	select {
	case id := <-m.timerC:
		m.OnTimerPop(id)
		t.Fatalf("stale timer pop delivered and misattributed; FSM state now %v",
			m.fsms[wepID1])
	case <-time.After(200 * time.Millisecond):
		// Expected: no delivery.
	}
	g.Expect(m.fsms[wepID1].currentState).To(Equal(liveMigrationStateTimeWait))

	// Reap episode 2's timer goroutine rather than leak it into the rest of the
	// test binary.
	m.OnUpdate(wepRemove(wepID1))
}

// --- Section 6: GARP/RARP packet matching ---

func TestIsGARPOrRARP(t *testing.T) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	t.Run("RARP packet returns true", func(t *testing.T) {
		g := NewWithT(t)
		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetType(0x8035),
		}
		buf := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth)
		g.Expect(err).NotTo(HaveOccurred())
		pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		g.Expect(isGARPOrRARP(pkt)).To(BeTrue())
	})

	t.Run("gratuitous ARP (sender IP == target IP) returns true", func(t *testing.T) {
		g := NewWithT(t)
		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeARP,
		}
		arp := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   srcMAC,
			SourceProtAddress: net.IP{10, 0, 0, 1},
			DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
			DstProtAddress:    net.IP{10, 0, 0, 1}, // same as source = gratuitous
		}
		pkt := serializePacket(t, eth, arp)
		g.Expect(isGARPOrRARP(pkt)).To(BeTrue())
	})

	t.Run("normal ARP (sender IP != target IP) returns false", func(t *testing.T) {
		g := NewWithT(t)
		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeARP,
		}
		arp := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   srcMAC,
			SourceProtAddress: net.IP{10, 0, 0, 1},
			DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
			DstProtAddress:    net.IP{10, 0, 0, 2}, // different from source
		}
		pkt := serializePacket(t, eth, arp)
		g.Expect(isGARPOrRARP(pkt)).To(BeFalse())
	})

	t.Run("non-ARP packet returns false", func(t *testing.T) {
		g := NewWithT(t)
		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			SrcIP: net.IP{10, 0, 0, 1},
			DstIP: net.IP{10, 0, 0, 2},
		}
		pkt := serializePacket(t, eth, ip)
		g.Expect(isGARPOrRARP(pkt)).To(BeFalse())
	})
}

// --- Test helpers ---

// expectUpdate drains pending updates and checks that exactly one update was emitted with
// the given state.
func expectUpdate(g Gomega, m *liveMigrationMonitor, expectedState liveMigrationState) {
	updates := drainUpdates(m)
	g.Expect(updates).To(HaveLen(1), "expected exactly one pending update")
	g.Expect(updates[0].State).To(Equal(expectedState))
}

// serializePacket serializes gopacket layers into a gopacket.Packet.
func serializePacket(t *testing.T, packetLayers ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, packetLayers...)
	if err != nil {
		t.Fatalf("Failed to serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// buildGARPPacketBytes builds a serialized gratuitous ARP packet.
func buildGARPPacketBytes(t *testing.T) []byte {
	t.Helper()
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   srcMAC,
			SourceProtAddress: net.IP{10, 0, 0, 1},
			DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
			DstProtAddress:    net.IP{10, 0, 0, 1},
		},
	)
	if err != nil {
		t.Fatalf("Failed to build GARP packet: %v", err)
	}
	return buf.Bytes()
}

// fakeGARPHandle is a mock garpHandle for testing.
type fakeGARPHandle struct {
	mu       sync.Mutex
	packets  [][]byte // raw packet bytes to deliver
	closedCh chan struct{}
	closed   bool
	idx      int
}

func newFakeGARPHandle(packets ...[]byte) *fakeGARPHandle {
	return &fakeGARPHandle{
		packets:  packets,
		closedCh: make(chan struct{}),
	}
}

func (f *fakeGARPHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	f.mu.Lock()
	if f.idx < len(f.packets) {
		data := f.packets[f.idx]
		f.idx++
		f.mu.Unlock()
		return data, gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}, nil
	}
	f.mu.Unlock()
	// Block until closed.
	<-f.closedCh
	return nil, gopacket.CaptureInfo{}, io.EOF
}

func (f *fakeGARPHandle) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.closedCh)
	}
	return nil
}

func (f *fakeGARPHandle) IsClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// --- Section 7: Migration UID tracking ---

func TestMigrationUIDTracking(t *testing.T) {
	t.Run("UID stored from WEP update and set on FSM", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdateWithUID(wepID1, proto.LiveMigrationRole_TARGET, "uid-abc-123"))

		g.Expect(m.migrationUIDs[wepID1]).To(Equal("uid-abc-123"))
		g.Expect(m.fsms[wepID1].migrationUID).To(Equal("uid-abc-123"))
	})

	t.Run("UID cleaned up on WEP remove", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdateWithUID(wepID1, proto.LiveMigrationRole_TARGET, "uid-abc-123"))
		g.Expect(m.migrationUIDs).To(HaveKey(wepID1))

		m.OnUpdate(wepRemove(wepID1))
		g.Expect(m.migrationUIDs).NotTo(HaveKey(wepID1))
	})

	t.Run("empty UID is not stored", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(m.migrationUIDs).NotTo(HaveKey(wepID1))
	})

	t.Run("UID preserved through FSM state transitions", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdateWithUID(wepID1, proto.LiveMigrationRole_TARGET, "uid-xyz-789"))
		drainUpdates(m)

		// GARP detected → Live
		m.OnGARPDetected(wepID1)
		g.Expect(m.fsms[wepID1].migrationUID).To(Equal("uid-xyz-789"))

		// NoRole → TimeWait
		m.OnUpdate(wepUpdateWithUID(wepID1, proto.LiveMigrationRole_NO_ROLE, "uid-xyz-789"))
		g.Expect(m.fsms[wepID1].migrationUID).To(Equal("uid-xyz-789"))
	})
}

func TestVMINameTracking(t *testing.T) {
	t.Run("VMI name stored from WEP update", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdateWithVMIName(wepID1, proto.LiveMigrationRole_TARGET, "uid-1", "my-vmi"))
		g.Expect(m.vmiNames[wepID1]).To(Equal("my-vmi"))
	})

	t.Run("VMI name cleaned up on WEP remove", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdateWithVMIName(wepID1, proto.LiveMigrationRole_TARGET, "uid-1", "my-vmi"))
		g.Expect(m.vmiNames).To(HaveKey(wepID1))

		m.OnUpdate(wepRemove(wepID1))
		g.Expect(m.vmiNames).NotTo(HaveKey(wepID1))
	})

	t.Run("empty VMI name is not stored", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(m.vmiNames).NotTo(HaveKey(wepID1))
	})
}

// fakeVMOwners models the IPAM owners of one VM handle, with the semantics of the vmipam
// promotion functions.
type fakeVMOwners struct {
	lock         sync.Mutex
	active       string
	alternate    string
	noHandle     bool
	failures     int
	ensureCalls  int
	promoteCalls int
}

func (f *fakeVMOwners) ensure(_ context.Context, _ ipam.Interface, _, _, _, pod string) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.ensureCalls++
	return f.promoteLocked(pod, false)
}

func (f *fakeVMOwners) promoteIfActiveEmpty(_ context.Context, _ ipam.Interface, _, _, _, pod string) (bool, error) {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.promoteCalls++
	before := f.active
	err := f.promoteLocked(pod, true)
	return f.active != before, err
}

func (f *fakeVMOwners) promoteLocked(pod string, requireActiveEmpty bool) error {
	switch {
	case f.noHandle:
		return vmipam.ErrNoVMAddresses
	case f.failures > 0:
		f.failures--
		return errors.New("transient datastore error")
	case f.active == pod:
		return nil
	case f.alternate == "":
		return vmipam.ErrAlternateOwnerEmpty
	case f.alternate != pod:
		return vmipam.ErrAlternateOwnerMismatch
	case f.active != "" && requireActiveEmpty:
		return vmipam.ErrActiveOwnerPresent
	}
	f.active, f.alternate = pod, f.active
	return nil
}

func (f *fakeVMOwners) set(active, alternate string) {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.active, f.alternate = active, alternate
}

func (f *fakeVMOwners) owners() [2]string {
	f.lock.Lock()
	defer f.lock.Unlock()
	return [2]string{f.active, f.alternate}
}

func (f *fakeVMOwners) calls() (ensure, promote int) {
	f.lock.Lock()
	defer f.lock.Unlock()
	return f.ensureCalls, f.promoteCalls
}

func newVMOwnerTestMonitor(owners *fakeVMOwners) *liveMigrationMonitor {
	m := newTestMonitor(testConvergenceTime)
	m.vmOwners.ensureActiveVMOwnerAttrs = owners.ensure
	m.vmOwners.promoteIfActiveEmpty = owners.promoteIfActiveEmpty
	m.vmOwners.initialBackoff = 5 * time.Millisecond
	m.vmOwners.maxBackoff = 20 * time.Millisecond
	return m
}

var vmPodID = types.WorkloadEndpointID{
	OrchestratorId: "k8s",
	WorkloadId:     "test-ns/virt-launcher-vm1-tgt",
	EndpointId:     "eth0",
}

// sendVMPodUpdate delivers a WEP update for vmPodID as one dataplane batch.
func sendVMPodUpdate(m *liveMigrationMonitor, role proto.LiveMigrationRole) {
	m.OnUpdate(wepUpdateWithVMIName(vmPodID, role, "", "vm1"))
	drainUpdates(m)
	Expect(m.CompleteDeferredWork()).To(Succeed())
}

func TestVMOwnerReconciler(t *testing.T) {
	const tgt = "virt-launcher-vm1-tgt"
	const src = "virt-launcher-vm1-src"

	t.Run("promotes a VM pod left as the only claimant, with no FSM", func(t *testing.T) {
		// Felix on the target restarted while the migration completed, and the source's CNI
		// DEL has cleared the active owner.
		RegisterTestingT(t)
		owners := &fakeVMOwners{alternate: tgt}
		m := newVMOwnerTestMonitor(owners)

		sendVMPodUpdate(m, proto.LiveMigrationRole_NO_ROLE)

		Eventually(owners.owners).Should(Equal([2]string{tgt, ""}))
		Expect(m.fsms).To(BeEmpty())
	})

	t.Run("waits for the source's CNI DEL before promoting", func(t *testing.T) {
		RegisterTestingT(t)
		owners := &fakeVMOwners{active: src, alternate: tgt}
		m := newVMOwnerTestMonitor(owners)

		sendVMPodUpdate(m, proto.LiveMigrationRole_NO_ROLE)
		Consistently(owners.owners, "100ms").Should(Equal([2]string{src, tgt}))

		owners.set("", tgt)
		Eventually(owners.owners).Should(Equal([2]string{tgt, ""}))
	})

	t.Run("does not promote a migration target", func(t *testing.T) {
		RegisterTestingT(t)
		owners := &fakeVMOwners{alternate: tgt}
		m := newVMOwnerTestMonitor(owners)

		sendVMPodUpdate(m, proto.LiveMigrationRole_TARGET)

		Consistently(owners.owners, "100ms").Should(Equal([2]string{"", tgt}))
		ensure, promote := owners.calls()
		Expect(ensure).To(BeZero())
		Expect(promote).To(BeZero())
	})

	t.Run("leaves the source active when a migration is cancelled", func(t *testing.T) {
		// Cancelling the migration deletes the LiveMigration, so the FSM goes Target ->
		// TimeWait just as for a completion with a missed GARP.
		RegisterTestingT(t)
		owners := &fakeVMOwners{active: src, alternate: tgt}
		m := newVMOwnerTestMonitor(owners)

		sendVMPodUpdate(m, proto.LiveMigrationRole_TARGET)
		sendVMPodUpdate(m, proto.LiveMigrationRole_NO_ROLE)
		Expect(m.fsms[vmPodID].currentState).To(Equal(liveMigrationStateTimeWait))

		Consistently(owners.owners, "100ms").Should(Equal([2]string{src, tgt}))
		ensure, _ := owners.calls()
		Expect(ensure).To(BeZero())

		// The target pod's CNI DEL clears it, and its WEP goes.
		owners.set(src, "")
		m.OnUpdate(wepRemove(vmPodID))
		drainUpdates(m)
		Expect(m.CompleteDeferredWork()).To(Succeed())
		Expect(owners.owners()).To(Equal([2]string{src, ""}))
	})

	t.Run("promotes straight away when the GARP is detected", func(t *testing.T) {
		RegisterTestingT(t)
		owners := &fakeVMOwners{active: src, alternate: tgt}
		m := newVMOwnerTestMonitor(owners)

		sendVMPodUpdate(m, proto.LiveMigrationRole_TARGET)
		m.OnGARPDetected(vmPodID)
		drainUpdates(m)

		Eventually(owners.owners).Should(Equal([2]string{tgt, src}))
	})

	t.Run("keeps retrying a promotion after transient errors", func(t *testing.T) {
		RegisterTestingT(t)
		owners := &fakeVMOwners{active: src, alternate: tgt, failures: 8}
		m := newVMOwnerTestMonitor(owners)

		sendVMPodUpdate(m, proto.LiveMigrationRole_TARGET)
		m.OnGARPDetected(vmPodID)
		drainUpdates(m)

		Eventually(owners.owners).Should(Equal([2]string{tgt, src}))
		ensure, _ := owners.calls()
		Expect(ensure).To(Equal(9))
	})

	t.Run("checks a VM without address persistence only once", func(t *testing.T) {
		RegisterTestingT(t)
		owners := &fakeVMOwners{noHandle: true}
		m := newVMOwnerTestMonitor(owners)

		sendVMPodUpdate(m, proto.LiveMigrationRole_NO_ROLE)

		Eventually(func() int { _, p := owners.calls(); return p }).Should(Equal(1))
		Consistently(func() int { _, p := owners.calls(); return p }, "100ms").Should(Equal(1))
	})

	t.Run("ignores workloads that are not VM pods", func(t *testing.T) {
		RegisterTestingT(t)
		owners := &fakeVMOwners{alternate: tgt}
		m := newVMOwnerTestMonitor(owners)

		m.OnUpdate(wepUpdateWithUID(vmPodID, proto.LiveMigrationRole_TARGET, "uid-1"))
		drainUpdates(m)
		m.OnGARPDetected(vmPodID)
		m.OnUpdate(wepUpdate(vmPodID, proto.LiveMigrationRole_NO_ROLE))
		drainUpdates(m)
		Expect(m.CompleteDeferredWork()).To(Succeed())

		Consistently(owners.calls, "100ms").Should(BeZero())
	})
}

func TestLiveMigrationStateString(t *testing.T) {
	g := NewWithT(t)
	g.Expect(liveMigrationStateBase.String()).To(Equal("Base"))
	g.Expect(liveMigrationStateTarget.String()).To(Equal("Target"))
	g.Expect(liveMigrationStateLive.String()).To(Equal("Live"))
	g.Expect(liveMigrationStateTimeWait.String()).To(Equal("TimeWait"))
	g.Expect(liveMigrationState(99).String()).To(Equal("Unknown(99)"))
}

func TestLiveMigrationInputString(t *testing.T) {
	g := NewWithT(t)
	g.Expect(liveMigrationInputNoRole.String()).To(Equal("NoRole"))
	g.Expect(liveMigrationInputSource.String()).To(Equal("Source"))
	g.Expect(liveMigrationInputTarget.String()).To(Equal("Target"))
	g.Expect(liveMigrationInputGARPDetected.String()).To(Equal("GARPDetected"))
	g.Expect(liveMigrationInputTimerPop.String()).To(Equal("TimerPop"))
	g.Expect(liveMigrationInputDeleted.String()).To(Equal("Deleted"))
	g.Expect(liveMigrationInput(99).String()).To(Equal("Unknown(99)"))
}

type fakeIPAM struct{}

func (i *fakeIPAM) AssignIP(ctx context.Context, args ipam.AssignIPArgs) error { return nil }
func (i *fakeIPAM) AutoAssign(ctx context.Context, args ipam.AutoAssignArgs) (*ipam.IPAMAssignments, *ipam.IPAMAssignments, error) {
	return nil, nil, nil
}
func (i *fakeIPAM) ReleaseIPs(ctx context.Context, ips ...ipam.ReleaseOptions) ([]cnet.IP, []ipam.ReleaseOptions, error) {
	return nil, nil, nil
}
func (i *fakeIPAM) GetAssignmentAttributes(ctx context.Context, addr cnet.IP) (*model.AllocationAttribute, error) {
	return nil, nil
}
func (i *fakeIPAM) IPsByHandle(ctx context.Context, handleID string) ([]cnet.IP, error) {
	return nil, nil
}
func (i *fakeIPAM) ReleaseByHandle(ctx context.Context, handleID string) error { return nil }
func (i *fakeIPAM) ClaimAffinity(ctx context.Context, cidr cnet.IPNet, affinityCfg ipam.AffinityConfig) ([]cnet.IPNet, []cnet.IPNet, error) {
	return nil, nil, nil
}
func (i *fakeIPAM) ReleaseAffinity(ctx context.Context, cidr cnet.IPNet, host string, mustBeEmpty bool) error {
	return nil
}
func (i *fakeIPAM) ReleaseHostAffinities(ctx context.Context, affinityCfg ipam.AffinityConfig, mustBeEmpty bool) error {
	return nil
}
func (i *fakeIPAM) ReleasePoolAffinities(ctx context.Context, pool cnet.IPNet) error { return nil }
func (i *fakeIPAM) ReleaseBlockAffinity(ctx context.Context, block *model.AllocationBlock, mustBeEmpty bool) error {
	return nil
}
func (i *fakeIPAM) GetIPAMConfig(ctx context.Context) (*ipam.IPAMConfig, error)  { return nil, nil }
func (i *fakeIPAM) SetIPAMConfig(ctx context.Context, cfg ipam.IPAMConfig) error { return nil }
func (i *fakeIPAM) RemoveIPAMHost(ctx context.Context, affinityCfg ipam.AffinityConfig) error {
	return nil
}
func (i *fakeIPAM) GetUtilization(ctx context.Context, args ipam.GetUtilizationArgs) ([]*ipam.PoolUtilization, error) {
	return nil, nil
}
func (i *fakeIPAM) EnsureBlock(ctx context.Context, args ipam.BlockArgs) (*cnet.IPNet, *cnet.IPNet, error) {
	return nil, nil, nil
}
func (i *fakeIPAM) UpgradeHost(ctx context.Context, nodeName string) error { return nil }
func (i *fakeIPAM) GarbageCollectColdIPs(_ context.Context, _ *ipam.IPAMConfig, _ *model.KVPair) error {
	return nil
}
func (i *fakeIPAM) SetOwnerAttributes(ctx context.Context, ip cnet.IP, handleID string, updates *ipam.OwnerAttributeUpdates, preconditions *ipam.OwnerAttributePreconditions) error {
	return nil
}

func (i *fakeIPAM) MoveIPToHandle(ctx context.Context, ip cnet.IP, opts ipam.MoveOptions) error {
	panic("MoveIPToHandle not expected on the live migration path")
}
