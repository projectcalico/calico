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
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

var testConvergenceTime = 30 * time.Second

// newTestMonitor creates a liveMigrationMonitor with a no-op GARP handle factory,
// preventing tests from opening real AF_PACKET sockets.
func newTestMonitor(convergenceTime time.Duration) *liveMigrationMonitor {
	m := newLiveMigrationMonitor(convergenceTime)
	m.newGARPHandle = func(ifaceName string) (garpHandle, error) {
		return newFakeGARPHandle(), nil
	}
	return m
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

		updates := m.PendingUpdates()
		g.Expect(updates).To(HaveLen(1))
		g.Expect(updates[0].State).To(Equal(liveMigrationStateTarget))
		g.Expect(updates[0].ID).To(Equal(wepID1))
	})

	t.Run("role change TARGET→NO_ROLE drives NoRole input", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
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
		m := newTestMonitor(testConvergenceTime)
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
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		m.PendingUpdates()

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(m.PendingUpdates()).To(BeEmpty())
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
		m.PendingUpdates()

		m.OnUpdate(wepRemove(wepID1))
		updates := m.PendingUpdates()
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
		g.Expect(m.PendingUpdates()).To(BeEmpty())
		g.Expect(m.fsms).To(BeEmpty())
	})

	t.Run("OnUpdate stores interface name", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(m.ifaceNames[wepID1]).To(Equal("cali" + wepID1.EndpointId))
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
		m.PendingUpdates()

		m.OnGARPDetected(wepID1)
		g.Expect(m.fsms).To(HaveLen(1))
		updates := m.PendingUpdates()
		g.Expect(updates).To(HaveLen(1))
		g.Expect(updates[0].State).To(Equal(liveMigrationStateLive))
	})

	t.Run("PendingUpdates drains and clears buffer", func(t *testing.T) {
		g := NewWithT(t)
		m := newTestMonitor(testConvergenceTime)
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))

		g.Expect(m.PendingUpdates()).To(HaveLen(1))
		g.Expect(m.PendingUpdates()).To(BeEmpty())
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
		m.PendingUpdates()

		// Drive to Base via Source input (calls stopGARPDetection).
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_SOURCE))
		m.PendingUpdates()

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
		m.PendingUpdates()

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
		updates := m.PendingUpdates()
		g.Expect(updates).To(HaveLen(2))
		g.Expect(updates[0]).To(Equal(liveMigrationStateUpdate{ID: wepID1, State: liveMigrationStateTarget}))
		g.Expect(updates[1]).To(Equal(liveMigrationStateUpdate{ID: wepID2, State: liveMigrationStateTarget}))

		// Drive WEP1 to Live via GARP, WEP2 stays in Target.
		m.OnGARPDetected(wepID1)
		updates = m.PendingUpdates()
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
		m.PendingUpdates()

		// Same role again.
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		g.Expect(m.PendingUpdates()).To(BeEmpty())
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
		m.PendingUpdates() // drain

		// Drive to TimeWait via NoRole (starts the timer).
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
		m.PendingUpdates() // drain

		// Wait for timer to fire and deliver the ID.
		select {
		case id := <-m.timerC:
			g.Expect(id).To(Equal(wepID1))
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for timer channel delivery")
		}

		// Simulate main loop calling OnTimerPop.
		m.OnTimerPop(wepID1)
		updates := m.PendingUpdates()
		g.Expect(updates).To(HaveLen(1))
		g.Expect(updates[0].State).To(Equal(liveMigrationStateBase))
		g.Expect(m.fsms).To(BeEmpty())
	})

	t.Run("stopElevatedRoutingTimer prevents channel delivery", func(t *testing.T) {
		m := newTestMonitor(500 * time.Millisecond)

		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_TARGET))
		m.PendingUpdates()

		// Drive to TimeWait (starts timer).
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_NO_ROLE))
		m.PendingUpdates()

		// Now drive to Base via Source (stops timer).
		m.OnUpdate(wepUpdate(wepID1, proto.LiveMigrationRole_SOURCE))
		m.PendingUpdates()

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
		updates := m.PendingUpdates()
		g.Expect(updates).To(HaveLen(1))
		g.Expect(updates[0].State).To(Equal(liveMigrationStateLive))
	})
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

// expectUpdate drains PendingUpdates and checks that exactly one update was emitted with
// the given state.
func expectUpdate(g Gomega, m *liveMigrationMonitor, expectedState liveMigrationState) {
	updates := m.PendingUpdates()
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
