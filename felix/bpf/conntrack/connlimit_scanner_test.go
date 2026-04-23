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

package conntrack

import (
	"net"
	"testing"
	"time"
)

// TestConnLimitScannerCheckNoPodsIsNoOp verifies that the scanner's Check
// method is a no-op when no pods have connection limits configured.
func TestConnLimitScannerCheckNoPodsIsNoOp(t *testing.T) {
	scanner := &ConnLimitScanner{
		counts: make(map[connlimitKey]uint32),
	}

	// Check should always return OK and never modify counts when no pod info
	verdict, _ := scanner.Check(nil, nil, nil)
	if verdict != ScanVerdictOK {
		t.Errorf("expected ScanVerdictOK, got %d", verdict)
	}
	if len(scanner.counts) != 0 {
		t.Errorf("expected empty counts, got %v", scanner.counts)
	}
}

// established creates a Leg with SYN+ACK seen (3-way handshake complete).
func established(opener bool) Leg {
	return Leg{SynSeen: true, AckSeen: true, Opener: opener}
}

// makeKey creates a TCP CT key for the given IPs and ports.
func makeKey(ipA, ipB string, portA, portB uint16) Key {
	return NewKey(6, net.ParseIP(ipA).To4(), portA, net.ParseIP(ipB).To4(), portB)
}

// makeEstablishedValue creates a NORMAL CT value with both legs established.
// legA is the opener (egress initiator).
func makeEstablishedValue() Value {
	return NewValueNormal(time.Duration(0), 0,
		established(true),  // A is opener
		established(false), // B is responder
	)
}

// makeEstablishedValueWithFIN creates an established value with a FIN on one leg.
func makeEstablishedValueWithFIN() Value {
	legA := established(true)
	legA.FinSeen = true
	return NewValueNormal(time.Duration(0), 0, legA, established(false))
}

// makeEstablishedValueWithRST creates an established value with RST seen.
func makeEstablishedValueWithRST() Value {
	legA := established(true)
	legA.RstSeen = true
	return NewValueNormal(time.Duration(0), 0, legA, established(false))
}

// makeSYNOnlyValue creates a value where only SYN was seen (not established).
func makeSYNOnlyValue() Value {
	return NewValueNormal(time.Duration(0), 0,
		Leg{SynSeen: true, Opener: true},
		Leg{},
	)
}

// makeNATForwardValue creates a NAT_FWD entry.
func makeNATForwardValue() Value {
	revKey := NewKey(6, net.ParseIP("10.0.0.1").To4(), 80, net.ParseIP("10.0.0.2").To4(), 1234)
	return NewValueNATForward(time.Duration(0), 0, revKey)
}

func podInfo(ifindex uint32, ingress, egress bool) ConnLimitPodInfo {
	return ConnLimitPodInfo{
		IfIndex:         ifindex,
		HasIngressLimit: ingress,
		HasEgressLimit:  egress,
	}
}

func TestConnLimitScannerCountsEstablishedTCP(t *testing.T) {
	podIP := "10.65.0.2"
	remoteIP := "10.65.1.3"

	scanner := &ConnLimitScanner{
		counts: make(map[connlimitKey]uint32),
		podInfo: map[string]ConnLimitPodInfo{
			string(net.ParseIP(podIP).To4()): podInfo(9, true, false),
		},
	}

	// Pod is AddrB (responder), remote is AddrA (opener).
	key := makeKey(remoteIP, podIP, 54321, 8080)
	val := makeEstablishedValue()

	verdict, _ := scanner.Check(key, val, nil)
	if verdict != ScanVerdictOK {
		t.Fatalf("expected ScanVerdictOK, got %d", verdict)
	}

	// Pod B is responder (A is opener), pod has ingress limit → ingress count.
	expected := connlimitKey{ifindex: 9, direction: 1}
	if scanner.counts[expected] != 1 {
		t.Errorf("expected ingress count 1 for ifindex 9, got counts: %v", scanner.counts)
	}
}

func TestConnLimitScannerCountsEgressConnection(t *testing.T) {
	podIP := "10.65.0.2"
	remoteIP := "10.65.1.3"

	scanner := &ConnLimitScanner{
		counts: make(map[connlimitKey]uint32),
		podInfo: map[string]ConnLimitPodInfo{
			string(net.ParseIP(podIP).To4()): podInfo(9, false, true),
		},
	}

	// Pod is AddrA (opener), remote is AddrB (responder).
	key := makeKey(podIP, remoteIP, 54321, 8080)
	val := makeEstablishedValue()

	verdict, _ := scanner.Check(key, val, nil)
	if verdict != ScanVerdictOK {
		t.Fatalf("expected ScanVerdictOK, got %d", verdict)
	}

	// Pod A is opener, pod has egress limit → egress count.
	expected := connlimitKey{ifindex: 9, direction: 0}
	if scanner.counts[expected] != 1 {
		t.Errorf("expected egress count 1 for ifindex 9, got counts: %v", scanner.counts)
	}
}

func TestConnLimitScannerSkipsFINSeen(t *testing.T) {
	podIP := "10.65.0.2"
	remoteIP := "10.65.1.3"

	scanner := &ConnLimitScanner{
		counts: make(map[connlimitKey]uint32),
		podInfo: map[string]ConnLimitPodInfo{
			string(net.ParseIP(podIP).To4()): podInfo(9, true, false),
		},
	}

	key := makeKey(remoteIP, podIP, 54321, 8080)
	val := makeEstablishedValueWithFIN()

	verdict, _ := scanner.Check(key, val, nil)
	if verdict != ScanVerdictOK {
		t.Fatalf("expected ScanVerdictOK, got %d", verdict)
	}
	if len(scanner.counts) != 0 {
		t.Errorf("expected no counts for FIN connection, got %v", scanner.counts)
	}
}

func TestConnLimitScannerSkipsRSTSeen(t *testing.T) {
	podIP := "10.65.0.2"
	remoteIP := "10.65.1.3"

	scanner := &ConnLimitScanner{
		counts: make(map[connlimitKey]uint32),
		podInfo: map[string]ConnLimitPodInfo{
			string(net.ParseIP(podIP).To4()): podInfo(9, true, false),
		},
	}

	key := makeKey(remoteIP, podIP, 54321, 8080)
	val := makeEstablishedValueWithRST()

	verdict, _ := scanner.Check(key, val, nil)
	if verdict != ScanVerdictOK {
		t.Fatalf("expected ScanVerdictOK, got %d", verdict)
	}
	if len(scanner.counts) != 0 {
		t.Errorf("expected no counts for RST connection, got %v", scanner.counts)
	}
}

func TestConnLimitScannerSkipsNotEstablished(t *testing.T) {
	podIP := "10.65.0.2"
	remoteIP := "10.65.1.3"

	scanner := &ConnLimitScanner{
		counts: make(map[connlimitKey]uint32),
		podInfo: map[string]ConnLimitPodInfo{
			string(net.ParseIP(podIP).To4()): podInfo(9, true, false),
		},
	}

	key := makeKey(remoteIP, podIP, 54321, 8080)
	val := makeSYNOnlyValue()

	verdict, _ := scanner.Check(key, val, nil)
	if verdict != ScanVerdictOK {
		t.Fatalf("expected ScanVerdictOK, got %d", verdict)
	}
	if len(scanner.counts) != 0 {
		t.Errorf("expected no counts for SYN-only connection, got %v", scanner.counts)
	}
}

func TestConnLimitScannerSkipsNATForward(t *testing.T) {
	podIP := "10.65.0.2"

	scanner := &ConnLimitScanner{
		counts: make(map[connlimitKey]uint32),
		podInfo: map[string]ConnLimitPodInfo{
			string(net.ParseIP(podIP).To4()): podInfo(9, true, false),
		},
	}

	key := makeKey("10.65.1.3", podIP, 54321, 8080)
	val := makeNATForwardValue()

	verdict, _ := scanner.Check(key, val, nil)
	if verdict != ScanVerdictOK {
		t.Fatalf("expected ScanVerdictOK, got %d", verdict)
	}
	if len(scanner.counts) != 0 {
		t.Errorf("expected no counts for NAT_FWD entry, got %v", scanner.counts)
	}
}

func TestConnLimitScannerSkipsNonTCP(t *testing.T) {
	podIP := "10.65.0.2"

	scanner := &ConnLimitScanner{
		counts: make(map[connlimitKey]uint32),
		podInfo: map[string]ConnLimitPodInfo{
			string(net.ParseIP(podIP).To4()): podInfo(9, true, false),
		},
	}

	// UDP (proto=17)
	key := NewKey(17, net.ParseIP("10.65.1.3").To4(), 54321, net.ParseIP(podIP).To4(), 8080)
	val := makeEstablishedValue()

	verdict, _ := scanner.Check(key, val, nil)
	if verdict != ScanVerdictOK {
		t.Fatalf("expected ScanVerdictOK, got %d", verdict)
	}
	if len(scanner.counts) != 0 {
		t.Errorf("expected no counts for UDP, got %v", scanner.counts)
	}
}

func TestConnLimitScannerSkipsUnlimitedPods(t *testing.T) {
	scanner := &ConnLimitScanner{
		counts: make(map[connlimitKey]uint32),
		podInfo: map[string]ConnLimitPodInfo{
			// Pod at 10.65.0.2 has limits, but the connection is between
			// two unlimited IPs.
			string(net.ParseIP("10.65.0.2").To4()): podInfo(9, true, false),
		},
	}

	key := makeKey("10.65.1.3", "10.65.1.4", 54321, 8080)
	val := makeEstablishedValue()

	verdict, _ := scanner.Check(key, val, nil)
	if verdict != ScanVerdictOK {
		t.Fatalf("expected ScanVerdictOK, got %d", verdict)
	}
	if len(scanner.counts) != 0 {
		t.Errorf("expected no counts for unlimited pods, got %v", scanner.counts)
	}
}

func TestConnLimitScannerMultipleConnections(t *testing.T) {
	podIP := "10.65.0.2"

	scanner := &ConnLimitScanner{
		counts: make(map[connlimitKey]uint32),
		podInfo: map[string]ConnLimitPodInfo{
			string(net.ParseIP(podIP).To4()): podInfo(9, true, true),
		},
	}

	// Two ingress connections (pod is responder = B, opener = A)
	scanner.Check(makeKey("10.65.1.3", podIP, 54321, 8080), makeEstablishedValue(), nil)
	scanner.Check(makeKey("10.65.1.4", podIP, 54322, 8080), makeEstablishedValue(), nil)

	// One egress connection (pod is opener = A)
	scanner.Check(makeKey(podIP, "10.65.1.5", 54323, 80), makeEstablishedValue(), nil)

	ingressKey := connlimitKey{ifindex: 9, direction: 1}
	egressKey := connlimitKey{ifindex: 9, direction: 0}

	if scanner.counts[ingressKey] != 2 {
		t.Errorf("expected ingress count 2, got %d", scanner.counts[ingressKey])
	}
	if scanner.counts[egressKey] != 1 {
		t.Errorf("expected egress count 1, got %d", scanner.counts[egressKey])
	}
}

func TestConnLimitScannerBothPodsLimited(t *testing.T) {
	podA := "10.65.0.2"
	podB := "10.65.0.3"

	scanner := &ConnLimitScanner{
		counts: make(map[connlimitKey]uint32),
		podInfo: map[string]ConnLimitPodInfo{
			string(net.ParseIP(podA).To4()): podInfo(9, false, true),  // egress only
			string(net.ParseIP(podB).To4()): podInfo(10, true, false), // ingress only
		},
	}

	// Pod A (opener) → Pod B (responder). A is AddrA, B is AddrB.
	key := makeKey(podA, podB, 54321, 8080)
	val := makeEstablishedValue()

	scanner.Check(key, val, nil)

	// Pod A is opener with egress limit → egress count on ifindex 9
	egressKey := connlimitKey{ifindex: 9, direction: 0}
	if scanner.counts[egressKey] != 1 {
		t.Errorf("expected egress count 1 for pod A, got %v", scanner.counts)
	}

	// Pod B is responder with ingress limit → ingress count on ifindex 10
	ingressKey := connlimitKey{ifindex: 10, direction: 1}
	if scanner.counts[ingressKey] != 1 {
		t.Errorf("expected ingress count 1 for pod B, got %v", scanner.counts)
	}
}

func TestConnLimitScannerNoCountWhenWrongDirection(t *testing.T) {
	podIP := "10.65.0.2"

	scanner := &ConnLimitScanner{
		counts: make(map[connlimitKey]uint32),
		podInfo: map[string]ConnLimitPodInfo{
			// Pod only has INGRESS limit, no egress limit.
			string(net.ParseIP(podIP).To4()): podInfo(9, true, false),
		},
	}

	// Pod is opener (= egress direction), but pod only has ingress limit → no count.
	key := makeKey(podIP, "10.65.1.3", 54321, 8080)
	val := makeEstablishedValue()

	scanner.Check(key, val, nil)

	if len(scanner.counts) != 0 {
		t.Errorf("expected no counts when pod is opener but only has ingress limit, got %v", scanner.counts)
	}
}
