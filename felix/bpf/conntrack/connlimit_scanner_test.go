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

	"golang.org/x/sys/unix"

	ctv4 "github.com/projectcalico/calico/felix/bpf/conntrack/v4"
	"github.com/projectcalico/calico/felix/bpf/qos"
)

// fakeQoSMap is a tiny in-memory implementation of connLimitQoSMap used by
// the batching tests. We don't reuse felix/bpf/mock.Map because that package
// imports conntrack (via cleaner.go), which would create a test-time import
// cycle.
type fakeQoSMap struct {
	contents         map[string][]byte
	batchUpdateCalls int
	lastBatchSize    int
	lastBatchFlags   uint64
	batchUpdateErr   error
}

func newFakeQoSMap() *fakeQoSMap {
	return &fakeQoSMap{contents: map[string][]byte{}}
}

func (f *fakeQoSMap) Get(k []byte) ([]byte, error) {
	v, ok := f.contents[string(k)]
	if !ok {
		return nil, unix.ENOENT
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (f *fakeQoSMap) BatchUpdate(ks, vs [][]byte, flags uint64) (int, error) {
	f.batchUpdateCalls++
	f.lastBatchSize = len(ks)
	f.lastBatchFlags = flags
	if f.batchUpdateErr != nil {
		return 0, f.batchUpdateErr
	}
	for i := range ks {
		cp := make([]byte, len(vs[i]))
		copy(cp, vs[i])
		f.contents[string(ks[i])] = cp
	}
	return len(ks), nil
}

// seed populates the connlimit map with (maxConn, current) for the given
// (ifindex, direction) pair. The scanner only touches the connlimit map;
// packet-rate state lives in a sibling map (cali_qos) the scanner never
// reads or writes.
func (f *fakeQoSMap) seed(t *testing.T, ifindex uint32, direction uint16, maxConn, current uint32) {
	t.Helper()
	k := qos.NewKey(ifindex, direction, qos.IPFamilyV4).AsBytes()
	v := qos.NewConnValue(maxConn, current).AsBytes()
	f.contents[string(k)] = v[:]
}

func (f *fakeQoSMap) currentCount(t *testing.T, ifindex uint32, direction uint16) uint32 {
	t.Helper()
	bytes, err := f.Get(qos.NewKey(ifindex, direction, qos.IPFamilyV4).AsBytes())
	if err != nil {
		t.Fatalf("fake Get for (%d,%d) failed: %v", ifindex, direction, err)
	}
	return qos.ConnValueFromBytes(bytes).CurrentCount()
}

// TestConnLimitScannerCheckNoPodsIsNoOp verifies that the scanner's Check
// method is a no-op when no pods have connection limits configured.
func TestConnLimitScannerCheckNoPodsIsNoOp(t *testing.T) {
	scanner := &ConnLimitScanner{
		family: qos.IPFamilyV4,
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
		family: qos.IPFamilyV4,
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
		family: qos.IPFamilyV4,
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
		family: qos.IPFamilyV4,
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
		family: qos.IPFamilyV4,
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
		family: qos.IPFamilyV4,
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
		family: qos.IPFamilyV4,
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
		family: qos.IPFamilyV4,
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
		family: qos.IPFamilyV4,
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
		family: qos.IPFamilyV4,
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
		family: qos.IPFamilyV4,
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

func TestConnLimitScannerSkipsConnLimitDec(t *testing.T) {
	podIP := "10.65.0.2"
	remoteIP := "10.65.1.3"

	scanner := &ConnLimitScanner{
		family: qos.IPFamilyV4,
		counts: make(map[connlimitKey]uint32),
		podInfo: map[string]ConnLimitPodInfo{
			string(net.ParseIP(podIP).To4()): podInfo(9, true, false),
		},
	}

	// Established connection with CONNLIMIT_DEC flag set — the BPF fast
	// path already decremented the counter for this connection. The scanner
	// must skip it to avoid recounting and overwriting the decremented value.
	key := makeKey(remoteIP, podIP, 54321, 8080)
	val := NewValueNormal(time.Duration(0), ctv4.FlagConnLimitDec,
		established(true),
		established(false),
	)

	verdict, _ := scanner.Check(key, val, nil)
	if verdict != ScanVerdictOK {
		t.Fatalf("expected ScanVerdictOK, got %d", verdict)
	}
	if len(scanner.counts) != 0 {
		t.Errorf("expected no counts for CONNLIMIT_DEC connection, got %v", scanner.counts)
	}
}

func TestConnLimitScannerNoCountWhenWrongDirection(t *testing.T) {
	podIP := "10.65.0.2"

	scanner := &ConnLimitScanner{
		family: qos.IPFamilyV4,
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

// TestConnLimitScannerDownsamples verifies that the scanner runs its real
// recount on iterations 1, 1+N, 1+2N, ... and skips the rest. The skipThisRun
// flag should suppress both Check (returns OK without touching counts) and
// IterationEnd. getPodInfo must be called only on the real-recount iterations.
func TestConnLimitScannerDownsamples(t *testing.T) {
	podInfoCalls := 0
	getPodInfo := func() map[string]ConnLimitPodInfo {
		podInfoCalls++
		return map[string]ConnLimitPodInfo{}
	}

	scanner := &ConnLimitScanner{
		family:     qos.IPFamilyV4,
		getPodInfo: getPodInfo,
		counts:     make(map[connlimitKey]uint32),
	}

	// Drive 2 full cycles + 1 extra iteration so we exercise both the
	// "run" and "skip" branches multiple times.
	const cycles = 2
	for i := 1; i <= cycles*connLimitScannerRunEveryN+1; i++ {
		scanner.IterationStart()

		wantSkip := (i-1)%connLimitScannerRunEveryN != 0
		if scanner.skipThisRun != wantSkip {
			t.Errorf("iteration %d: skipThisRun=%v, want %v", i, scanner.skipThisRun, wantSkip)
		}

		// Check should short-circuit on skipped iterations regardless
		// of input. Pass nil args — they must not be dereferenced.
		verdict, _ := scanner.Check(nil, nil, nil)
		if verdict != ScanVerdictOK {
			t.Errorf("iteration %d: Check verdict=%v, want OK", i, verdict)
		}

		// IterationEnd should short-circuit on skipped iterations.
		// On non-skipped iterations the podInfo is empty so the
		// early-return at "len(s.podInfo) == 0" kicks in instead.
		scanner.IterationEnd()
	}

	// Real recounts occur on iterations 1, 1+N, 1+2N → cycles+1 calls.
	wantCalls := cycles + 1
	if podInfoCalls != wantCalls {
		t.Errorf("getPodInfo calls=%d, want %d (one per real recount across %d cycles + 1)", podInfoCalls, wantCalls, cycles)
	}
}

// TestConnLimitScannerBatchesActiveCountUpdates verifies that IterationEnd
// batches updates for entries whose counts changed, preserves the packet-rate
// fields, and leaves unchanged entries alone.
func TestConnLimitScannerBatchesActiveCountUpdates(t *testing.T) {
	m := newFakeQoSMap()

	// Three limited pods: two whose counts changed, one whose count is
	// already correct (must not appear in the batch).
	const (
		ifA = uint32(11)
		ifB = uint32(22)
		ifC = uint32(33)
	)
	m.seed(t, ifA, 1, 5, 5) // ingress, will go to 2
	m.seed(t, ifB, 0, 5, 0) // egress, will go to 3
	m.seed(t, ifC, 1, 5, 1) // ingress, no change

	scanner := &ConnLimitScanner{
		family: qos.IPFamilyV4,
		qosMap: m,
		podInfo: map[string]ConnLimitPodInfo{
			"\x0a\x41\x00\x01": {IfIndex: ifA, HasIngressLimit: true},
			"\x0a\x41\x00\x02": {IfIndex: ifB, HasEgressLimit: true},
			"\x0a\x41\x00\x03": {IfIndex: ifC, HasIngressLimit: true},
		},
		counts: map[connlimitKey]uint32{
			{ifindex: ifA, direction: 1}: 2,
			{ifindex: ifB, direction: 0}: 3,
			{ifindex: ifC, direction: 1}: 1,
		},
	}

	scanner.IterationEnd()

	if got, want := m.currentCount(t, ifA, 1), uint32(2); got != want {
		t.Errorf("ifA ingress current=%d, want %d", got, want)
	}
	if got, want := m.currentCount(t, ifB, 0), uint32(3); got != want {
		t.Errorf("ifB egress current=%d, want %d", got, want)
	}
	if got, want := m.currentCount(t, ifC, 1), uint32(1); got != want {
		t.Errorf("ifC ingress current=%d, want %d (unchanged)", got, want)
	}

	// Exactly one BatchUpdate syscall, containing the two changed entries.
	if m.batchUpdateCalls != 1 {
		t.Errorf("expected 1 BatchUpdate call, got %d", m.batchUpdateCalls)
	}
	if m.lastBatchSize != 2 {
		t.Errorf("expected batch size 2 (the changed entries), got %d", m.lastBatchSize)
	}
	if m.lastBatchFlags != unix.BPF_F_LOCK {
		t.Errorf("expected batch flags=BPF_F_LOCK (0x%x), got 0x%x", unix.BPF_F_LOCK, m.lastBatchFlags)
	}

	// max_connections must survive the recount. Packet-rate state lives
	// in a separate map (cali_qos) the scanner has no handle to; the
	// connLimitQoSMap interface structurally precludes the scanner from
	// touching it.
	bytes, err := m.Get(qos.NewKey(ifA, 1, qos.IPFamilyV4).AsBytes())
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	v := qos.ConnValueFromBytes(bytes)
	if v.MaxConnections() != 5 {
		t.Errorf("max_connections not preserved: got %d, want 5", v.MaxConnections())
	}
}

// TestConnLimitScannerBatchNoOpWhenNothingChanged verifies that when the
// scanner's recount matches the existing map state, IterationEnd issues no
// BatchUpdate at all.
func TestConnLimitScannerBatchNoOpWhenNothingChanged(t *testing.T) {
	m := newFakeQoSMap()
	m.seed(t, 11, 1, 5, 2)
	m.seed(t, 22, 0, 5, 3)

	scanner := &ConnLimitScanner{
		family: qos.IPFamilyV4,
		qosMap: m,
		podInfo: map[string]ConnLimitPodInfo{
			"\x0a\x41\x00\x01": {IfIndex: 11, HasIngressLimit: true},
			"\x0a\x41\x00\x02": {IfIndex: 22, HasEgressLimit: true},
		},
		counts: map[connlimitKey]uint32{
			{ifindex: 11, direction: 1}: 2,
			{ifindex: 22, direction: 0}: 3,
		},
	}

	scanner.IterationEnd()
	if m.batchUpdateCalls != 0 {
		t.Errorf("expected 0 BatchUpdate calls when nothing changed, got %d", m.batchUpdateCalls)
	}
}

// TestConnLimitScannerBatchZeroesOutInactiveLimits verifies that pods with
// limits but no entries in s.counts get their current_count batched to 0.
func TestConnLimitScannerBatchZeroesOutInactiveLimits(t *testing.T) {
	m := newFakeQoSMap()
	// Stale non-zero current_count from a previous scan; no active connections
	// counted this iteration. Must be reset to 0.
	m.seed(t, 11, 1, 5, 4) // ingress
	m.seed(t, 22, 0, 5, 2) // egress

	scanner := &ConnLimitScanner{
		family: qos.IPFamilyV4,
		qosMap: m,
		podInfo: map[string]ConnLimitPodInfo{
			"\x0a\x41\x00\x01": {IfIndex: 11, HasIngressLimit: true},
			"\x0a\x41\x00\x02": {IfIndex: 22, HasEgressLimit: true},
		},
		counts: map[connlimitKey]uint32{}, // no active connections
	}

	scanner.IterationEnd()

	if got := m.currentCount(t, 11, 1); got != 0 {
		t.Errorf("ifindex 11 ingress: got current=%d, want 0", got)
	}
	if got := m.currentCount(t, 22, 0); got != 0 {
		t.Errorf("ifindex 22 egress: got current=%d, want 0", got)
	}
	// Both zero-outs should be in a single batch.
	if m.batchUpdateCalls != 1 {
		t.Errorf("expected 1 BatchUpdate call, got %d", m.batchUpdateCalls)
	}
	if m.lastBatchSize != 2 {
		t.Errorf("expected batch size 2, got %d", m.lastBatchSize)
	}
}
