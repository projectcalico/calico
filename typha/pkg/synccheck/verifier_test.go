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

package synccheck

import (
	"sync/atomic"
	"testing"
	"time"
)

// mutableLocal is a settable LocalChecksumProvider for tests.
type mutableLocal struct {
	atomic.Pointer[Checksum]
}

func (m *mutableLocal) set(c Checksum) { m.Store(&c) }
func (m *mutableLocal) LocalChecksum() Checksum {
	if p := m.Load(); p != nil {
		return *p
	}
	return Checksum{}
}

func newTestVerifier(local LocalChecksumProvider, action MismatchAction, reconnect func()) *Verifier {
	return NewVerifier(VerifierConfig{
		SyncerType:           "test",
		MismatchAction:       action,
		Local:                local,
		RequestReconnect:     reconnect,
		PersistChecks:        3,
		ReconnectMinInterval: 10 * time.Minute,
	})
}

func cs(xor uint64, count int64) Checksum { return Checksum{XOR: xor, KVCount: count} }

// TestVerifier_DeferredMatchClearsExpectation verifies that a mismatch caused by
// in-flight pipeline skew clears once the local state catches up, without
// alarming.
func TestVerifier_DeferredMatchClearsExpectation(t *testing.T) {
	local := &mutableLocal{}
	local.set(cs(111, 5)) // stale: pipeline hasn't drained yet.
	var reconnects int
	v := newTestVerifier(local, MismatchActionReconnect, func() { reconnects++ })

	v.OnRemoteChecksum(cs(222, 6), false)

	// First two checks see the stale local value: mismatch, but below the
	// persistence threshold, so no alarm.
	if v.Check() {
		t.Fatal("alarmed on first check")
	}
	// Local catches up before the third check.
	local.set(cs(222, 6))
	if v.Check() {
		t.Fatal("alarmed after local caught up")
	}
	if reconnects != 0 {
		t.Fatalf("unexpected reconnects: %d", reconnects)
	}
	// Expectation should be cleared; a further check is a no-op.
	if v.Check() {
		t.Fatal("alarmed with no pending expectation")
	}
}

// TestVerifier_PersistentMismatchAlarms verifies that a mismatch persisting
// across the configured number of checks is confirmed and triggers a reconnect.
func TestVerifier_PersistentMismatchAlarms(t *testing.T) {
	local := &mutableLocal{}
	local.set(cs(111, 5))
	var reconnects int
	v := newTestVerifier(local, MismatchActionReconnect, func() { reconnects++ })

	v.OnRemoteChecksum(cs(999, 9), false)

	// Three consecutive mismatches needed (PersistChecks=3).
	if v.Check() {
		t.Fatal("alarmed too early (check 1)")
	}
	if v.Check() {
		t.Fatal("alarmed too early (check 2)")
	}
	if !v.Check() {
		t.Fatal("did not alarm on third persistent mismatch")
	}
	if reconnects != 1 {
		t.Fatalf("expected exactly one reconnect, got %d", reconnects)
	}
}

// TestVerifier_CountOnlyIgnoresXORDifference verifies version-skew handling:
// when countOnly is set, a differing XOR with a matching KVCount is treated as a
// match.
func TestVerifier_CountOnlyIgnoresXORDifference(t *testing.T) {
	local := &mutableLocal{}
	// Different XOR (re-serialized bytes differ across versions) but same count.
	local.set(cs(0xdead, 42))
	v := newTestVerifier(local, MismatchActionLog, nil)

	v.OnRemoteChecksum(cs(0xbeef, 42), true /* countOnly */)
	if v.Check() {
		t.Fatal("count-only comparison should have matched despite differing XOR")
	}

	// But a differing count must still alarm.
	local.set(cs(0xdead, 41))
	v.OnRemoteChecksum(cs(0xbeef, 42), true)
	v.Check()
	v.Check()
	if !v.Check() {
		t.Fatal("count-only comparison should alarm on differing KVCount")
	}
}

// TestVerifier_LogActionDoesNotReconnect verifies the log-only action never
// calls the reconnect hook.
func TestVerifier_LogActionDoesNotReconnect(t *testing.T) {
	local := &mutableLocal{}
	local.set(cs(1, 1))
	var reconnects int
	v := newTestVerifier(local, MismatchActionLog, func() { reconnects++ })

	v.OnRemoteChecksum(cs(2, 2), false)
	for i := 0; i < 5; i++ {
		v.Check()
	}
	if reconnects != 0 {
		t.Fatalf("log action triggered %d reconnects, want 0", reconnects)
	}
}

// TestVerifier_ReconnectRateLimited verifies repeated confirmed mismatches don't
// produce a reconnect storm.
func TestVerifier_ReconnectRateLimited(t *testing.T) {
	local := &mutableLocal{}
	local.set(cs(1, 1))
	var reconnects int
	now := time.Now()
	v := NewVerifier(VerifierConfig{
		SyncerType:           "test",
		MismatchAction:       MismatchActionReconnect,
		Local:                local,
		RequestReconnect:     func() { reconnects++ },
		PersistChecks:        1,
		ReconnectMinInterval: 10 * time.Minute,
		Now:                  func() time.Time { return now },
	})

	// Confirm a mismatch three times in quick succession (clock frozen).
	for i := 0; i < 3; i++ {
		v.OnRemoteChecksum(cs(uint64(100+i), 2), false)
		if !v.Check() {
			t.Fatalf("expected confirmed mismatch on iteration %d", i)
		}
	}
	if reconnects != 1 {
		t.Fatalf("expected rate-limited to a single reconnect, got %d", reconnects)
	}

	// Advance past the rate-limit window: the next confirmed mismatch reconnects.
	now = now.Add(11 * time.Minute)
	v.OnRemoteChecksum(cs(200, 2), false)
	if !v.Check() {
		t.Fatal("expected confirmed mismatch after window")
	}
	if reconnects != 2 {
		t.Fatalf("expected a second reconnect after the window, got %d", reconnects)
	}
}

// TestVerifier_ResetClearsExpectation verifies Reset drops a pending comparison.
func TestVerifier_ResetClearsExpectation(t *testing.T) {
	local := &mutableLocal{}
	local.set(cs(1, 1))
	v := newTestVerifier(local, MismatchActionLog, nil)
	v.OnRemoteChecksum(cs(2, 2), false)
	v.Reset()
	if v.Check() {
		t.Fatal("Check alarmed after Reset cleared the expectation")
	}
}
