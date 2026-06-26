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

package snapshotdump

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestResultForOutcomeInSync(t *testing.T) {
	r := resultForOutcome(outcomeInSync, 7, nil, nil, time.Second)
	if r.err != nil || r.timedOut || r.status != "in-sync" || r.count != 7 {
		t.Fatalf("unexpected result: %+v", r)
	}
}

func TestResultForOutcomeIdleTimeout(t *testing.T) {
	r := resultForOutcome(outcomeIdleTimeout, 3, nil, nil, 10*time.Second)
	if r.err != nil || !r.timedOut || r.count != 3 {
		t.Fatalf("unexpected result: %+v", r)
	}
}

func TestResultForOutcomeCancelled(t *testing.T) {
	ctxErr := context.Canceled
	r := resultForOutcome(outcomeCancelled, 1, nil, ctxErr, time.Second)
	if !errors.Is(r.err, context.Canceled) || r.timedOut || r.status != "cancelled" {
		t.Fatalf("unexpected result: %+v", r)
	}
}

// TestResultForOutcomeWriteErrorBeatsTimeout is the regression test for the
// case where the snapshot stream hit a write error and then the connection went
// idle: the write error must surface as a hard error, not be masked by a
// "timed-out" status that would leave a corrupt/partial dump with no marker.
func TestResultForOutcomeWriteErrorBeatsTimeout(t *testing.T) {
	writeErr := errors.New("disk full")
	for _, outcome := range []waitOutcome{outcomeInSync, outcomeIdleTimeout, outcomeCancelled} {
		r := resultForOutcome(outcome, 5, writeErr, context.Canceled, time.Second)
		if !errors.Is(r.err, writeErr) {
			t.Fatalf("outcome %v: expected write error to surface, got %+v", outcome, r)
		}
		if r.timedOut {
			t.Fatalf("outcome %v: write error must not be reported as timed-out: %+v", outcome, r)
		}
		if r.status != "error: disk full" {
			t.Fatalf("outcome %v: unexpected status %q", outcome, r.status)
		}
	}
}

func TestWaitForSnapshotInSync(t *testing.T) {
	done := make(chan struct{})
	activity := make(chan struct{}, 1)
	close(done)
	if got := waitForSnapshot(context.Background(), done, activity, 50*time.Millisecond); got != outcomeInSync {
		t.Fatalf("expected outcomeInSync, got %v", got)
	}
}

func TestWaitForSnapshotIdleTimeout(t *testing.T) {
	done := make(chan struct{})        // never closed
	activity := make(chan struct{}, 1) // no activity
	start := time.Now()
	if got := waitForSnapshot(context.Background(), done, activity, 30*time.Millisecond); got != outcomeIdleTimeout {
		t.Fatalf("expected outcomeIdleTimeout, got %v", got)
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Fatalf("timed out too early: %v", elapsed)
	}
}

func TestWaitForSnapshotActivityResetsTimer(t *testing.T) {
	done := make(chan struct{})
	activity := make(chan struct{}, 1)

	// Keep pinging activity faster than the idle timeout for a while, then let
	// it complete.  It must not time out while activity is flowing.
	go func() {
		for i := 0; i < 5; i++ {
			activity <- struct{}{}
			time.Sleep(20 * time.Millisecond)
		}
		close(done)
	}()

	if got := waitForSnapshot(context.Background(), done, activity, 60*time.Millisecond); got != outcomeInSync {
		t.Fatalf("expected outcomeInSync (activity should keep it alive), got %v", got)
	}
}

func TestWaitForSnapshotCancelled(t *testing.T) {
	done := make(chan struct{})
	activity := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := waitForSnapshot(ctx, done, activity, time.Hour); got != outcomeCancelled {
		t.Fatalf("expected outcomeCancelled, got %v", got)
	}
}

func TestWaitForSnapshotUnboundedIgnoresIdle(t *testing.T) {
	done := make(chan struct{})
	activity := make(chan struct{}, 1)
	// idle <= 0 disables the bound: with no done and no cancel it would block
	// forever, so cancel shortly to prove it isn't the idle path that returns.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()
	if got := waitForSnapshot(ctx, done, activity, 0); got != outcomeCancelled {
		t.Fatalf("expected outcomeCancelled (idle disabled), got %v", got)
	}
}
