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

package syncsource

import (
	"context"
	"sync"
	"testing"
	"time"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

// fakeSyncer is a minimal bapi.Syncer that records Start/Stop calls and can
// push updates into its callbacks.
type fakeSyncer struct {
	callbacks bapi.SyncerCallbacks

	lock         sync.Mutex
	startCalled  int
	stopCalled   int
	stopBlocksOn chan struct{}
}

func (f *fakeSyncer) Start() {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.startCalled++
}

func (f *fakeSyncer) Stop() {
	f.lock.Lock()
	ch := f.stopBlocksOn
	f.stopCalled++
	f.lock.Unlock()
	if ch != nil {
		<-ch
	}
}

func (f *fakeSyncer) starts() int {
	f.lock.Lock()
	defer f.lock.Unlock()
	return f.startCalled
}

func (f *fakeSyncer) stops() int {
	f.lock.Lock()
	defer f.lock.Unlock()
	return f.stopCalled
}

func TestDatastoreSource_ConstructStartStop(t *testing.T) {
	var fs *fakeSyncer
	src := NewDatastoreSource(func(cbs bapi.SyncerCallbacks) bapi.Syncer {
		fs = &fakeSyncer{callbacks: cbs}
		return fs
	}, nil)

	// Syncer should be constructed eagerly (matches historical behaviour) but
	// not yet started.
	if fs == nil {
		t.Fatal("expected syncer to be constructed at NewDatastoreSource time")
	}
	if got := fs.starts(); got != 0 {
		t.Fatalf("expected syncer not started before Start(); got %d starts", got)
	}

	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if got := fs.starts(); got != 1 {
		t.Fatalf("expected 1 start, got %d", got)
	}

	// Second Start is a no-op.
	_ = src.Start(context.Background())
	if got := fs.starts(); got != 1 {
		t.Fatalf("expected Start to be idempotent, got %d starts", got)
	}

	// Done should not be closed before Stop.
	select {
	case <-src.Done():
		t.Fatal("Done closed before Stop")
	default:
	}

	src.Stop()
	if got := fs.stops(); got != 1 {
		t.Fatalf("expected 1 stop, got %d", got)
	}
	select {
	case <-src.Done():
	case <-time.After(time.Second):
		t.Fatal("Done not closed after Stop")
	}

	// Stop is idempotent.
	src.Stop()
	if got := fs.stops(); got != 1 {
		t.Fatalf("expected Stop to be idempotent, got %d stops", got)
	}
}

// TestDatastoreSource_StopBlocksUntilSyncerStopped verifies the contract that
// Stop() does not return until the underlying syncer has stopped (i.e. no more
// callbacks can fire).  We make the fake syncer's Stop() block and confirm the
// source's Stop() blocks with it.
func TestDatastoreSource_StopBlocksUntilSyncerStopped(t *testing.T) {
	release := make(chan struct{})
	fs := &fakeSyncer{stopBlocksOn: release}
	src := NewDatastoreSource(func(cbs bapi.SyncerCallbacks) bapi.Syncer {
		fs.callbacks = cbs
		return fs
	}, nil)
	_ = src.Start(context.Background())

	stopReturned := make(chan struct{})
	go func() {
		src.Stop()
		close(stopReturned)
	}()

	select {
	case <-stopReturned:
		t.Fatal("Stop returned before the syncer's Stop() unblocked")
	case <-time.After(100 * time.Millisecond):
		// Expected: still blocked.
	}

	close(release)
	select {
	case <-stopReturned:
	case <-time.After(time.Second):
		t.Fatal("Stop did not return after the syncer's Stop() unblocked")
	}
}

// TestDatastoreSource_StopBeforeStart verifies stopping a source that was never
// started doesn't call Syncer.Stop() (which can panic in some implementations)
// and still closes Done.
func TestDatastoreSource_StopBeforeStart(t *testing.T) {
	fs := &fakeSyncer{}
	src := NewDatastoreSource(func(cbs bapi.SyncerCallbacks) bapi.Syncer {
		fs.callbacks = cbs
		return fs
	}, nil)

	src.Stop()
	if got := fs.stops(); got != 0 {
		t.Fatalf("expected syncer Stop NOT to be called when never started, got %d", got)
	}
	select {
	case <-src.Done():
	case <-time.After(time.Second):
		t.Fatal("Done not closed after Stop")
	}

	// Start after Stop should be a no-op.
	_ = src.Start(context.Background())
	if got := fs.starts(); got != 0 {
		t.Fatalf("expected Start after Stop to be a no-op, got %d starts", got)
	}
}
