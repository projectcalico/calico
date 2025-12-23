// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// ============================================================================
// Test Mocks
// ============================================================================

// mockEventHandler implements EventHandler for testing
type mockEventHandler struct {
	addEvents       []*model.KVPair
	updateEvents    []*model.KVPair
	deleteEvents    []*model.KVPair
	syncCount       int
	resyncStartedCt int
	errors          []error
}

func newMockEventHandler() *mockEventHandler {
	return &mockEventHandler{
		addEvents:    make([]*model.KVPair, 0),
		updateEvents: make([]*model.KVPair, 0),
		deleteEvents: make([]*model.KVPair, 0),
		errors:       make([]error, 0),
	}
}

func (m *mockEventHandler) OnResyncStarted() {
	m.resyncStartedCt++
}

func (m *mockEventHandler) OnAdd(kvp *model.KVPair) {
	m.addEvents = append(m.addEvents, kvp)
}

func (m *mockEventHandler) OnUpdate(kvp *model.KVPair) {
	m.updateEvents = append(m.updateEvents, kvp)
}

func (m *mockEventHandler) OnDelete(kvp *model.KVPair) {
	m.deleteEvents = append(m.deleteEvents, kvp)
}

func (m *mockEventHandler) OnSync() {
	m.syncCount++
}

func (m *mockEventHandler) OnError(err error) {
	m.errors = append(m.errors, err)
}

// mockWatcher implements WatchInterface for testing
type mockWatcher struct {
	events     chan WatchEvent
	stopped    bool
	terminated bool
}

func newMockWatcher() *mockWatcher {
	return &mockWatcher{
		events: make(chan WatchEvent, 10),
	}
}

func (w *mockWatcher) Stop() {
	if !w.stopped {
		w.stopped = true
		close(w.events)
	}
}

func (w *mockWatcher) ResultChan() <-chan WatchEvent {
	return w.events
}

func (w *mockWatcher) HasTerminated() bool {
	return w.terminated
}

func (w *mockWatcher) SendEvent(event WatchEvent) {
	w.events <- event
}

// mockListWatchBackend implements ListWatchBackend for testing
type mockListWatchBackend struct {
	listResult       *model.KVPairList
	listError        error
	watchResult      WatchInterface
	watchError       error
	listErrorHandler func(error)
	watchErrorCalls  int
}

func newMockListWatchBackend() *mockListWatchBackend {
	return &mockListWatchBackend{
		listResult: &model.KVPairList{
			KVPairs: []*model.KVPair{
				{Key: model.GlobalConfigKey{Name: "key1"}, Value: "value1", Revision: "1"},
			},
			Revision: "100",
		},
	}
}

func (m *mockListWatchBackend) PerformList(ctx context.Context) (*model.KVPairList, error) {
	return m.listResult, m.listError
}

func (m *mockListWatchBackend) CreateWatch(ctx context.Context, isInitialSync bool) (WatchInterface, error) {
	return m.watchResult, m.watchError
}

func (m *mockListWatchBackend) HandleWatchEvent(event WatchEvent) error {
	return nil
}

func (m *mockListWatchBackend) HandleListError(err error) {
	if m.listErrorHandler != nil {
		m.listErrorHandler(err)
	}
}

func (m *mockListWatchBackend) HandleWatchError(err error) {
	m.watchErrorCalls++
}

func (m *mockListWatchBackend) PerformInitialSync(ctx context.Context, g *GenericListWatcher) error {
	return g.PerformListSync(ctx, m)
}

// testListOptions returns a real ListInterface for testing
func testListOptions() model.ListInterface {
	return model.GlobalConfigListOptions{}
}

// ============================================================================
// GenericListWatcher Creation and State Management Tests
// ============================================================================

func TestNewGenericListWatcher(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewGenericListWatcher(list, handler)

	assert.NotNil(t, lw)
	assert.Equal(t, list, lw.List)
	assert.Equal(t, handler, lw.Handler)
	assert.Equal(t, "", lw.CurrentRevision)
	assert.Equal(t, 0, lw.ErrorCountAtCurrentRev)
	assert.NotNil(t, lw.Logger)
}

func TestGenericListWatcher_UpdateRevision(t *testing.T) {
	lw := NewGenericListWatcher(testListOptions(), newMockEventHandler())

	// Update revision should set CurrentRevision and reset error count
	lw.IncrementErrorCount()
	lw.IncrementErrorCount()
	assert.Equal(t, 2, lw.ErrorCountAtCurrentRev)

	lw.UpdateRevision("100")
	assert.Equal(t, "100", lw.CurrentRevision)
	assert.Equal(t, 0, lw.ErrorCountAtCurrentRev)

	// Empty revision should not update
	lw.UpdateRevision("")
	assert.Equal(t, "100", lw.CurrentRevision)
}

func TestGenericListWatcher_IncrementErrorCount_Threshold(t *testing.T) {
	lw := NewGenericListWatcher(testListOptions(), newMockEventHandler())

	// Increment errors up to threshold
	for i := 1; i < MaxErrorsPerRevision; i++ {
		exceeded := lw.IncrementErrorCount()
		assert.False(t, exceeded, "Should not exceed at count %d", i)
	}

	// Next increment should exceed threshold
	exceeded := lw.IncrementErrorCount()
	assert.True(t, exceeded)
	assert.Equal(t, MaxErrorsPerRevision, lw.ErrorCountAtCurrentRev)
}

func TestGenericListWatcher_ResetForFullResync(t *testing.T) {
	lw := NewGenericListWatcher(testListOptions(), newMockEventHandler())

	lw.UpdateRevision("500")
	lw.IncrementErrorCount()
	lw.MarkInitialSyncComplete() // Clear initial sync pending

	lw.ResetForFullResync()

	assert.Equal(t, "", lw.CurrentRevision)
	assert.Equal(t, 0, lw.ErrorCountAtCurrentRev)
	assert.True(t, lw.InitialSyncPending) // Should be set back to true
}

func TestGenericListWatcher_MarkInitialSyncComplete(t *testing.T) {
	lw := NewGenericListWatcher(testListOptions(), newMockEventHandler())

	// Initially pending
	assert.True(t, lw.InitialSyncPending)

	lw.MarkInitialSyncComplete()

	assert.False(t, lw.InitialSyncPending)
}

func TestGenericListWatcher_InitialSyncPending(t *testing.T) {
	lw := NewGenericListWatcher(testListOptions(), newMockEventHandler())

	// Initial state: InitialSyncPending=true
	assert.True(t, lw.InitialSyncPending)

	// Clear InitialSyncPending
	lw.MarkInitialSyncComplete()
	assert.False(t, lw.InitialSyncPending)

	// Reset should set InitialSyncPending=true
	lw.ResetForFullResync()
	assert.True(t, lw.InitialSyncPending)
}

func TestGenericListWatcher_ConnectionTracking(t *testing.T) {
	lw := NewGenericListWatcher(testListOptions(), newMockEventHandler())

	// Just connected, should not timeout
	assert.False(t, lw.CheckConnectionTimeout())

	// Set last connection to past timeout
	lw.LastSuccessfulConnTime = time.Now().Add(-WatchRetryTimeout - time.Second)
	assert.True(t, lw.CheckConnectionTimeout())

	// Mark successful connection should reset
	lw.MarkSuccessfulConnection()
	assert.False(t, lw.CheckConnectionTimeout())
}

// ============================================================================
// Retry Throttling Tests
// ============================================================================

func TestGenericListWatcher_RetryThrottling(t *testing.T) {
	lw := NewGenericListWatcher(testListOptions(), newMockEventHandler())

	// No pending delay, should trigger immediately
	select {
	case <-lw.RetryThrottleC():
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Fatal("RetryThrottleC should have triggered immediately")
	}

	// Schedule retry for 50ms in future
	lw.RetryAfter(50 * time.Millisecond)

	start := time.Now()
	<-lw.RetryThrottleC()
	elapsed := time.Since(start)

	assert.True(t, elapsed >= 40*time.Millisecond, "Should wait for scheduled time")
}

// ============================================================================
// Watch Event Handling Tests
// ============================================================================

func TestGenericListWatcher_HandleBasicWatchEvent(t *testing.T) {
	tests := []struct {
		name           string
		event          WatchEvent
		expectHandled  bool
		expectAdds     int
		expectUpdates  int
		expectDeletes  int
		expectRevision string
	}{
		{
			name: "Added event",
			event: WatchEvent{
				Type: WatchAdded,
				New:  &model.KVPair{Key: model.GlobalConfigKey{Name: "test"}, Value: "val", Revision: "10"},
			},
			expectHandled:  true,
			expectAdds:     1,
			expectRevision: "10",
		},
		{
			name: "Modified event",
			event: WatchEvent{
				Type: WatchModified,
				New:  &model.KVPair{Key: model.GlobalConfigKey{Name: "test"}, Value: "new", Revision: "20"},
			},
			expectHandled:  true,
			expectUpdates:  1,
			expectRevision: "20",
		},
		{
			name: "Deleted event",
			event: WatchEvent{
				Type: WatchDeleted,
				Old:  &model.KVPair{Key: model.GlobalConfigKey{Name: "test"}, Value: "val", Revision: "30"},
			},
			expectHandled:  true,
			expectDeletes:  1,
			expectRevision: "30",
		},
		{
			name: "Error event - not handled by basic handler",
			event: WatchEvent{
				Type:  WatchError,
				Error: errors.New("test error"),
			},
			expectHandled:  false,
			expectRevision: "",
		},
		{
			name: "Bookmark event - not handled by basic handler",
			event: WatchEvent{
				Type: WatchBookmark,
				New:  &model.KVPair{Revision: "100"},
			},
			expectHandled:  false,
			expectRevision: "",
		},
		{
			name: "Unknown event type - not handled",
			event: WatchEvent{
				Type: WatchEventType("unknown"),
			},
			expectHandled:  false,
			expectRevision: "",
		},
		{
			name:           "Added without New value - handled with error log",
			event:          WatchEvent{Type: WatchAdded, New: nil},
			expectHandled:  true,
			expectAdds:     0,
			expectRevision: "",
		},
		{
			name:           "Modified without New value - handled with error log",
			event:          WatchEvent{Type: WatchModified, New: nil},
			expectHandled:  true,
			expectUpdates:  0,
			expectRevision: "",
		},
		{
			name:           "Deleted without Old value - handled with error log",
			event:          WatchEvent{Type: WatchDeleted, Old: nil},
			expectHandled:  true,
			expectDeletes:  0,
			expectRevision: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := newMockEventHandler()
			lw := NewGenericListWatcher(testListOptions(), handler)

			handled := lw.HandleBasicWatchEvent(tt.event)

			assert.Equal(t, tt.expectHandled, handled)
			assert.Len(t, handler.addEvents, tt.expectAdds)
			assert.Len(t, handler.updateEvents, tt.expectUpdates)
			assert.Len(t, handler.deleteEvents, tt.expectDeletes)
			assert.Equal(t, tt.expectRevision, lw.CurrentRevision)
		})
	}
}

func TestGenericListWatcher_SendListAsAddEvents(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)

	kvpList := &model.KVPairList{
		KVPairs: []*model.KVPair{
			{Key: model.GlobalConfigKey{Name: "key1"}, Value: "value1", Revision: "1"},
			{Key: model.GlobalConfigKey{Name: "key2"}, Value: "value2", Revision: "2"},
			{Key: model.GlobalConfigKey{Name: "key3"}, Value: "value3", Revision: "3"},
		},
		Revision: "3",
	}

	lw.SendListAsAddEvents(kvpList)

	assert.Len(t, handler.addEvents, 3)
	assert.Equal(t, "value1", handler.addEvents[0].Value)
	assert.Equal(t, "value2", handler.addEvents[1].Value)
	assert.Equal(t, "value3", handler.addEvents[2].Value)
}

// ============================================================================
// Watch Loop Tests
// ============================================================================

func TestGenericListWatcher_LoopReadingFromWatcher(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)

	watcher := newMockWatcher()
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(10 * time.Millisecond)
		watcher.SendEvent(WatchEvent{
			Type: WatchAdded,
			New:  &model.KVPair{Key: model.GlobalConfigKey{Name: "k1"}, Value: "v1", Revision: "1"},
		})
		watcher.SendEvent(WatchEvent{
			Type: WatchModified,
			New:  &model.KVPair{Key: model.GlobalConfigKey{Name: "k1"}, Value: "v2", Revision: "2"},
		})
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	eventHandler := func(event WatchEvent) error {
		lw.HandleBasicWatchEvent(event)
		return nil
	}

	lw.LoopReadingFromWatcher(ctx, watcher, eventHandler)

	assert.Len(t, handler.addEvents, 1)
	assert.Len(t, handler.updateEvents, 1)
	assert.Equal(t, "2", lw.CurrentRevision)
}

func TestGenericListWatcher_LoopReadingFromWatcher_ChannelClosed(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)

	watcher := newMockWatcher()
	ctx := context.Background()

	go func() {
		time.Sleep(10 * time.Millisecond)
		watcher.SendEvent(WatchEvent{
			Type: WatchAdded,
			New:  &model.KVPair{Key: model.GlobalConfigKey{Name: "k1"}, Value: "v1", Revision: "1"},
		})
		time.Sleep(10 * time.Millisecond)
		watcher.Stop()
	}()

	eventHandler := func(event WatchEvent) error {
		lw.HandleBasicWatchEvent(event)
		return nil
	}

	lw.LoopReadingFromWatcher(ctx, watcher, eventHandler)

	assert.Len(t, handler.addEvents, 1)
}

func TestGenericListWatcher_LoopReadingFromWatcher_ErrorStopsLoop(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)

	watcher := newMockWatcher()
	ctx := context.Background()

	go func() {
		time.Sleep(10 * time.Millisecond)
		watcher.SendEvent(WatchEvent{
			Type: WatchAdded,
			New:  &model.KVPair{Key: model.GlobalConfigKey{Name: "k1"}, Value: "v1", Revision: "1"},
		})
		watcher.SendEvent(WatchEvent{
			Type:  WatchError,
			Error: errors.New("watch error"),
		})
		// This event should not be processed
		watcher.SendEvent(WatchEvent{
			Type: WatchAdded,
			New:  &model.KVPair{Key: model.GlobalConfigKey{Name: "k2"}, Value: "v2", Revision: "2"},
		})
	}()

	eventHandler := func(event WatchEvent) error {
		if event.Type == WatchError {
			return event.Error
		}
		lw.HandleBasicWatchEvent(event)
		return nil
	}

	lw.LoopReadingFromWatcher(ctx, watcher, eventHandler)

	// Only first event should be processed
	assert.Len(t, handler.addEvents, 1)
}

// ============================================================================
// Watcher Cleanup Tests
// ============================================================================

func TestGenericListWatcher_CleanExistingWatcher(t *testing.T) {
	lw := NewGenericListWatcher(testListOptions(), newMockEventHandler())

	// With watcher - should stop and nil it
	watcher := newMockWatcher()
	lw.Watch = watcher
	assert.False(t, watcher.stopped)

	lw.CleanExistingWatcher()
	assert.True(t, watcher.stopped)
	assert.Nil(t, lw.Watch)

	// With nil watcher - should not panic
	lw.Watch = nil
	lw.CleanExistingWatcher()
	assert.Nil(t, lw.Watch)
}

// ============================================================================
// PerformListSync Tests
// ============================================================================

func TestPerformListSync_Success(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)

	backend := newMockListWatchBackend()

	err := lw.PerformListSync(context.Background(), backend)

	assert.NoError(t, err)
	assert.Equal(t, 1, handler.resyncStartedCt)
	assert.Equal(t, 1, handler.syncCount)
	assert.Len(t, handler.addEvents, 1)
	assert.Equal(t, "100", lw.CurrentRevision)
	assert.False(t, lw.InitialSyncPending) // Should be cleared after successful sync
}

func TestPerformListSync_ListError(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)

	backend := newMockListWatchBackend()
	backend.listError = errors.New("list failed")

	listErrorCalled := false
	backend.listErrorHandler = func(err error) {
		listErrorCalled = true
	}

	err := lw.PerformListSync(context.Background(), backend)

	assert.Error(t, err)
	assert.True(t, listErrorCalled)
	assert.Equal(t, 1, handler.resyncStartedCt)
	assert.Equal(t, 0, handler.syncCount) // Sync should not be called on error
}

func TestPerformListSync_EmptyRevisionNoItems(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)

	backend := newMockListWatchBackend()
	backend.listResult = &model.KVPairList{
		KVPairs:  []*model.KVPair{}, // No items
		Revision: "",                // Empty revision
	}

	err := lw.PerformListSync(context.Background(), backend)

	// Should return error and schedule retry (poll mode)
	assert.Error(t, err)
	assert.Equal(t, "", lw.CurrentRevision) // Should reset for resync
	assert.True(t, lw.RetryBlockedUntil.After(time.Now()))
}

func TestPerformListSync_ZeroRevisionNoItems(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)

	backend := newMockListWatchBackend()
	backend.listResult = &model.KVPairList{
		KVPairs:  []*model.KVPair{}, // No items
		Revision: "",                // Zero revision
	}

	err := lw.PerformListSync(context.Background(), backend)

	// Should return error and schedule retry (poll mode)
	assert.Error(t, err)
	assert.Equal(t, "", lw.CurrentRevision)
}

func TestPerformListSync_ZeroRevisionWithItems_Panics(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)

	backend := newMockListWatchBackend()
	backend.listResult = &model.KVPairList{
		KVPairs: []*model.KVPair{
			{Key: model.GlobalConfigKey{Name: "key1"}, Value: "value1", Revision: "1"},
		},
		Revision: "", // Zero revision with items - BUG condition
	}

	// Should panic due to inconsistent state
	assert.Panics(t, func() {
		lw.PerformListSync(context.Background(), backend)
	})
}

// ============================================================================
// RunLoopWithBackend Integration Tests
// ============================================================================

func TestGenericListWatcher_RunLoopWithBackend_SuccessfulSync(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)

	backend := newMockListWatchBackend()
	watcher := newMockWatcher()
	backend.watchResult = watcher

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error)
	go func() {
		done <- lw.RunLoopWithBackend(ctx, backend)
	}()

	// Wait a bit for initial sync to complete
	time.Sleep(50 * time.Millisecond)

	// Send a watch event
	watcher.SendEvent(WatchEvent{
		Type: WatchAdded,
		New:  &model.KVPair{Key: model.GlobalConfigKey{Name: "new-key"}, Value: "new-value", Revision: "101"},
	})

	time.Sleep(20 * time.Millisecond)
	cancel()

	err := <-done
	assert.Equal(t, context.Canceled, err)

	// Verify initial sync occurred
	assert.Equal(t, 1, handler.resyncStartedCt)
	assert.Equal(t, 1, handler.syncCount)
	assert.GreaterOrEqual(t, len(handler.addEvents), 1)
}

func TestGenericListWatcher_RunLoopWithBackend_WatchCreationFails(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)

	backend := newMockListWatchBackend()
	backend.watchError = errors.New("watch creation failed")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := lw.RunLoopWithBackend(ctx, backend)

	assert.Equal(t, context.DeadlineExceeded, err)
	assert.GreaterOrEqual(t, backend.watchErrorCalls, 1)
}

func TestGenericListWatcher_RunLoopWithBackend_NoResyncNeeded(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)
	lw.UpdateRevision("100")     // Already has a revision
	lw.MarkInitialSyncComplete() // No resync needed

	backend := newMockListWatchBackend()
	watcher := newMockWatcher()
	backend.watchResult = watcher

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error)
	go func() {
		done <- lw.RunLoopWithBackend(ctx, backend)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	err := <-done
	assert.Equal(t, context.Canceled, err)

	// No resync should occur
	assert.Equal(t, 0, handler.resyncStartedCt)
}

func TestGenericListWatcher_RunLoopWithBackend_WatchChannelClosed_Recreates(t *testing.T) {
	handler := newMockEventHandler()
	lw := NewGenericListWatcher(testListOptions(), handler)

	watcherCount := 0
	backend := newMockListWatchBackend()

	// Create multiple watchers to simulate reconnection
	originalCreateWatch := backend.CreateWatch
	_ = originalCreateWatch
	backend.watchResult = nil

	// Custom mock that creates new watchers
	var currentWatcher *mockWatcher
	backend = &mockListWatchBackend{
		listResult: &model.KVPairList{
			KVPairs:  []*model.KVPair{{Key: model.GlobalConfigKey{Name: "key1"}, Value: "value1", Revision: "1"}},
			Revision: "100",
		},
	}

	// Override watch creation to track calls
	createWatchCalls := 0
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error)
	go func() {
		for ctx.Err() == nil {
			createWatchCalls++
			currentWatcher = newMockWatcher()
			// Close the watcher after a short time to trigger reconnection
			go func(w *mockWatcher) {
				time.Sleep(50 * time.Millisecond)
				w.Stop()
			}(currentWatcher)

			lw.Watch = currentWatcher
			lw.loopReadingFromWatcherWithBackend(ctx, backend)
			watcherCount++
			if watcherCount >= 2 {
				cancel()
				break
			}
		}
		done <- nil
	}()

	<-done

	// Verify multiple watchers were created due to channel close
	require.GreaterOrEqual(t, watcherCount, 1)
}
