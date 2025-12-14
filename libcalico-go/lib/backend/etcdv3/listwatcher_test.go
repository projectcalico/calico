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

package etcdv3

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// mockEventHandler implements api.EventHandler for testing
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

// mockWatcher implements api.WatchInterface for testing
type mockWatcher struct {
	events     chan api.WatchEvent
	stopped    bool
	terminated bool
}

func newMockWatcher() *mockWatcher {
	return &mockWatcher{
		events: make(chan api.WatchEvent, 10),
	}
}

func (w *mockWatcher) Stop() {
	if !w.stopped {
		w.stopped = true
		close(w.events)
	}
}

func (w *mockWatcher) ResultChan() <-chan api.WatchEvent {
	return w.events
}

func (w *mockWatcher) HasTerminated() bool {
	return w.terminated
}

func (w *mockWatcher) SendEvent(event api.WatchEvent) {
	w.events <- event
}

// testListOptions returns a real ListInterface for testing
func testListOptions() model.ListInterface {
	return model.GlobalConfigListOptions{}
}

// ============================================================================
// ListWatcher Creation Tests
// ============================================================================

func TestListWatcher_Creation(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil, // We don't need a real client for this test
	}

	assert.NotNil(t, lw)
	assert.NotNil(t, lw.GenericListWatcher)
	assert.Equal(t, list, lw.List)
	assert.Equal(t, handler, lw.Handler)
	assert.Equal(t, "", lw.CurrentRevision)
}

// ============================================================================
// HandleWatchEvent Tests
// ============================================================================

func TestListWatcher_HandleWatchEvent_Added(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}

	event := api.WatchEvent{
		Type: api.WatchAdded,
		New:  &model.KVPair{Key: model.GlobalConfigKey{Name: "test"}, Value: "val", Revision: "10"},
	}

	err := lw.HandleWatchEvent(event)

	assert.NoError(t, err)
	assert.Len(t, handler.addEvents, 1)
	assert.Equal(t, "10", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchEvent_Modified(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}

	event := api.WatchEvent{
		Type: api.WatchModified,
		Old:  &model.KVPair{Key: model.GlobalConfigKey{Name: "test"}, Value: "old", Revision: "5"},
		New:  &model.KVPair{Key: model.GlobalConfigKey{Name: "test"}, Value: "new", Revision: "20"},
	}

	err := lw.HandleWatchEvent(event)

	assert.NoError(t, err)
	assert.Len(t, handler.updateEvents, 1)
	assert.Equal(t, "new", handler.updateEvents[0].Value)
	assert.Equal(t, "20", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchEvent_Deleted(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}

	event := api.WatchEvent{
		Type: api.WatchDeleted,
		Old:  &model.KVPair{Key: model.GlobalConfigKey{Name: "test"}, Value: "val", Revision: "30"},
	}

	err := lw.HandleWatchEvent(event)

	assert.NoError(t, err)
	assert.Len(t, handler.deleteEvents, 1)
	assert.Equal(t, "30", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchEvent_Error_BelowThreshold(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}
	lw.CurrentRevision = "100"

	testErr := errors.New("watch error")
	event := api.WatchEvent{
		Type:  api.WatchError,
		Error: testErr,
	}

	err := lw.HandleWatchEvent(event)

	// Should return the error to stop processing
	assert.Error(t, err)
	assert.Equal(t, testErr, err)
	// Should not reset revision (below error threshold)
	assert.Equal(t, "100", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchEvent_Error_ExceedsThreshold(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}
	lw.CurrentRevision = "100"

	// Set error count close to threshold
	for i := 0; i < api.MaxErrorsPerRevision-1; i++ {
		lw.IncrementErrorCount()
	}

	testErr := errors.New("watch error")
	event := api.WatchEvent{
		Type:  api.WatchError,
		Error: testErr,
	}

	err := lw.HandleWatchEvent(event)

	// Should return the error to stop processing
	assert.Error(t, err)
	// Should reset for full resync after exceeding threshold
	assert.Equal(t, "", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchEvent_UnknownType(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}

	event := api.WatchEvent{
		Type: api.WatchEventType("UNKNOWN"),
	}

	err := lw.HandleWatchEvent(event)

	// Should return nil (just log warning)
	assert.NoError(t, err)
}

// ============================================================================
// HandleListError Tests
// ============================================================================

func TestListWatcher_HandleListError_GenericError(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}

	genericErr := errors.New("list failed")

	lw.HandleListError(genericErr)

	// Should schedule a retry
	assert.True(t, lw.RetryBlockedUntil.After(time.Now()))
}

func TestListWatcher_HandleListError_ConnectionTimeout(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}
	// Set last connection to past timeout
	lw.LastSuccessfulConnTime = time.Now().Add(-api.WatchRetryTimeout - time.Second)

	genericErr := errors.New("connection error")

	lw.HandleListError(genericErr)

	// Should call OnError due to timeout
	assert.Len(t, handler.errors, 1)
}

// ============================================================================
// HandleWatchError Tests
// ============================================================================

func TestListWatcher_HandleWatchError_BelowThreshold(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}
	lw.CurrentRevision = "100"

	genericErr := errors.New("watch error")

	lw.HandleWatchError(genericErr)

	// Should not reset revision (below threshold)
	assert.Equal(t, "100", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchError_ExceedsThreshold(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}
	lw.CurrentRevision = "100"

	// Set error count close to threshold
	for i := 0; i < api.MaxErrorsPerRevision-1; i++ {
		lw.IncrementErrorCount()
	}

	genericErr := errors.New("watch error")

	lw.HandleWatchError(genericErr)

	// Should reset for full resync after exceeding threshold
	assert.Equal(t, "", lw.CurrentRevision)
}

// ============================================================================
// InitialSyncPending Tests
// ============================================================================

func TestListWatcher_InitialSyncPending_Initial(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}

	// Initial state: InitialSyncPending=true
	assert.True(t, lw.InitialSyncPending)
}

func TestListWatcher_InitialSyncPending_AfterSync(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}
	lw.CurrentRevision = "100"
	lw.MarkInitialSyncComplete() // Clear the initial sync flag

	assert.False(t, lw.InitialSyncPending)
}

func TestListWatcher_InitialSyncPending_AfterReset(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}
	lw.CurrentRevision = "100"
	lw.MarkInitialSyncComplete()
	lw.ResetForFullResync()

	assert.True(t, lw.InitialSyncPending)
	assert.Equal(t, "", lw.CurrentRevision)
}

// ============================================================================
// PerformInitialSync Tests
// ============================================================================

func TestListWatcher_PerformInitialSync(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}

	// etcd uses PerformListSync internally, which requires a working client
	// We can verify the method exists and the ListWatcher implements ListWatchBackend
	var _ api.ListWatchBackend = lw

	// Verify initial state
	assert.True(t, lw.InitialSyncPending)
	assert.Equal(t, "", lw.CurrentRevision)
}

// ============================================================================
// Boundary and Edge Case Tests
// ============================================================================

func TestListWatcher_HandleWatchEvent_MissingValue(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}

	// Added without New value
	event := api.WatchEvent{Type: api.WatchAdded, New: nil}
	err := lw.HandleWatchEvent(event)
	assert.NoError(t, err)              // Handled (with error log)
	assert.Len(t, handler.addEvents, 0) // No event added

	// Modified without New value
	event = api.WatchEvent{Type: api.WatchModified, New: nil}
	err = lw.HandleWatchEvent(event)
	assert.NoError(t, err)
	assert.Len(t, handler.updateEvents, 0)

	// Deleted without Old value
	event = api.WatchEvent{Type: api.WatchDeleted, Old: nil}
	err = lw.HandleWatchEvent(event)
	assert.NoError(t, err)
	assert.Len(t, handler.deleteEvents, 0)
}

func TestListWatcher_MultipleRevisionsInSequence(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}

	// Simulate a sequence of revisions
	revisions := []string{"10", "20", "30", "40", "50"}

	for _, rev := range revisions {
		event := api.WatchEvent{
			Type: api.WatchAdded,
			New:  &model.KVPair{Key: model.GlobalConfigKey{Name: "key"}, Value: "val", Revision: rev},
		}
		err := lw.HandleWatchEvent(event)
		assert.NoError(t, err)
		assert.Equal(t, rev, lw.CurrentRevision)
	}

	assert.Equal(t, "50", lw.CurrentRevision)
	assert.Len(t, handler.addEvents, 5)
}

func TestListWatcher_ErrorCountResetOnNewRevision(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}

	// Accumulate errors at revision "100"
	lw.UpdateRevision("100")
	for i := 0; i < 3; i++ {
		lw.IncrementErrorCount()
	}
	assert.Equal(t, 3, lw.ErrorCountAtCurrentRev)

	// Update to new revision - errors should reset
	lw.UpdateRevision("200")
	assert.Equal(t, 0, lw.ErrorCountAtCurrentRev)

	// Accumulate more errors
	for i := 0; i < 2; i++ {
		lw.IncrementErrorCount()
	}
	assert.Equal(t, 2, lw.ErrorCountAtCurrentRev)
}

func TestListWatcher_ConnectionTimeoutBoundary(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}

	// Just under timeout
	lw.LastSuccessfulConnTime = time.Now().Add(-api.WatchRetryTimeout + time.Second)
	assert.False(t, lw.CheckConnectionTimeout())

	// Just over timeout
	lw.LastSuccessfulConnTime = time.Now().Add(-api.WatchRetryTimeout - time.Second)
	assert.True(t, lw.CheckConnectionTimeout())
}

// ============================================================================
// Watch Bookmark Tests (etcd doesn't use bookmarks, but verify handling)
// ============================================================================

func TestListWatcher_HandleWatchEvent_Bookmark(t *testing.T) {
	list := testListOptions()
	handler := newMockEventHandler()

	lw := &ListWatcher{
		GenericListWatcher: api.NewGenericListWatcher(list, handler),
		client:             nil,
	}

	// etcd doesn't use bookmarks, but HandleBasicWatchEvent will return false
	event := api.WatchEvent{
		Type: api.WatchBookmark,
		New:  &model.KVPair{Revision: "100"},
	}

	err := lw.HandleWatchEvent(event)

	// Bookmark is not a basic watch event, so it falls through to unknown type warning
	assert.NoError(t, err)
}
