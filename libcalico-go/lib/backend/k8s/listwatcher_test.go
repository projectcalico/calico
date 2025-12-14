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

package k8s

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// mockK8sResourceClient implements resources.K8sResourceClient for testing
type mockK8sResourceClient struct {
	listResult  *model.KVPairList
	listError   error
	watchResult api.WatchInterface
	watchError  error
}

func (m *mockK8sResourceClient) Create(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	return nil, nil
}

func (m *mockK8sResourceClient) Update(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	return nil, nil
}

func (m *mockK8sResourceClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	return nil, nil
}

func (m *mockK8sResourceClient) DeleteKVP(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	return nil, nil
}

func (m *mockK8sResourceClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	return nil, nil
}

func (m *mockK8sResourceClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	return m.listResult, m.listError
}

func (m *mockK8sResourceClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	return m.watchResult, m.watchError
}

func (m *mockK8sResourceClient) EnsureInitialized() error {
	return nil
}

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

func TestNewListWatcher(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	assert.NotNil(t, lw)
	assert.NotNil(t, lw.GenericListWatcher)
	assert.Equal(t, list, lw.List)
	assert.Equal(t, handler, lw.Handler)
	assert.True(t, lw.InitialSyncPending)
	assert.False(t, lw.fallbackToList)
	assert.Equal(t, "", lw.CurrentRevision)
}

// ============================================================================
// PerformList Tests
// ============================================================================

func TestListWatcher_PerformList_Success(t *testing.T) {
	client := &mockK8sResourceClient{
		listResult: &model.KVPairList{
			KVPairs: []*model.KVPair{
				{Key: model.GlobalConfigKey{Name: "key1"}, Value: "value1", Revision: "1"},
			},
			Revision: "100",
		},
	}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	result, err := lw.PerformList(context.Background())

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.KVPairs, 1)
	assert.Equal(t, "100", result.Revision)
}

func TestListWatcher_PerformList_Error(t *testing.T) {
	client := &mockK8sResourceClient{
		listError: errors.New("list failed"),
	}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	result, err := lw.PerformList(context.Background())

	assert.Error(t, err)
	assert.Nil(t, result)
}

// ============================================================================
// CreateWatch Tests
// ============================================================================

func TestListWatcher_CreateWatch_NormalMode(t *testing.T) {
	watcher := newMockWatcher()
	client := &mockK8sResourceClient{
		watchResult: watcher,
	}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.CurrentRevision = "100"

	// Not initial sync
	result, err := lw.CreateWatch(context.Background(), false)

	assert.NoError(t, err)
	assert.Equal(t, watcher, result)
}

func TestListWatcher_CreateWatch_InitialSync_WatchListMode(t *testing.T) {
	watcher := newMockWatcher()
	client := &mockK8sResourceClient{
		watchResult: watcher,
	}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	// Initial sync without fallback should use WatchList mode
	result, err := lw.CreateWatch(context.Background(), true)

	assert.NoError(t, err)
	assert.Equal(t, watcher, result)
}

func TestListWatcher_CreateWatch_InitialSync_FallbackMode(t *testing.T) {
	watcher := newMockWatcher()
	client := &mockK8sResourceClient{
		watchResult: watcher,
	}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.fallbackToList = true // Set fallback mode

	// Initial sync with fallback should not use WatchList options
	result, err := lw.CreateWatch(context.Background(), true)

	assert.NoError(t, err)
	assert.Equal(t, watcher, result)
}

func TestListWatcher_CreateWatch_Error(t *testing.T) {
	client := &mockK8sResourceClient{
		watchError: errors.New("watch failed"),
	}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	result, err := lw.CreateWatch(context.Background(), false)

	assert.Error(t, err)
	assert.Nil(t, result)
}

// ============================================================================
// HandleListError Tests
// ============================================================================

func TestListWatcher_HandleListError_NotFound(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	// Create a NotFound error
	notFoundErr := kerrors.NewNotFound(schema.GroupResource{Group: "test", Resource: "test"}, "test")

	lw.HandleListError(notFoundErr)

	// Should call OnSync to mark as in-sync even though API is not installed
	assert.Equal(t, 1, handler.syncCount)
	// Should schedule a long retry
	assert.True(t, lw.RetryBlockedUntil.After(time.Now().Add(29*time.Minute)))
}

func TestListWatcher_HandleListError_ResourceExpired(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.CurrentRevision = "100"

	// Create a ResourceExpired error
	expiredErr := kerrors.NewResourceExpired("resource expired")

	lw.HandleListError(expiredErr)

	// Should reset for full resync
	assert.Equal(t, "", lw.CurrentRevision)
	// Should mark successful connection (layer 7 error)
	assert.True(t, lw.LastSuccessfulConnTime.After(time.Now().Add(-1*time.Second)))
}

func TestListWatcher_HandleListError_GenericError(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	genericErr := errors.New("generic error")

	lw.HandleListError(genericErr)

	// Should schedule a retry
	assert.True(t, lw.RetryBlockedUntil.After(time.Now()))
}

func TestListWatcher_HandleListError_ConnectionTimeout(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
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

func TestListWatcher_HandleWatchError_WatchListNotSupported(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	// Create an Invalid error (indicates WatchList not supported)
	invalidErr := kerrors.NewInvalid(schema.GroupKind{Group: "test", Kind: "test"}, "test", nil)

	lw.HandleWatchError(invalidErr)

	// Should fall back to list mode
	assert.True(t, lw.fallbackToList)
}

func TestListWatcher_HandleWatchError_ResourceExpired(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.CurrentRevision = "100"

	// Create a ResourceExpired error
	expiredErr := kerrors.NewResourceExpired("resource expired")

	lw.HandleWatchError(expiredErr)

	// Should reset for full resync
	assert.Equal(t, "", lw.CurrentRevision)
	// Should mark successful connection (layer 7 error)
	assert.True(t, lw.LastSuccessfulConnTime.After(time.Now().Add(-1*time.Second)))
}

func TestListWatcher_HandleWatchError_Gone(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.CurrentRevision = "100"

	// Create a Gone error
	goneErr := kerrors.NewGone("resource gone")

	lw.HandleWatchError(goneErr)

	// Should reset for full resync
	assert.Equal(t, "", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchError_TooManyRequests(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.CurrentRevision = "100"

	// Create a TooManyRequests error
	tooManyErr := kerrors.NewTooManyRequests("too many requests", 10)

	lw.HandleWatchError(tooManyErr)

	// Should not reset revision (just retry)
	assert.Equal(t, "100", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchError_TooManyRequests_ConnectionTimeout(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.CurrentRevision = "100"
	// Set last connection to past timeout
	lw.LastSuccessfulConnTime = time.Now().Add(-api.WatchRetryTimeout - time.Second)

	// Create a TooManyRequests error
	tooManyErr := kerrors.NewTooManyRequests("too many requests", 10)

	lw.HandleWatchError(tooManyErr)

	// Should reset for full resync due to timeout
	assert.Equal(t, "", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchError_OperationNotSupported(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.CurrentRevision = "100"

	// Create an OperationNotSupported error
	notSuppErr := cerrors.ErrorOperationNotSupported{
		Operation: "watch",
	}

	lw.HandleWatchError(notSuppErr)

	// Should fall back to list mode and need initial sync
	assert.True(t, lw.fallbackToList)
	assert.True(t, lw.InitialSyncPending)
	// Should schedule a poll interval retry
	assert.True(t, lw.RetryBlockedUntil.After(time.Now()))
}

func TestListWatcher_HandleWatchError_ResourceDoesNotExist(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.CurrentRevision = "100"

	// Create a ResourceDoesNotExist error
	notExistErr := cerrors.ErrorResourceDoesNotExist{
		Identifier: "test-resource",
	}

	lw.HandleWatchError(notExistErr)

	// Should fall back to list mode and need initial sync
	assert.True(t, lw.fallbackToList)
	assert.True(t, lw.InitialSyncPending)
}

func TestListWatcher_HandleWatchError_UnknownError_ExceedsThreshold(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.CurrentRevision = "100"

	// Set error count close to threshold
	for i := 0; i < api.MaxErrorsPerRevision-1; i++ {
		lw.IncrementErrorCount()
	}

	genericErr := errors.New("unknown error")

	lw.HandleWatchError(genericErr)

	// Should reset for full resync after exceeding threshold
	assert.Equal(t, "", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchError_UnknownError_BelowThreshold(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.CurrentRevision = "100"

	genericErr := errors.New("unknown error")

	lw.HandleWatchError(genericErr)

	// Should not reset revision (below threshold)
	assert.Equal(t, "100", lw.CurrentRevision)
}

// ============================================================================
// HandleWatchEvent Tests
// ============================================================================

func TestListWatcher_HandleWatchEvent_Added(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

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
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	event := api.WatchEvent{
		Type: api.WatchModified,
		Old:  &model.KVPair{Key: model.GlobalConfigKey{Name: "test"}, Value: "old", Revision: "5"},
		New:  &model.KVPair{Key: model.GlobalConfigKey{Name: "test"}, Value: "new", Revision: "20"},
	}

	err := lw.HandleWatchEvent(event)

	assert.NoError(t, err)
	assert.Len(t, handler.updateEvents, 1)
	assert.Equal(t, "20", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchEvent_Deleted(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	event := api.WatchEvent{
		Type: api.WatchDeleted,
		Old:  &model.KVPair{Key: model.GlobalConfigKey{Name: "test"}, Value: "val", Revision: "30"},
	}

	err := lw.HandleWatchEvent(event)

	assert.NoError(t, err)
	assert.Len(t, handler.deleteEvents, 1)
	assert.Equal(t, "30", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchEvent_Bookmark(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	event := api.WatchEvent{
		Type: api.WatchBookmark,
		New:  &model.KVPair{Revision: "100"},
	}

	err := lw.HandleWatchEvent(event)

	assert.NoError(t, err)
	assert.Equal(t, "100", lw.CurrentRevision)
}

func TestListWatcher_HandleWatchEvent_Error(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
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
}

// ============================================================================
// InitialSyncPending Tests
// ============================================================================

func TestListWatcher_InitialSyncPending_Initial(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	// Initial state: InitialSyncPending=true, CurrentRevision=""
	assert.True(t, lw.InitialSyncPending)
	assert.Equal(t, "", lw.CurrentRevision)
}

func TestListWatcher_InitialSyncPending_AfterSync(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.CurrentRevision = "100"
	lw.MarkInitialSyncComplete()

	assert.False(t, lw.InitialSyncPending)
}

func TestListWatcher_InitialSyncPending_AfterReset(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.CurrentRevision = "100"
	lw.MarkInitialSyncComplete()
	lw.ResetForFullResync()

	assert.True(t, lw.InitialSyncPending)
	assert.Equal(t, "", lw.CurrentRevision)
}

// ============================================================================
// PerformInitialSync Tests
// ============================================================================

func TestListWatcher_PerformInitialSync_WatchListMode(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	// WatchList mode (default)
	err := lw.PerformInitialSync(context.Background(), lw.GenericListWatcher)

	assert.NoError(t, err)
	assert.Equal(t, 1, handler.resyncStartedCt)
	assert.Equal(t, 0, handler.syncCount) // Sync is signaled by bookmark, not here
}

func TestListWatcher_PerformInitialSync_FallbackMode(t *testing.T) {
	client := &mockK8sResourceClient{
		listResult: &model.KVPairList{
			KVPairs: []*model.KVPair{
				{Key: model.GlobalConfigKey{Name: "key1"}, Value: "value1", Revision: "1"},
			},
			Revision: "100",
		},
	}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.fallbackToList = true

	// Fallback to List+Watch mode
	err := lw.PerformInitialSync(context.Background(), lw.GenericListWatcher)

	assert.NoError(t, err)
	assert.Equal(t, 1, handler.resyncStartedCt)
	assert.Equal(t, 1, handler.syncCount)
	assert.Len(t, handler.addEvents, 1)
	assert.Equal(t, "100", lw.CurrentRevision)
	assert.False(t, lw.InitialSyncPending)
}

// ============================================================================
// Bookmark Handling Tests
// ============================================================================

// mockResource implements resources.Resource for testing bookmark handling
type mockResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
}

// Ensure mockResource implements resources.Resource
var _ resources.Resource = (*mockResource)(nil)

func (m *mockResource) GetObjectKind() schema.ObjectKind {
	return &m.TypeMeta
}

func (m *mockResource) DeepCopyObject() runtime.Object {
	if m == nil {
		return nil
	}
	out := new(mockResource)
	m.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.TypeMeta = m.TypeMeta
	return out
}

func TestListWatcher_HandleBookmark_WithInitialEventsAnnotation(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	// Create a bookmark event with InitialEventsAnnotationKey
	resource := &mockResource{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				metav1.InitialEventsAnnotationKey: "true",
			},
		},
	}

	event := api.WatchEvent{
		Type: api.WatchBookmark,
		New:  &model.KVPair{Revision: "100", Value: resource},
	}

	err := lw.HandleWatchEvent(event)

	assert.NoError(t, err)
	assert.Equal(t, "100", lw.CurrentRevision)
	assert.Equal(t, 1, handler.syncCount) // OnSync should be called
	assert.False(t, lw.InitialSyncPending)
}

func TestListWatcher_HandleBookmark_WithoutInitialEventsAnnotation(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	// Create a bookmark event without InitialEventsAnnotationKey
	event := api.WatchEvent{
		Type: api.WatchBookmark,
		New:  &model.KVPair{Revision: "100"},
	}

	err := lw.HandleWatchEvent(event)

	assert.NoError(t, err)
	assert.Equal(t, "100", lw.CurrentRevision)
	assert.Equal(t, 0, handler.syncCount) // OnSync should NOT be called
	assert.True(t, lw.InitialSyncPending) // Still needs initial sync
}

// ============================================================================
// Integration-like Tests
// ============================================================================

func TestListWatcher_FullListThenWatch_Flow(t *testing.T) {
	watcher := newMockWatcher()
	client := &mockK8sResourceClient{
		listResult: &model.KVPairList{
			KVPairs: []*model.KVPair{
				{Key: model.GlobalConfigKey{Name: "key1"}, Value: "value1", Revision: "1"},
				{Key: model.GlobalConfigKey{Name: "key2"}, Value: "value2", Revision: "2"},
			},
			Revision: "100",
		},
		watchResult: watcher,
	}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)
	lw.fallbackToList = true // Force list-then-watch mode

	// Perform the initial sync using PerformInitialSync
	err := lw.PerformInitialSync(context.Background(), lw.GenericListWatcher)

	assert.NoError(t, err)
	assert.Equal(t, 1, handler.resyncStartedCt)
	assert.Equal(t, 1, handler.syncCount)
	assert.Len(t, handler.addEvents, 2)
	assert.Equal(t, "100", lw.CurrentRevision)
	assert.False(t, lw.InitialSyncPending)
}

func TestListWatcher_WatchListMode_Flow(t *testing.T) {
	client := &mockK8sResourceClient{}
	list := testListOptions()
	handler := newMockEventHandler()

	lw := NewListWatcher(client, list, handler)

	// Perform the initial sync using WatchList mode
	err := lw.PerformInitialSync(context.Background(), lw.GenericListWatcher)

	assert.NoError(t, err)
	assert.Equal(t, 1, handler.resyncStartedCt)
	assert.Equal(t, 0, handler.syncCount) // Sync is signaled by bookmark, not here
	assert.True(t, lw.InitialSyncPending) // Still true until bookmark received
}
