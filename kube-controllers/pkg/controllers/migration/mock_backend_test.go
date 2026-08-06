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

package migration

import (
	"context"
	"fmt"
	"sync"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

// TODO: Remove this mock when the backend client supports injecting client mocks.
//
// mockBackendClient fakes the libcalico-go backend client (api.Client) for
// v1 resource data. Only List, Get, and Update are implemented; the rest
// panic via the embedded interface.
type mockBackendClient struct {
	bapi.Client
	resources   map[string][]*model.KVPair
	clusterInfo *model.KVPair

	// mu guards clusterInfo and the error-injection fields for concurrent
	// access from the controller goroutine and test assertions.
	mu sync.Mutex

	// listErrors maps a Kind to an error that List should return for that
	// kind. Used to simulate backend failures during migration. The error
	// is only returned after the kind has been listed successfully
	// listErrorAfter times (to allow RBAC pre-checks and conflict detection
	// to pass first).
	listErrors     map[string]error
	listErrorAfter int
	listCounts     map[string]int

	// clusterInfoGetErr and clusterInfoUpdateErr, when set, are returned from
	// Get/Update for the ClusterInformation resource.
	clusterInfoGetErr    error
	clusterInfoUpdateErr error

	// events, when set, records v1 datastore locks so tests can assert on the
	// order of the controller's side effects.
	events *orderLog
}

// getClusterInfo returns a copy of the stored v1 ClusterInformation KVPair, so callers
// can read it without racing the controller goroutine.
func (m *mockBackendClient) getClusterInfo() *model.KVPair {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.clusterInfo == nil {
		return nil
	}
	copied := *m.clusterInfo
	if ci, ok := m.clusterInfo.Value.(*apiv3.ClusterInformation); ok {
		copied.Value = ci.DeepCopy()
	}
	return &copied
}

// listCount returns the number of times List has been called for a kind.
func (m *mockBackendClient) listCount(kind string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listCounts[kind]
}

func (m *mockBackendClient) List(_ context.Context, list model.ListInterface, _ string) (*model.KVPairList, error) {
	switch list.(type) {
	case model.BlockListOptions:
		return &model.KVPairList{}, nil
	case model.IPAMHandleListOptions:
		return &model.KVPairList{}, nil
	default:
		rlo := list.(model.ResourceListOptions)
		m.mu.Lock()
		if m.listCounts == nil {
			m.listCounts = make(map[string]int)
		}
		m.listCounts[rlo.Kind]++
		if m.listErrors != nil {
			if err, ok := m.listErrors[rlo.Kind]; ok && m.listCounts[rlo.Kind] > m.listErrorAfter {
				m.mu.Unlock()
				return nil, err
			}
		}
		m.mu.Unlock()
		kvps := m.resources[rlo.Kind]
		if rlo.Kind == apiv3.KindTier {
			kvps = defaultTierKVPs(kvps)
		}
		return &model.KVPairList{KVPairs: kvps}, nil
	}
}

// defaultTierKVPs applies the defaulting the real backend does on the tier read
// path, so tests see the shape production sees.
func defaultTierKVPs(kvps []*model.KVPair) []*model.KVPair {
	out := make([]*model.KVPair, 0, len(kvps))
	for _, kvp := range kvps {
		tier, ok := kvp.Value.(*apiv3.Tier)
		if !ok {
			out = append(out, kvp)
			continue
		}
		defaulted := tier.DeepCopy()
		resources.DefaultTierFields(defaulted)
		copied := *kvp
		copied.Value = defaulted
		out = append(out, &copied)
	}
	return out
}

func (m *mockBackendClient) Get(_ context.Context, key model.Key, _ string) (*model.KVPair, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rk, ok := key.(model.ResourceKey)
	if ok && rk.Kind == apiv3.KindClusterInformation {
		if m.clusterInfoGetErr != nil {
			return nil, m.clusterInfoGetErr
		}
		if m.clusterInfo != nil {
			return m.clusterInfo, nil
		}
	}
	return nil, fmt.Errorf("not found: %v", key)
}

func (m *mockBackendClient) Update(_ context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rk, ok := kvp.Key.(model.ResourceKey)
	if ok && rk.Kind == apiv3.KindClusterInformation {
		if m.clusterInfoUpdateErr != nil {
			return nil, m.clusterInfoUpdateErr
		}
		m.clusterInfo = kvp
		if m.events != nil {
			if ci, ok := kvp.Value.(*apiv3.ClusterInformation); ok && ci.Spec.DatastoreReady != nil && !*ci.Spec.DatastoreReady {
				m.events.record(eventLockV1)
			}
		}
		return kvp, nil
	}
	return nil, fmt.Errorf("not found: %v", kvp.Key)
}
