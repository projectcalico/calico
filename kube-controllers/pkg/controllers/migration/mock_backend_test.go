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

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
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
}

func (m *mockBackendClient) List(_ context.Context, list model.ListInterface, _ string) (*model.KVPairList, error) {
	switch list.(type) {
	case model.BlockListOptions:
		return &model.KVPairList{}, nil
	case model.IPAMHandleListOptions:
		return &model.KVPairList{}, nil
	default:
		rlo := list.(model.ResourceListOptions)
		return &model.KVPairList{KVPairs: m.resources[rlo.Kind]}, nil
	}
}

func (m *mockBackendClient) Get(_ context.Context, key model.Key, _ string) (*model.KVPair, error) {
	rk, ok := key.(model.ResourceKey)
	if ok && rk.Kind == apiv3.KindClusterInformation && m.clusterInfo != nil {
		return m.clusterInfo, nil
	}
	return nil, fmt.Errorf("not found: %v", key)
}

func (m *mockBackendClient) Update(_ context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	rk, ok := kvp.Key.(model.ResourceKey)
	if ok && rk.Kind == apiv3.KindClusterInformation {
		m.clusterInfo = kvp
		return kvp, nil
	}
	return nil, fmt.Errorf("not found: %v", kvp.Key)
}
