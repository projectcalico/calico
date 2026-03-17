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
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

func withTestRegistry(t *testing.T, migrators []ResourceMigrator) {
	t.Helper()
	registryMu.Lock()
	saved := registry
	registry = migrators
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry = saved
		registryMu.Unlock()
	})
}

func tierMigrator() ResourceMigrator {
	return ResourceMigrator{
		Kind:         apiv3.KindTier,
		Order:        OrderTiers,
		V3Object:     func() rtclient.Object { return &apiv3.Tier{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.TierList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.Tier).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.Tier)
			v3 := &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	}
}

func gnpMigrator() ResourceMigrator {
	return ResourceMigrator{
		Kind:         apiv3.KindGlobalNetworkPolicy,
		Order:        OrderPolicy,
		V3Object:     func() rtclient.Object { return &apiv3.GlobalNetworkPolicy{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.GlobalNetworkPolicyList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.GlobalNetworkPolicy).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindGlobalNetworkPolicy)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.GlobalNetworkPolicy)
			v3Name := migratedPolicyName(v1.Name, v1.Spec.Tier)
			v3 := &apiv3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: v3Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	}
}

func felixConfigMigrator() ResourceMigrator {
	return ResourceMigrator{
		Kind:         apiv3.KindFelixConfiguration,
		Order:        OrderConfigSingletons,
		V3Object:     func() rtclient.Object { return &apiv3.FelixConfiguration{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.FelixConfigurationList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.FelixConfiguration).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindFelixConfiguration)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.FelixConfiguration)
			v3 := &apiv3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	}
}

func ipPoolMigrator() ResourceMigrator {
	return ResourceMigrator{
		Kind:         apiv3.KindIPPool,
		Order:        OrderNetworkInfra,
		V3Object:     func() rtclient.Object { return &apiv3.IPPool{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.IPPoolList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.IPPool).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindIPPool)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.IPPool)
			v3 := &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	}
}

func bgpPeerMigrator() ResourceMigrator {
	return ResourceMigrator{
		Kind:         apiv3.KindBGPPeer,
		Order:        OrderNetworkInfra,
		V3Object:     func() rtclient.Object { return &apiv3.BGPPeer{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.BGPPeerList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.BGPPeer).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindBGPPeer)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.BGPPeer)
			v3 := &apiv3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	}
}

func testTierMigrator() ResourceMigrator {
	return ResourceMigrator{
		Kind:         apiv3.KindTier,
		Order:        OrderTiers,
		V3Object:     func() rtclient.Object { return &apiv3.Tier{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.TierList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.Tier).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.Tier)
			return &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}, nil
		},
	}
}

type mockBackendClient struct {
	api.Client
	resources   map[string][]*model.KVPair
	ipamBlocks  []*model.KVPair
	ipamHandles []*model.KVPair
	clusterInfo *model.KVPair
}

func (m *mockBackendClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	switch list.(type) {
	case model.BlockListOptions:
		return &model.KVPairList{KVPairs: m.ipamBlocks}, nil
	case model.IPAMHandleListOptions:
		return &model.KVPairList{KVPairs: m.ipamHandles}, nil
	default:
		rlo := list.(model.ResourceListOptions)
		kvps := m.resources[rlo.Kind]
		return &model.KVPairList{KVPairs: kvps}, nil
	}
}

func (m *mockBackendClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	rk, ok := key.(model.ResourceKey)
	if ok && rk.Kind == apiv3.KindClusterInformation && m.clusterInfo != nil {
		return m.clusterInfo, nil
	}
	return nil, fmt.Errorf("not found: %v", key)
}

func (m *mockBackendClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	rk, ok := kvp.Key.(model.ResourceKey)
	if ok && rk.Kind == apiv3.KindClusterInformation {
		m.clusterInfo = kvp
		return kvp, nil
	}
	return nil, fmt.Errorf("not found: %v", kvp.Key)
}

type uidAssigningClient struct {
	rtclient.Client
}

func (u *uidAssigningClient) Create(ctx context.Context, obj rtclient.Object, opts ...rtclient.CreateOption) error {
	if obj.GetUID() == "" {
		key := obj.GetName()
		if obj.GetNamespace() != "" {
			key = obj.GetNamespace() + "/" + key
		}
		obj.SetUID(types.UID("v3-uid-" + key))
	}
	return u.Client.Create(ctx, obj, opts...)
}

type retryTestClient struct {
	rtclient.Client
	createCalls *int
}

func (r *retryTestClient) Create(ctx context.Context, obj rtclient.Object, opts ...rtclient.CreateOption) error {
	*r.createCalls++
	if *r.createCalls == 1 {
		return kerrors.NewServiceUnavailable("transient")
	}
	return r.Client.Create(ctx, obj, opts...)
}
