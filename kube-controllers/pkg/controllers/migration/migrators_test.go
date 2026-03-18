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
	"reflect"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/migration/migrators"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

func withTestRegistry(t *testing.T, ms []migrators.ResourceMigrator) {
	t.Helper()
	registryMu.Lock()
	saved := registry
	registry = ms
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry = saved
		registryMu.Unlock()
	})
}

func tierMigrator(bc bapi.Client, rt rtclient.Client) migrators.ResourceMigrator {
	return newTestMigrator(apiv3.KindTier, OrderTiers, bc, rt,
		func() rtclient.Object { return &apiv3.Tier{} },
		func() rtclient.ObjectList { return &apiv3.TierList{} },
		func(obj rtclient.Object) any { return obj.(*apiv3.Tier).Spec },
		func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.Tier)
			v3 := v1.DeepCopy()
			v3.ResourceVersion = ""
			v3.CreationTimestamp = metav1.Time{}
			v3.ManagedFields = nil
			v3.Generation = 0
			filterInternalAnnotations(v3)
			return v3, nil
		},
	)
}

func gnpMigrator(bc bapi.Client, rt rtclient.Client) migrators.ResourceMigrator {
	return newTestMigrator(apiv3.KindGlobalNetworkPolicy, OrderPolicy, bc, rt,
		func() rtclient.Object { return &apiv3.GlobalNetworkPolicy{} },
		func() rtclient.ObjectList { return &apiv3.GlobalNetworkPolicyList{} },
		func(obj rtclient.Object) any { return obj.(*apiv3.GlobalNetworkPolicy).Spec },
		func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.GlobalNetworkPolicy)
			v3Name := migratedPolicyName(v1.Name, v1.Spec.Tier)
			v3 := v1.DeepCopy()
			v3.Name = v3Name
			v3.ResourceVersion = ""
			v3.CreationTimestamp = metav1.Time{}
			v3.ManagedFields = nil
			v3.Generation = 0
			filterInternalAnnotations(v3)
			return v3, nil
		},
	)
}

func felixConfigMigrator(bc bapi.Client, rt rtclient.Client) migrators.ResourceMigrator {
	return newTestMigrator(apiv3.KindFelixConfiguration, OrderConfigSingletons, bc, rt,
		func() rtclient.Object { return &apiv3.FelixConfiguration{} },
		func() rtclient.ObjectList { return &apiv3.FelixConfigurationList{} },
		func(obj rtclient.Object) any { return obj.(*apiv3.FelixConfiguration).Spec },
		func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.FelixConfiguration)
			v3 := v1.DeepCopy()
			v3.ResourceVersion = ""
			v3.CreationTimestamp = metav1.Time{}
			v3.ManagedFields = nil
			v3.Generation = 0
			filterInternalAnnotations(v3)
			return v3, nil
		},
	)
}

func ipPoolMigrator(bc bapi.Client, rt rtclient.Client) migrators.ResourceMigrator {
	return newTestMigrator(apiv3.KindIPPool, OrderNetworkInfra, bc, rt,
		func() rtclient.Object { return &apiv3.IPPool{} },
		func() rtclient.ObjectList { return &apiv3.IPPoolList{} },
		func(obj rtclient.Object) any { return obj.(*apiv3.IPPool).Spec },
		func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.IPPool)
			v3 := v1.DeepCopy()
			v3.ResourceVersion = ""
			v3.CreationTimestamp = metav1.Time{}
			v3.ManagedFields = nil
			v3.Generation = 0
			filterInternalAnnotations(v3)
			return v3, nil
		},
	)
}

func bgpPeerMigrator(bc bapi.Client, rt rtclient.Client) migrators.ResourceMigrator {
	return newTestMigrator(apiv3.KindBGPPeer, OrderNetworkInfra, bc, rt,
		func() rtclient.Object { return &apiv3.BGPPeer{} },
		func() rtclient.ObjectList { return &apiv3.BGPPeerList{} },
		func(obj rtclient.Object) any { return obj.(*apiv3.BGPPeer).Spec },
		func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.BGPPeer)
			v3 := v1.DeepCopy()
			v3.ResourceVersion = ""
			v3.CreationTimestamp = metav1.Time{}
			v3.ManagedFields = nil
			v3.Generation = 0
			filterInternalAnnotations(v3)
			return v3, nil
		},
	)
}

// testMigrator implements migrators.ResourceMigrator for unit tests.
type testMigrator struct {
	kind       string
	order      int
	bc         bapi.Client
	rt         rtclient.Client
	convertFn  func(kvp *model.KVPair) (rtclient.Object, error)
	newObj     func() rtclient.Object
	newObjList func() rtclient.ObjectList
	getSpecFn  func(obj rtclient.Object) any
}

func newTestMigrator(
	kind string, order int,
	bc bapi.Client, rt rtclient.Client,
	newObj func() rtclient.Object,
	newObjList func() rtclient.ObjectList,
	getSpecFn func(obj rtclient.Object) any,
	convertFn func(kvp *model.KVPair) (rtclient.Object, error),
) *testMigrator {
	return &testMigrator{
		kind:       kind,
		order:      order,
		bc:         bc,
		rt:         rt,
		convertFn:  convertFn,
		newObj:     newObj,
		newObjList: newObjList,
		getSpecFn:  getSpecFn,
	}
}

func (m *testMigrator) Kind() string { return m.kind }
func (m *testMigrator) Order() int   { return m.order }

func (m *testMigrator) ListV1(ctx context.Context) ([]rtclient.Object, error) {
	kvpList, err := m.bc.List(ctx, model.ResourceListOptions{Kind: m.kind}, "")
	if err != nil {
		return nil, err
	}
	result := make([]rtclient.Object, 0, len(kvpList.KVPairs))
	for _, kvp := range kvpList.KVPairs {
		obj, err := m.convertFn(kvp)
		if err != nil {
			return nil, fmt.Errorf("converting %s: %w", m.kind, err)
		}
		result = append(result, obj)
	}
	return result, nil
}

func (m *testMigrator) GetV3(ctx context.Context, name, namespace string) (rtclient.Object, error) {
	obj := m.newObj()
	err := m.rt.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, obj)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return obj, nil
}

func (m *testMigrator) CreateV3(ctx context.Context, obj rtclient.Object) error {
	return m.rt.Create(ctx, obj)
}

func (m *testMigrator) UpdateV3(ctx context.Context, obj rtclient.Object) error {
	return m.rt.Update(ctx, obj)
}

func (m *testMigrator) ListV3(ctx context.Context) ([]rtclient.Object, error) {
	list := m.newObjList()
	if err := m.rt.List(ctx, list); err != nil {
		return nil, err
	}
	var result []rtclient.Object
	_ = meta.EachListItem(list, func(obj runtime.Object) error {
		if o, ok := obj.(rtclient.Object); ok {
			result = append(result, o)
		}
		return nil
	})
	return result, nil
}

func (m *testMigrator) DeleteV3(ctx context.Context, obj rtclient.Object) error {
	return m.rt.Delete(ctx, obj)
}

func (m *testMigrator) SpecsEqual(a, b rtclient.Object) bool {
	return reflect.DeepEqual(m.getSpecFn(a), m.getSpecFn(b))
}

// testTierMigrator returns a minimal tier migrator for standalone registry tests.
func testTierMigrator(bc bapi.Client, rt rtclient.Client) *testMigrator {
	return newTestMigrator(apiv3.KindTier, OrderTiers, bc, rt,
		func() rtclient.Object { return &apiv3.Tier{} },
		func() rtclient.ObjectList { return &apiv3.TierList{} },
		func(obj rtclient.Object) any { return obj.(*apiv3.Tier).Spec },
		func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.Tier)
			return &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name, UID: v1.UID},
				Spec:       *v1.Spec.DeepCopy(),
			}, nil
		},
	)
}

type mockBackendClient struct {
	bapi.Client
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
