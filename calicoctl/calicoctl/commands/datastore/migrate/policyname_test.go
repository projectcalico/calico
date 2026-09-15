// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package migrate

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	liberr "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

func gnp(storedName, tier string) *model.KVPair {
	name := storedName
	if tier == "" || tier == "default" {
		name = trimDefaultPrefix(storedName)
	}
	return &model.KVPair{
		Key: model.ResourceKey{Kind: v3.KindGlobalNetworkPolicy, Name: storedName},
		Value: &v3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       v3.GlobalNetworkPolicySpec{Tier: tier},
		},
	}
}

func np(namespace, storedName string) *model.KVPair {
	return &model.KVPair{
		Key: model.ResourceKey{Kind: v3.KindNetworkPolicy, Namespace: namespace, Name: storedName},
		Value: &v3.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: trimDefaultPrefix(storedName)},
		},
	}
}

func trimDefaultPrefix(name string) string {
	if len(name) > len("default.") && name[:len("default.")] == "default." {
		return name[len("default."):]
	}
	return name
}

func TestMigratePolicyNames(t *testing.T) {
	g := NewWithT(t)

	// Backend state as the etcdv3 driver presents it after an in-place upgrade to
	// v3.32: legacy default-tier policies keep their "default."-prefixed datastore
	// key while their decoded v3 name is bare, so Key.Name and ObjectMeta.Name diverge.
	bc := newFakeBackend(
		gnp("default.legacy-gnp", ""),  // needs migration -> "legacy-gnp"
		gnp("already-bare", "default"), // already aligned, leave alone
		np("ns1", "default.legacy-np"), // namespaced, needs migration -> "legacy-np"
		// Non-default tier with a mismatched name should be left alone: only the
		// default tier ever had the prefix sneak-in that produced the mismatch.
		&model.KVPair{
			Key: model.ResourceKey{Kind: v3.KindGlobalNetworkPolicy, Name: "sec.stale"},
			Value: &v3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "sec.renamed"},
				Spec:       v3.GlobalNetworkPolicySpec{Tier: "sec"},
			},
		},
	)

	migrated, err := migratePolicyNames(context.Background(), bc)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(migrated).To(Equal(2))

	g.Expect(bc.has(model.ResourceKey{Kind: v3.KindGlobalNetworkPolicy, Name: "legacy-gnp"})).To(BeTrue(), "new bare GNP key should exist")
	g.Expect(bc.has(model.ResourceKey{Kind: v3.KindGlobalNetworkPolicy, Name: "default.legacy-gnp"})).To(BeFalse(), "old prefixed GNP key should be gone")

	g.Expect(bc.has(model.ResourceKey{Kind: v3.KindNetworkPolicy, Namespace: "ns1", Name: "legacy-np"})).To(BeTrue(), "new bare NP key should exist")
	g.Expect(bc.has(model.ResourceKey{Kind: v3.KindNetworkPolicy, Namespace: "ns1", Name: "default.legacy-np"})).To(BeFalse(), "old prefixed NP key should be gone")

	g.Expect(bc.has(model.ResourceKey{Kind: v3.KindGlobalNetworkPolicy, Name: "already-bare"})).To(BeTrue(), "aligned policy should be untouched")
	g.Expect(bc.has(model.ResourceKey{Kind: v3.KindGlobalNetworkPolicy, Name: "sec.stale"})).To(BeTrue(), "non-default tier policy should be untouched")

	// Re-running is a no-op: the datastore is already aligned.
	migrated, err = migratePolicyNames(context.Background(), bc)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(migrated).To(Equal(0))
}

// fakeBackend is an in-memory bapi.Client that stores KVPairs keyed by their
// default datastore path, so Create/DeleteKVP/List interact like the real thing.
type fakeBackend struct {
	store map[string]*model.KVPair
}

func newFakeBackend(kvps ...*model.KVPair) *fakeBackend {
	b := &fakeBackend{store: map[string]*model.KVPair{}}
	for _, kvp := range kvps {
		path, err := model.KeyToDefaultPath(kvp.Key)
		if err != nil {
			panic(err)
		}
		b.store[path] = kvp
	}
	return b
}

func (b *fakeBackend) has(key model.Key) bool {
	path, err := model.KeyToDefaultPath(key)
	if err != nil {
		panic(err)
	}
	_, ok := b.store[path]
	return ok
}

func (b *fakeBackend) Create(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	path, err := model.KeyToDefaultPath(object.Key)
	if err != nil {
		return nil, err
	}
	if _, ok := b.store[path]; ok {
		return nil, liberr.ErrorResourceAlreadyExists{Identifier: object.Key}
	}
	b.store[path] = object
	return object, nil
}

func (b *fakeBackend) DeleteKVP(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	path, err := model.KeyToDefaultPath(object.Key)
	if err != nil {
		return nil, err
	}
	if _, ok := b.store[path]; !ok {
		return nil, liberr.ErrorResourceDoesNotExist{Identifier: object.Key}
	}
	delete(b.store, path)
	return object, nil
}

func (b *fakeBackend) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	opts, ok := list.(model.ResourceListOptions)
	if !ok {
		return &model.KVPairList{}, nil
	}
	out := &model.KVPairList{}
	for _, kvp := range b.store {
		k, ok := kvp.Key.(model.ResourceKey)
		if !ok {
			continue
		}
		if k.Kind == opts.Kind {
			out.KVPairs = append(out.KVPairs, kvp)
		}
	}
	return out, nil
}

func (b *fakeBackend) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	return nil, nil
}

func (b *fakeBackend) Update(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	return object, nil
}

func (b *fakeBackend) Apply(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	return object, nil
}

func (b *fakeBackend) Delete(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	return nil, nil
}

func (b *fakeBackend) Watch(ctx context.Context, list model.ListInterface, options bapi.WatchOptions) (bapi.WatchInterface, error) {
	return bapi.NewFake(), nil
}

func (b *fakeBackend) EnsureInitialized() error {
	return nil
}

func (b *fakeBackend) Clean() error {
	return nil
}

func (b *fakeBackend) Close() error {
	return nil
}
