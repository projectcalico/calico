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

package rest_test

import (
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"
	"k8s.io/client-go/tools/cache"

	calicorest "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/rest"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/server"
)

type decoration struct {
	resourcePrefix string
	reverseKeyFunc storage.ReverseKeyFunc
	newFunc        func() runtime.Object
}

type recordingGetter struct {
	decorations []decoration
}

func (g *recordingGetter) GetRESTOptions(resource schema.GroupResource, _ runtime.Object) (generic.RESTOptions, error) {
	return generic.RESTOptions{
		StorageConfig:  &storagebackend.ConfigForResource{},
		ResourcePrefix: resource.Group + "/" + resource.Resource,
		Decorator: func(
			_ *storagebackend.ConfigForResource,
			resourcePrefix string,
			_ generic.CacheKeyFunc,
			reverseKeyFunc storage.ReverseKeyFunc,
			newFunc func() runtime.Object,
			_ func() runtime.Object,
			_ storage.AttrFunc,
			_ storage.IndexerFuncs,
			_ *cache.Indexers,
		) (storage.Interface, factory.DestroyFunc, error) {
			g.decorations = append(g.decorations, decoration{resourcePrefix, reverseKeyFunc, newFunc})
			return nil, func() {}, nil
		},
	}, nil
}

// The etcd watch cache recovers object identity from the storage key alone
// when watching without previous values, so every decorated storage, status
// storages included, must reverse the keys its registry store writes.
func TestEtcdStorageReverseKeyFuncsRoundTrip(t *testing.T) {
	getter := &recordingGetter{}
	provider := calicorest.RESTStorageProvider{StorageType: server.StorageTypeEtcd}
	storages, err := provider.NewV3Storage(runtime.NewScheme(), getter, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewV3Storage: %v", err)
	}
	if len(getter.decorations) == 0 {
		t.Fatal("no storage was decorated")
	}

	// A status store copies its main store, so it writes the same keys.
	stores := map[reflect.Type]*registry.Store{}
	for _, s := range storages {
		if store := registryStore(s); store != nil {
			stores[reflect.TypeOf(store.NewFunc())] = store
		}
	}

	ctx := genericapirequest.WithNamespace(genericapirequest.NewContext(), "ns-a")
	for _, d := range getter.decorations {
		store, ok := stores[reflect.TypeOf(d.newFunc())]
		if !ok {
			t.Errorf("%s: no registry store writes this type", d.resourcePrefix)
			continue
		}
		key, err := store.KeyFunc(ctx, "obj-a")
		if err != nil {
			t.Fatalf("%s: key func: %v", d.resourcePrefix, err)
		}
		// Known issue: the store's keys lack the leading slash that resourcePrefix
		// carries, and the etcd store rejects keys outside its prefix, so etcd
		// storage mode cannot work yet. Pin that mismatch instead of hiding it,
		// and check the reverse function against the key a fixed store writes.
		if strings.HasPrefix(key, d.resourcePrefix+"/") {
			t.Errorf("%s: store key %q now carries the resource prefix: drop the known-issue handling here", d.resourcePrefix, key)
		} else if !strings.HasPrefix("/"+key, d.resourcePrefix+"/") {
			t.Errorf("%s: store key %q is outside the resource prefix, even with the missing slash added", d.resourcePrefix, key)
			continue
		} else {
			key = "/" + key
		}
		if d.reverseKeyFunc == nil {
			t.Errorf("%s: no reverse key func", d.resourcePrefix)
			continue
		}
		name, namespace, err := d.reverseKeyFunc(key)
		if err != nil {
			t.Errorf("%s: reverse of %q: %v", d.resourcePrefix, key, err)
			continue
		}
		wantNamespace := ""
		if store.NamespaceScoped() {
			wantNamespace = "ns-a"
		}
		if name != "obj-a" || namespace != wantNamespace {
			t.Errorf("%s: reverse of %q = (%q, %q), want (%q, %q)", d.resourcePrefix, key, name, namespace, "obj-a", wantNamespace)
		}
	}
}

// registryStore follows the exported, embedded Store fields that wrap a
// registry.Store, and returns nil for storages that do not wrap one.
func registryStore(s any) *registry.Store {
	v := reflect.ValueOf(s)
	for v.IsValid() {
		if store, ok := v.Interface().(*registry.Store); ok {
			return store
		}
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return nil
			}
			v = v.Elem()
		}
		if v.Kind() != reflect.Struct {
			return nil
		}
		v = v.FieldByName("Store")
	}
	return nil
}
