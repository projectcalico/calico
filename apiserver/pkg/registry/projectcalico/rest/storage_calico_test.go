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
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"
	"k8s.io/client-go/tools/cache"

	calicorest "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/rest"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/server"
)

type decoration struct {
	resourcePrefix string
	keyFunc        generic.CacheKeyFunc
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
			keyFunc generic.CacheKeyFunc,
			reverseKeyFunc storage.ReverseKeyFunc,
			newFunc func() runtime.Object,
			_ func() runtime.Object,
			_ storage.AttrFunc,
			_ storage.IndexerFuncs,
			_ *cache.Indexers,
		) (storage.Interface, factory.DestroyFunc, error) {
			g.decorations = append(g.decorations, decoration{resourcePrefix, keyFunc, reverseKeyFunc, newFunc})
			return nil, func() {}, nil
		},
	}, nil
}

// The etcd watch cache recovers object identity from the storage key alone
// when watching without previous values, so every resource must pass a reverse
// key function that undoes its key function.
func TestEtcdStorageReverseKeyFuncsRoundTrip(t *testing.T) {
	getter := &recordingGetter{}
	provider := calicorest.RESTStorageProvider{StorageType: server.StorageTypeEtcd}
	if _, err := provider.NewV3Storage(runtime.NewScheme(), getter, nil, nil, nil); err != nil {
		t.Fatalf("NewV3Storage: %v", err)
	}
	if len(getter.decorations) == 0 {
		t.Fatal("no storage was decorated")
	}

	for _, d := range getter.decorations {
		obj := d.newFunc()
		accessor, err := meta.Accessor(obj)
		if err != nil {
			t.Fatalf("%s: %v", d.resourcePrefix, err)
		}
		accessor.SetName("obj-a")
		accessor.SetNamespace("ns-a")

		key, err := d.keyFunc(obj)
		if err != nil {
			t.Fatalf("%s: key func: %v", d.resourcePrefix, err)
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
		if strings.Contains(key, "/ns-a/") {
			wantNamespace = "ns-a"
		}
		if name != "obj-a" || namespace != wantNamespace {
			t.Errorf("%s: reverse of %q = (%q, %q), want (%q, %q)", d.resourcePrefix, key, name, namespace, "obj-a", wantNamespace)
		}
	}
}
