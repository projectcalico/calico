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

package migrators

import (
	"context"
	"fmt"
	"reflect"

	"github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// ResourceMigrator defines how to migrate a single resource type from v1 to v3 CRDs.
type ResourceMigrator interface {
	Kind() string
	Order() int
	ListV1(ctx context.Context) ([]client.Object, error)
	GetV3(ctx context.Context, name, namespace string) (client.Object, error)
	CreateV3(ctx context.Context, obj client.Object) error
	UpdateV3(ctx context.Context, obj client.Object) error
	ListV3(ctx context.Context) ([]client.Object, error)
	DeleteV3(ctx context.Context, obj client.Object) error
	SpecsEqual(a, b client.Object) bool
}

// resourceMigrator is a generic implementation of ResourceMigrator.
// T is the value type (e.g., apiv3.Tier), TList is the list type (e.g., apiv3.TierList).
type resourceMigrator[T any, TList any] struct {
	kind     string
	order    int
	bcClient api.Client
	rtClient client.Client
	convert  func(*model.KVPair) (*T, error)
	listOpts model.ListInterface
}

// New creates a ResourceMigrator for the given type. If no WithConvert option
// is provided, the default deep-copy-and-clean conversion is used.
func New[T any, TList any](
	kind string,
	order int,
	bcClient api.Client,
	rtClient client.Client,
	opts ...Option,
) ResourceMigrator {
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}

	m := &resourceMigrator[T, TList]{
		kind:     kind,
		order:    order,
		bcClient: bcClient,
		rtClient: rtClient,
		listOpts: model.ResourceListOptions{Kind: kind},
	}

	if cfg.listOpts != nil {
		m.listOpts = cfg.listOpts
	}

	if cfg.convert != nil {
		fn, ok := cfg.convert.(func(*model.KVPair) (*T, error))
		if !ok {
			panic(fmt.Sprintf("WithConvert function has wrong type for %s: expected func(*model.KVPair) (*%s, error)", kind, reflect.TypeOf((*T)(nil)).Elem().Name()))
		}
		m.convert = fn
	} else {
		m.convert = defaultConvert[T]
	}

	return m
}

func (m *resourceMigrator[T, TList]) Kind() string { return m.kind }
func (m *resourceMigrator[T, TList]) Order() int   { return m.order }

// ListV1 lists all v1 resources and converts them to v3 objects. The returned
// objects retain the v1 UID and OwnerReferences so MigrateResourceType can
// build the UID mapping and copy OwnerRefs.
func (m *resourceMigrator[T, TList]) ListV1(ctx context.Context) ([]client.Object, error) {
	kvpList, err := m.bcClient.List(ctx, m.listOpts, "")
	if err != nil {
		return nil, err
	}
	result := make([]client.Object, 0, len(kvpList.KVPairs))
	for _, kvp := range kvpList.KVPairs {
		converted, err := m.convert(kvp)
		if err != nil {
			return nil, fmt.Errorf("converting %s: %w", m.kind, err)
		}
		obj, ok := any(converted).(client.Object)
		if !ok {
			return nil, fmt.Errorf("converted %s does not implement client.Object", m.kind)
		}
		result = append(result, obj)
	}
	return result, nil
}

// GetV3 fetches a v3 resource by name/namespace. Returns (nil, nil) if not found.
func (m *resourceMigrator[T, TList]) GetV3(ctx context.Context, name, namespace string) (client.Object, error) {
	obj, ok := any(new(T)).(client.Object)
	if !ok {
		return nil, fmt.Errorf("type %T does not implement client.Object", (*T)(nil))
	}
	err := m.rtClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, obj)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return obj, nil
}

func (m *resourceMigrator[T, TList]) CreateV3(ctx context.Context, obj client.Object) error {
	return m.rtClient.Create(ctx, obj)
}

func (m *resourceMigrator[T, TList]) UpdateV3(ctx context.Context, obj client.Object) error {
	return m.rtClient.Update(ctx, obj)
}

// ListV3 lists all v3 resources of this type.
func (m *resourceMigrator[T, TList]) ListV3(ctx context.Context) ([]client.Object, error) {
	list, ok := any(new(TList)).(client.ObjectList)
	if !ok {
		return nil, fmt.Errorf("type %T does not implement client.ObjectList", (*TList)(nil))
	}
	if err := m.rtClient.List(ctx, list); err != nil {
		return nil, err
	}
	var result []client.Object
	_ = meta.EachListItem(list, func(obj runtime.Object) error {
		if o, ok := obj.(client.Object); ok {
			result = append(result, o)
		}
		return nil
	})
	return result, nil
}

func (m *resourceMigrator[T, TList]) DeleteV3(ctx context.Context, obj client.Object) error {
	return m.rtClient.Delete(ctx, obj)
}

// SpecsEqual compares the Spec field of two v3 objects using reflection.
func (m *resourceMigrator[T, TList]) SpecsEqual(a, b client.Object) bool {
	specA := reflect.ValueOf(a).Elem().FieldByName("Spec")
	specB := reflect.ValueOf(b).Elem().FieldByName("Spec")
	if !specA.IsValid() || !specB.IsValid() {
		logrus.WithField("kind", m.kind).Warn("Spec field not found on object, falling back to full DeepEqual")
		return reflect.DeepEqual(a, b)
	}
	return reflect.DeepEqual(specA.Interface(), specB.Interface())
}
