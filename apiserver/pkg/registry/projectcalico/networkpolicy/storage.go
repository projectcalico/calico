// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package networkpolicy

import (
	"context"

	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/server"

	"k8s.io/apimachinery/pkg/api/meta"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
)

// rest implements a RESTStorage for API services against etcd
type REST struct {
	*genericregistry.Store
	shortNames []string
}

// EmptyObject returns an empty instance
func EmptyObject() runtime.Object {
	return &calico.NetworkPolicy{}
}

// NewList returns a new shell of a binding list
func NewList() runtime.Object {
	return &calico.NetworkPolicyList{
		//TypeMeta: metav1.TypeMeta{},
		//Items:    []calico.NetworkPolicy{},
	}
}

// NewREST returns a RESTStorage object that will work against API services.
func NewREST(scheme *runtime.Scheme, opts server.Options) (*REST, error) {
	strategy := NewStrategy(scheme)

	prefix := "/" + opts.ResourcePrefix()
	// We adapt the store's keyFunc so that we can use it with the StorageDecorator
	// without making any assumptions about where objects are stored in etcd
	keyFunc := func(obj runtime.Object) (string, error) {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return "", err
		}
		return registry.NamespaceKeyFunc(genericapirequest.WithNamespace(genericapirequest.NewContext(), accessor.GetNamespace()), prefix, accessor.GetName())
	}
	storageInterface, dFunc, err := opts.GetStorage(
		prefix,
		keyFunc,
		strategy,
		func() runtime.Object { return &calico.NetworkPolicy{} },
		func() runtime.Object { return &calico.NetworkPolicyList{} },
		GetAttrs,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}
	store := &genericregistry.Store{
		NewFunc:     func() runtime.Object { return &calico.NetworkPolicy{} },
		NewListFunc: func() runtime.Object { return &calico.NetworkPolicyList{} },
		KeyRootFunc: opts.KeyRootFunc(true),
		KeyFunc:     opts.KeyFunc(true),
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*calico.NetworkPolicy).Name, nil
		},
		PredicateFunc:            MatchPolicy,
		DefaultQualifiedResource: calico.Resource("networkpolicies"),

		CreateStrategy:          strategy,
		UpdateStrategy:          strategy,
		DeleteStrategy:          strategy,
		EnableGarbageCollection: true,

		Storage:     storageInterface,
		DestroyFunc: dFunc,
	}

	return &REST{Store: store, shortNames: opts.ShortNames}, nil
}

func (r *REST) List(ctx context.Context, options *metainternalversion.ListOptions) (runtime.Object, error) {
	return r.Store.List(ctx, options)
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, val rest.ValidateObjectFunc, createOpt *metav1.CreateOptions) (runtime.Object, error) {
	return r.Store.Create(ctx, obj, val, createOpt)
}

func (r *REST) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc,
	updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	return r.Store.Update(ctx, name, objInfo, createValidation, updateValidation, forceAllowCreate, options)
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.Store.Get(ctx, name, options)
}

func (r *REST) Delete(ctx context.Context, name string, deleteValidation rest.ValidateObjectFunc, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	return r.Store.Delete(ctx, name, deleteValidation, options)
}

func (r *REST) Watch(ctx context.Context, options *metainternalversion.ListOptions) (watch.Interface, error) {
	return r.Store.Watch(ctx, options)
}

func (r *REST) ShortNames() []string {
	return r.shortNames
}

func (r *REST) Categories() []string {
	return []string{""}
}
