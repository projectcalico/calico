// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing persmissions and
// limitations under the License.

package tier

import (
	"context"

	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/meta"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/server"
)

// REST implements a RESTStorage for API services against etcd
type REST struct {
	*registry.Store
	authorizer authorizer.TierAuthorizer
}

// EmptyObject returns an empty instance
func EmptyObject() runtime.Object {
	return &calico.Tier{}
}

// NewList returns a new shell of a binding list
func NewList() runtime.Object {
	return &calico.TierList{}
}

// StatusREST implements the REST endpoint for changing the status of a Tier.
type StatusREST struct {
	store *registry.Store
}

func (r *StatusREST) New() runtime.Object {
	return &calico.Tier{}
}

func (r *StatusREST) Destroy() {
	r.store.Destroy()
}

// Get retrieves the object from the storage. It is required to support Patch.
func (r *StatusREST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.store.Get(ctx, name, options)
}

// Update alters the status subset of an object.
func (r *StatusREST) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc,
	updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions,
) (runtime.Object, bool, error) {
	return r.store.Update(ctx, name, objInfo, createValidation, updateValidation, forceAllowCreate, options)
}

// NewREST returns a RESTStorage object that will work against API services.
func NewREST(scheme *runtime.Scheme, opts server.Options, statusOpts server.Options) (*REST, *StatusREST, error) {
	strategy := NewStrategy(scheme)

	prefix := "/" + opts.ResourcePrefix()
	statusPrefix := "/" + statusOpts.ResourcePrefix()

	// We adapt the store's keyFunc so that we can use it with the StorageDecorator
	// without making any assumptions about where objects are stored in etcd
	keyFunc := func(obj runtime.Object) (string, error) {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return "", err
		}
		return registry.NoNamespaceKeyFunc(
			genericapirequest.NewContext(),
			prefix,
			accessor.GetName(),
		)
	}
	statusKeyFunc := func(obj runtime.Object) (string, error) {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return "", err
		}
		return registry.NoNamespaceKeyFunc(
			genericapirequest.NewContext(),
			statusPrefix,
			accessor.GetName(),
		)
	}
	storageInterface, dFunc, err := opts.GetStorage(
		prefix,
		keyFunc,
		strategy,
		func() runtime.Object { return &calico.Tier{} },
		func() runtime.Object { return &calico.TierList{} },
		GetAttrs,
		nil,
		nil,
	)
	if err != nil {
		return nil, nil, err
	}
	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &calico.Tier{} },
		NewListFunc: func() runtime.Object { return &calico.TierList{} },
		KeyRootFunc: opts.KeyRootFunc(false),
		KeyFunc:     opts.KeyFunc(false),
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*calico.Tier).Name, nil
		},
		PredicateFunc:            MatchTier,
		DefaultQualifiedResource: calico.Resource("tiers"),

		CreateStrategy:          strategy,
		UpdateStrategy:          strategy,
		DeleteStrategy:          strategy,
		EnableGarbageCollection: true,

		Storage:     storageInterface,
		DestroyFunc: dFunc,
	}

	statusStorageInterface, statusDFunc, err := statusOpts.GetStorage(
		prefix,
		statusKeyFunc,
		strategy,
		func() runtime.Object { return &calico.Tier{} },
		func() runtime.Object { return &calico.TierList{} },
		GetAttrs,
		nil,
		nil,
	)
	if err != nil {
		return nil, nil, err
	}

	statusStore := *store
	statusStore.UpdateStrategy = NewStatusStrategy(strategy)
	statusStore.Storage = statusStorageInterface
	statusStore.DestroyFunc = statusDFunc

	return &REST{store, authorizer.NewTierAuthorizer(opts.Authorizer)}, &StatusREST{&statusStore}, nil
}

// Apply tiered RBAC to delete requests. A Tier is its own tier scope, so the
// object's name is also the tierName argument.
func (r *REST) Delete(ctx context.Context, name string, deleteValidation rest.ValidateObjectFunc, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	if err := r.authorizer.AuthorizeTierOperation(ctx, name, name); err != nil {
		return nil, false, err
	}
	return r.Store.Delete(ctx, name, deleteValidation, options)
}

// Apply tiered RBAC to deletecollection requests.
func (r *REST) DeleteCollection(ctx context.Context, deleteValidation rest.ValidateObjectFunc, options *metav1.DeleteOptions, listOptions *metainternalversion.ListOptions) (runtime.Object, error) {
	if listOptions == nil {
		listOptions = &metainternalversion.ListOptions{}
	}
	listObj, err := r.List(ctx, listOptions)
	if err != nil {
		return nil, err
	}
	items, err := meta.ExtractList(listObj)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		accessor, err := meta.Accessor(item)
		if err != nil {
			return nil, err
		}
		tierName := accessor.GetName()
		if err := r.authorizer.AuthorizeTierOperation(ctx, tierName, tierName); err != nil {
			return nil, err
		}
	}
	return r.Store.DeleteCollection(ctx, deleteValidation, options, listOptions)
}
