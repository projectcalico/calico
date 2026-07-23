// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

package ippool

import (
	"context"

	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/server"
)

// rest implements a RESTStorage for API services against etcd
type REST struct {
	*registry.Store
	shortNames []string
}

func (r *REST) ShortNames() []string {
	return r.shortNames
}

func (r *REST) Categories() []string {
	return []string{""}
}

// EmptyObject returns an empty instance
func EmptyObject() runtime.Object {
	return &calico.IPPool{}
}

// NewList returns a new shell of a binding list
func NewList() runtime.Object {
	return &calico.IPPoolList{}
}

// StatusREST implements the REST endpoint for changing the status of an IPPool.
type StatusREST struct {
	store      *registry.Store
	shortNames []string
}

func (r *StatusREST) New() runtime.Object {
	return &calico.IPPool{}
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
	updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
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
		func() runtime.Object { return &calico.IPPool{} },
		func() runtime.Object { return &calico.IPPoolList{} },
		GetAttrs,
		nil,
		nil,
	)
	if err != nil {
		return nil, nil, err
	}
	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &calico.IPPool{} },
		NewListFunc: func() runtime.Object { return &calico.IPPoolList{} },
		KeyRootFunc: opts.KeyRootFunc(false),
		KeyFunc:     opts.KeyFunc(false),
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*calico.IPPool).Name, nil
		},
		PredicateFunc:            MatchIPPool,
		DefaultQualifiedResource: calico.Resource("ippools"),

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
		func() runtime.Object { return &calico.IPPool{} },
		func() runtime.Object { return &calico.IPPoolList{} },
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

	return &REST{store, opts.ShortNames}, &StatusREST{&statusStore, opts.ShortNames}, nil
}
