// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package ipamconfig

import (
	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/server"
)

type REST struct {
	*genericregistry.Store
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
	return &calico.IPAMConfiguration{}
}

// NewList returns a new shell of a binding list
func NewList() runtime.Object {
	return &calico.IPAMConfigurationList{}
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
		return registry.NoNamespaceKeyFunc(
			genericapirequest.NewContext(),
			prefix,
			accessor.GetName(),
		)
	}
	storageInterface, dFunc, err := opts.GetStorage(
		prefix,
		keyFunc,
		strategy,
		func() runtime.Object { return &calico.IPAMConfiguration{} },
		func() runtime.Object { return &calico.IPAMConfigurationList{} },
		GetAttrs,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}
	store := &genericregistry.Store{
		NewFunc:     func() runtime.Object { return &calico.IPAMConfiguration{} },
		NewListFunc: func() runtime.Object { return &calico.IPAMConfigurationList{} },
		KeyRootFunc: opts.KeyRootFunc(false),
		KeyFunc:     opts.KeyFunc(false),
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*calico.IPAMConfiguration).Name, nil
		},
		PredicateFunc:            MatchIPAMConfiguration,
		DefaultQualifiedResource: calico.Resource("ipamconfigurations"),

		CreateStrategy:          strategy,
		UpdateStrategy:          strategy,
		DeleteStrategy:          strategy,
		EnableGarbageCollection: true,

		Storage:     storageInterface,
		DestroyFunc: dFunc,
	}

	return &REST{store, opts.ShortNames}, nil
}
