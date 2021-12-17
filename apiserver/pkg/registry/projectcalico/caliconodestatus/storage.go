// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package caliconodestatus

import (
	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/kubernetes/pkg/printers"
	printerstorage "k8s.io/kubernetes/pkg/printers/storage"

	calicoprinter "github.com/projectcalico/calico/apiserver/pkg/printers/projectcalico"
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
	return &calico.CalicoNodeStatus{}
}

// NewList returns a new shell of a binding list
func NewList() runtime.Object {
	return &calico.CalicoNodeStatusList{}
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
		func() runtime.Object { return &calico.CalicoNodeStatus{} },
		func() runtime.Object { return &calico.CalicoNodeStatusList{} },
		GetAttrs,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}
	store := &genericregistry.Store{
		NewFunc:     func() runtime.Object { return &calico.CalicoNodeStatus{} },
		NewListFunc: func() runtime.Object { return &calico.CalicoNodeStatusList{} },
		KeyRootFunc: opts.KeyRootFunc(false),
		KeyFunc:     opts.KeyFunc(false),
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*calico.CalicoNodeStatus).Name, nil
		},
		PredicateFunc:            MatchCalicoNodeStatus,
		DefaultQualifiedResource: calico.Resource("caliconodestatuses"),

		CreateStrategy:          strategy,
		UpdateStrategy:          strategy,
		DeleteStrategy:          strategy,
		EnableGarbageCollection: true,

		Storage:     storageInterface,
		DestroyFunc: dFunc,

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(calicoprinter.CalicoNodeStatusAddHandlers)},
	}

	return &REST{store, opts.ShortNames}, nil
}
