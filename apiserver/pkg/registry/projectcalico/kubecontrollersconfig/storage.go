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

package kubecontrollersconfig

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

// EmptyObject returns an empty instance
func EmptyObject() runtime.Object {
	return &calico.KubeControllersConfiguration{}
}

// NewList returns a new shell of a binding list
func NewList() runtime.Object {
	return &calico.KubeControllersConfigurationList{}
}

// StatusREST implements the REST endpoint for changing the status of a deployment
type StatusREST struct {
	store      *registry.Store
	shortNames []string
}

func (r *StatusREST) New() runtime.Object {
	return &calico.KubeControllersConfiguration{}
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

	storageInterface, dFunc, err := opts.GetStorage(
		prefix,
		configureKeyFunc(prefix),
		strategy,
		func() runtime.Object { return &calico.KubeControllersConfiguration{} },
		func() runtime.Object { return &calico.KubeControllersConfigurationList{} },
		GetAttrs,
		nil,
		nil,
	)
	if err != nil {
		return nil, nil, err
	}

	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &calico.KubeControllersConfiguration{} },
		NewListFunc: func() runtime.Object { return &calico.KubeControllersConfigurationList{} },
		KeyRootFunc: opts.KeyRootFunc(false),
		KeyFunc:     opts.KeyFunc(false),
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*calico.KubeControllersConfiguration).Name, nil
		},
		PredicateFunc:            Match,
		DefaultQualifiedResource: calico.Resource("kubecontrollersconfigurations"),

		CreateStrategy:          strategy,
		UpdateStrategy:          strategy,
		DeleteStrategy:          strategy,
		EnableGarbageCollection: true,

		Storage:     storageInterface,
		DestroyFunc: dFunc,
	}

	statusStorageInterface, statusDFunc, err := statusOpts.GetStorage(
		prefix,
		configureKeyFunc(statusPrefix),
		strategy,
		func() runtime.Object { return &calico.KubeControllersConfiguration{} },
		func() runtime.Object { return &calico.KubeControllersConfigurationList{} },
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

func configureKeyFunc(resourcePrefix string) func(obj runtime.Object) (string, error) {
	return func(obj runtime.Object) (string, error) {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return "", err
		}
		return registry.NoNamespaceKeyFunc(
			genericapirequest.NewContext(),
			resourcePrefix,
			accessor.GetName(),
		)
	}
}

func (r *REST) ShortNames() []string {
	return r.shortNames
}
