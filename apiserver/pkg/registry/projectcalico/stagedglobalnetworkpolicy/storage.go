/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package stagedglobalpolicy

import (
	"context"

	calico "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/meta"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/server"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/util"
)

// rest implements a RESTStorage for API services against etcd
type REST struct {
	*genericregistry.Store
	rbac.CalicoResourceLister
	authorizer authorizer.TierAuthorizer
}

// EmptyObject returns an empty instance
func EmptyObject() runtime.Object {
	return &calico.StagedGlobalNetworkPolicy{}
}

// NewList returns a new shell of a binding list
func NewList() runtime.Object {
	return &calico.StagedGlobalNetworkPolicyList{}
}

// NewREST returns a RESTStorage object that will work against API services.
func NewREST(scheme *runtime.Scheme, opts server.Options, calicoResourceLister rbac.CalicoResourceLister) (*REST, error) {
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
		func() runtime.Object { return &calico.StagedGlobalNetworkPolicy{} },
		func() runtime.Object { return &calico.StagedGlobalNetworkPolicyList{} },
		GetAttrs,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}
	store := &genericregistry.Store{
		NewFunc:     func() runtime.Object { return &calico.StagedGlobalNetworkPolicy{} },
		NewListFunc: func() runtime.Object { return &calico.StagedGlobalNetworkPolicyList{} },
		KeyRootFunc: opts.KeyRootFunc(false),
		KeyFunc:     opts.KeyFunc(false),
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*calico.StagedGlobalNetworkPolicy).Name, nil
		},
		PredicateFunc:            MatchPolicy,
		DefaultQualifiedResource: calico.Resource("stagedglobalnetworkpolicies"),

		CreateStrategy:          strategy,
		UpdateStrategy:          strategy,
		DeleteStrategy:          strategy,
		EnableGarbageCollection: true,

		Storage:     storageInterface,
		DestroyFunc: dFunc,
	}

	return &REST{store, calicoResourceLister, authorizer.NewTierAuthorizer(opts.Authorizer)}, nil
}

func (r *REST) List(ctx context.Context, options *metainternalversion.ListOptions) (runtime.Object, error) {
	err := util.EnsureTierSelector(ctx, options, r.authorizer, r.CalicoResourceLister)
	if err != nil {
		return nil, err
	}

	return r.Store.List(ctx, options)
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, val rest.ValidateObjectFunc, createOpt *metav1.CreateOptions) (runtime.Object, error) {
	policy := obj.(*calico.StagedGlobalNetworkPolicy)
	// Is Tier prepended. If not prepend default?
	tierName, _ := util.GetTierFromPolicyName(policy.Name)
	err := r.authorizer.AuthorizeTierOperation(ctx, policy.Name, tierName)
	if err != nil {
		return nil, err
	}

	return r.Store.Create(ctx, obj, val, createOpt)
}

func (r *REST) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc,
	updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	tierName, _ := util.GetTierFromPolicyName(name)
	err := r.authorizer.AuthorizeTierOperation(ctx, name, tierName)
	if err != nil {
		return nil, false, err
	}

	return r.Store.Update(ctx, name, objInfo, createValidation, updateValidation, forceAllowCreate, options)
}

// Get retrieves the item from storage.
func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	tierName, _ := util.GetTierFromPolicyName(name)
	err := r.authorizer.AuthorizeTierOperation(ctx, name, tierName)
	if err != nil {
		return nil, err
	}

	return r.Store.Get(ctx, name, options)
}

func (r *REST) Delete(ctx context.Context, name string, deleteValidation rest.ValidateObjectFunc, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	tierName, _ := util.GetTierFromPolicyName(name)
	err := r.authorizer.AuthorizeTierOperation(ctx, name, tierName)
	if err != nil {
		return nil, false, err
	}

	return r.Store.Delete(ctx, name, deleteValidation, options)
}

func (r *REST) Watch(ctx context.Context, options *metainternalversion.ListOptions) (watch.Interface, error) {
	err := util.EnsureTierSelector(ctx, options, r.authorizer, r.CalicoResourceLister)
	if err != nil {
		return nil, err
	}

	return r.Store.Watch(ctx, options)
}
