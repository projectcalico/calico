// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package server

import (
	"context"
	"fmt"

	"github.com/projectcalico/calico/apiserver/pkg/storage/calico"
	"github.com/projectcalico/calico/apiserver/pkg/storage/etcd"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

type errUnsupportedStorageType struct {
	t StorageType
}

func (e errUnsupportedStorageType) Error() string {
	return fmt.Sprintf("unsupported storage type %s", e.t)
}

// StorageType represents the type of storage a storage interface should use
type StorageType string

// StorageTypeFromString converts s to a valid StorageType. Returns StorageType("") and a non-nil
// error if s names an invalid or unsupported storage type
func StorageTypeFromString(s string) (StorageType, error) {
	switch s {
	case StorageTypeCalico.String():
		return StorageTypeCalico, nil
	case StorageTypeEtcd.String():
		return StorageTypeEtcd, nil
	default:
		return StorageType(""), errUnsupportedStorageType{t: StorageType(s)}
	}
}

func (s StorageType) String() string {
	return string(s)
}

const (
	// StorageTypeCalico indicates a storage interface should use libcalico
	StorageTypeCalico StorageType = "calico"
	// StorageTypeEtcd indicates a storage interface should use default etcd
	StorageTypeEtcd StorageType = "etcd"
)

// Options is the extension of a generic.RESTOptions struct, complete with service-catalog
// specific things
type Options struct {
	EtcdOptions   etcd.Options
	CalicoOptions calico.Options
	storageType   StorageType
	Authorizer    authorizer.Authorizer
	ShortNames    []string
}

// NewOptions returns a new Options with the given parameters
func NewOptions(
	etcdOpts etcd.Options,
	calicoOpts calico.Options,
	sType StorageType,
	authorizer authorizer.Authorizer,
	ShortNames []string,
) *Options {
	return &Options{
		EtcdOptions:   etcdOpts,
		CalicoOptions: calicoOpts,
		storageType:   sType,
		Authorizer:    authorizer,
		ShortNames:    ShortNames,
	}
}

// StorageType returns the storage type the rest server should use, or an error if an unsupported
// storage type is indicated
func (o Options) StorageType() (StorageType, error) {
	switch o.storageType {
	case StorageTypeCalico, StorageTypeEtcd:
		return o.storageType, nil
	default:
		return StorageType(""), errUnsupportedStorageType{t: o.storageType}
	}
}

// ResourcePrefix gets the resource prefix of all etcd keys
func (o Options) ResourcePrefix() string {
	return o.EtcdOptions.RESTOptions.ResourcePrefix
}

// KeyRootFunc returns the appropriate key root function for the storage type in o.
// This function produces a path that etcd or Calico storage understands, to the root of the resource
// by combining the namespace in the context with the given prefix
func (o Options) KeyRootFunc(namespaced bool) func(context.Context) string {
	prefix := o.ResourcePrefix()

	return func(ctx context.Context) string {
		if namespaced {
			return registry.NamespaceKeyRootFunc(ctx, prefix)
		}
		return prefix
	}
}

// KeyFunc returns the appropriate key function for the storage type in o.
// This function should produce a path that etcd or Calico storage understands, to the resource
// by combining the namespace in the context with the given prefix
func (o Options) KeyFunc(namespaced bool) func(context.Context, string) (string, error) {
	prefix := o.ResourcePrefix()

	return func(ctx context.Context, name string) (string, error) {
		if namespaced {
			return registry.NamespaceKeyFunc(ctx, prefix, name)
		}
		return registry.NoNamespaceKeyFunc(ctx, prefix, name)
	}
}

// GetStorage returns the storage from the given parameters
func (o Options) GetStorage(
	resourcePrefix string,
	keyFunc func(obj runtime.Object) (string, error),
	scopeStrategy rest.NamespaceScopedStrategy,
	newFunc func() runtime.Object,
	newListFunc func() runtime.Object,
	getAttrsFunc storage.AttrFunc,
	trigger storage.IndexerFuncs,
	indexers *cache.Indexers,
) (registry.DryRunnableStorage, factory.DestroyFunc, error) {
	if o.storageType == StorageTypeEtcd {
		etcdRESTOpts := o.EtcdOptions.RESTOptions
		storageInterface, dFunc, err := etcdRESTOpts.Decorator(
			etcdRESTOpts.StorageConfig,
			resourcePrefix,
			keyFunc, /* keyFunc for decorator -- looks to be unused everywhere */
			newFunc,
			newListFunc,
			getAttrsFunc,
			trigger,
			indexers,
		)
		if err != nil {
			klog.Warning("error (%s)", err)
			return registry.DryRunnableStorage{}, nil, err
		}
		dryRunnableStorage := registry.DryRunnableStorage{Storage: storageInterface, Codec: etcdRESTOpts.StorageConfig.Codec}
		return dryRunnableStorage, dFunc, nil
	}
	dryRunnableStorage, dFunc := calico.NewStorage(o.CalicoOptions)
	return dryRunnableStorage, dFunc, nil
}
