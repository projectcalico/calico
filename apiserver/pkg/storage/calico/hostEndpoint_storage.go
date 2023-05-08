// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package calico

import (
	"reflect"

	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"

	aapi "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

// NewHostEndpointStorage creates a new libcalico-based storage.Interface implementation for HostEndpoints
func NewHostEndpointStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.HostEndpoint)
		return c.HostEndpoints().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.HostEndpoint)
		return c.HostEndpoints().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.HostEndpoints().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.HostEndpoints().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.HostEndpoints().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.HostEndpoints().Watch(ctx, olo)
	}

	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeOf(aapi.HostEndpoint{}),
		aapiListType:      reflect.TypeOf(aapi.HostEndpointList{}),
		libCalicoType:     reflect.TypeOf(api.HostEndpoint{}),
		libCalicoListType: reflect.TypeOf(api.HostEndpointList{}),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "HostEndpoint",
		converter:         HostEndpointConverter{},
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type HostEndpointConverter struct {
}

func (gc HostEndpointConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiHostEndpoint := aapiObj.(*aapi.HostEndpoint)
	lcgHostEndpoint := &api.HostEndpoint{}
	lcgHostEndpoint.TypeMeta = aapiHostEndpoint.TypeMeta
	lcgHostEndpoint.ObjectMeta = aapiHostEndpoint.ObjectMeta
	lcgHostEndpoint.Kind = api.KindHostEndpoint
	lcgHostEndpoint.APIVersion = api.GroupVersionCurrent
	lcgHostEndpoint.Spec = aapiHostEndpoint.Spec
	return lcgHostEndpoint
}

func (gc HostEndpointConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgHostEndpoint := libcalicoObject.(*api.HostEndpoint)
	aapiHostEndpoint := aapiObj.(*aapi.HostEndpoint)
	aapiHostEndpoint.Spec = lcgHostEndpoint.Spec
	aapiHostEndpoint.TypeMeta = lcgHostEndpoint.TypeMeta
	aapiHostEndpoint.ObjectMeta = lcgHostEndpoint.ObjectMeta
}

func (gc HostEndpointConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgHostEndpointList := libcalicoListObject.(*api.HostEndpointList)
	aapiHostEndpointList := aapiListObj.(*aapi.HostEndpointList)
	if libcalicoListObject == nil {
		aapiHostEndpointList.Items = []aapi.HostEndpoint{}
		return
	}
	aapiHostEndpointList.TypeMeta = lcgHostEndpointList.TypeMeta
	aapiHostEndpointList.ListMeta = lcgHostEndpointList.ListMeta
	for _, item := range lcgHostEndpointList.Items {
		aapiHostEndpoint := aapi.HostEndpoint{}
		gc.convertToAAPI(&item, &aapiHostEndpoint)
		if matched, err := pred.Matches(&aapiHostEndpoint); err == nil && matched {
			aapiHostEndpointList.Items = append(aapiHostEndpointList.Items, aapiHostEndpoint)
		}
	}
}
