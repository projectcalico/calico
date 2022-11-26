// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package calico

import (
	"reflect"

	"golang.org/x/net/context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	etcd "k8s.io/apiserver/pkg/storage/etcd3"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// NewBGPFilterStorage creates a new libcalico-based storage.Interface implementation for BGPFilters
func NewBGPFilterStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.BGPFilter)
		return c.BGPFilter().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.BGPFilter)
		return c.BGPFilter().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.BGPFilter().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.BGPFilter().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.BGPFilter().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.BGPFilter().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return false
	}

	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         etcd.APIObjectVersioner{},
		aapiType:          reflect.TypeOf(v3.BGPFilter{}),
		aapiListType:      reflect.TypeOf(v3.BGPFilterList{}),
		libCalicoType:     reflect.TypeOf(v3.BGPFilter{}),
		libCalicoListType: reflect.TypeOf(v3.BGPFilterList{}),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "BGPFilter",
		converter:         BGPFilterConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type BGPFilterConverter struct {
}

func (gc BGPFilterConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiBGPFilter := aapiObj.(*v3.BGPFilter)
	lcgBGPFilter := &v3.BGPFilter{}
	lcgBGPFilter.TypeMeta = aapiBGPFilter.TypeMeta
	lcgBGPFilter.ObjectMeta = aapiBGPFilter.ObjectMeta
	lcgBGPFilter.Kind = v3.KindBGPFilter
	lcgBGPFilter.APIVersion = v3.GroupVersionCurrent
	lcgBGPFilter.Spec = aapiBGPFilter.Spec
	return lcgBGPFilter
}

func (gc BGPFilterConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgBGPFilter := libcalicoObject.(*v3.BGPFilter)
	aapiBGPFilter := aapiObj.(*v3.BGPFilter)
	aapiBGPFilter.Spec = lcgBGPFilter.Spec
	aapiBGPFilter.TypeMeta = lcgBGPFilter.TypeMeta
	aapiBGPFilter.ObjectMeta = lcgBGPFilter.ObjectMeta
}

func (gc BGPFilterConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgBGPFilterList := libcalicoListObject.(*v3.BGPFilterList)
	aapiBGPFilterList := aapiListObj.(*v3.BGPFilterList)
	if libcalicoListObject == nil {
		aapiBGPFilterList.Items = []v3.BGPFilter{}
		return
	}
	aapiBGPFilterList.TypeMeta = lcgBGPFilterList.TypeMeta
	aapiBGPFilterList.ListMeta = lcgBGPFilterList.ListMeta
	for _, item := range lcgBGPFilterList.Items {
		aapiBGPFilter := v3.BGPFilter{}
		gc.convertToAAPI(&item, &aapiBGPFilter)
		if matched, err := pred.Matches(&aapiBGPFilter); err == nil && matched {
			aapiBGPFilterList.Items = append(aapiBGPFilterList.Items, aapiBGPFilter)
		}
	}
}
