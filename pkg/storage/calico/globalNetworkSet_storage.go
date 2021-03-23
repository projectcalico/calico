// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.

package calico

import (
	"reflect"

	"golang.org/x/net/context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	etcd "k8s.io/apiserver/pkg/storage/etcd3"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	aapi "github.com/projectcalico/apiserver/pkg/apis/projectcalico"

	libcalicoapi "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
)

// NewGlobalNetworkSetStorage creates a new libcalico-based storage.Interface implementation for GlobalNetworkSets
func NewGlobalNetworkSetStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*libcalicoapi.GlobalNetworkSet)
		return c.GlobalNetworkSets().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*libcalicoapi.GlobalNetworkSet)
		return c.GlobalNetworkSets().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.GlobalNetworkSets().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.GlobalNetworkSets().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.GlobalNetworkSets().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.GlobalNetworkSets().Watch(ctx, olo)
	}
	// TODO(doublek): Inject codec, client for nicer testing.
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         etcd.APIObjectVersioner{},
		aapiType:          reflect.TypeOf(aapi.GlobalNetworkSet{}),
		aapiListType:      reflect.TypeOf(aapi.GlobalNetworkSetList{}),
		libCalicoType:     reflect.TypeOf(libcalicoapi.GlobalNetworkSet{}),
		libCalicoListType: reflect.TypeOf(libcalicoapi.GlobalNetworkSetList{}),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "GlobalNetworkSet",
		converter:         GlobalNetworkSetConverter{},
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type GlobalNetworkSetConverter struct {
}

func (gc GlobalNetworkSetConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiGlobalNetworkSet := aapiObj.(*aapi.GlobalNetworkSet)
	lcgGlobalNetworkSet := &libcalicoapi.GlobalNetworkSet{}
	lcgGlobalNetworkSet.TypeMeta = aapiGlobalNetworkSet.TypeMeta
	lcgGlobalNetworkSet.ObjectMeta = aapiGlobalNetworkSet.ObjectMeta
	lcgGlobalNetworkSet.Kind = libcalicoapi.KindGlobalNetworkSet
	lcgGlobalNetworkSet.APIVersion = libcalicoapi.GroupVersionCurrent
	lcgGlobalNetworkSet.Spec = aapiGlobalNetworkSet.Spec
	return lcgGlobalNetworkSet
}

func (gc GlobalNetworkSetConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgGlobalNetworkSet := libcalicoObject.(*libcalicoapi.GlobalNetworkSet)
	aapiGlobalNetworkSet := aapiObj.(*aapi.GlobalNetworkSet)
	aapiGlobalNetworkSet.Spec = lcgGlobalNetworkSet.Spec
	aapiGlobalNetworkSet.TypeMeta = lcgGlobalNetworkSet.TypeMeta
	aapiGlobalNetworkSet.ObjectMeta = lcgGlobalNetworkSet.ObjectMeta
}

func (gc GlobalNetworkSetConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgGlobalNetworkSetList := libcalicoListObject.(*libcalicoapi.GlobalNetworkSetList)
	aapiGlobalNetworkSetList := aapiListObj.(*aapi.GlobalNetworkSetList)
	if libcalicoListObject == nil {
		aapiGlobalNetworkSetList.Items = []aapi.GlobalNetworkSet{}
		return
	}
	aapiGlobalNetworkSetList.TypeMeta = lcgGlobalNetworkSetList.TypeMeta
	aapiGlobalNetworkSetList.ListMeta = lcgGlobalNetworkSetList.ListMeta
	for _, item := range lcgGlobalNetworkSetList.Items {
		aapiGlobalNetworkSet := aapi.GlobalNetworkSet{}
		gc.convertToAAPI(&item, &aapiGlobalNetworkSet)
		if matched, err := pred.Matches(&aapiGlobalNetworkSet); err == nil && matched {
			aapiGlobalNetworkSetList.Items = append(aapiGlobalNetworkSetList.Items, aapiGlobalNetworkSet)
		}
	}
}
