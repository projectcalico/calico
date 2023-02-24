// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package calico

import (
	"reflect"

	"golang.org/x/net/context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	aapi "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// NewFelixConfigurationStorage creates a new libcalico-based storage.Interface implementation for FelixConfigurations
func NewFelixConfigurationStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.FelixConfiguration)
		return c.FelixConfigurations().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.FelixConfiguration)
		return c.FelixConfigurations().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.FelixConfigurations().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.FelixConfigurations().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.FelixConfigurations().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.FelixConfigurations().Watch(ctx, olo)
	}
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeOf(aapi.FelixConfiguration{}),
		aapiListType:      reflect.TypeOf(aapi.FelixConfigurationList{}),
		libCalicoType:     reflect.TypeOf(api.FelixConfiguration{}),
		libCalicoListType: reflect.TypeOf(api.FelixConfigurationList{}),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "FelixConfiguration",
		converter:         FelixConfigurationConverter{},
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type FelixConfigurationConverter struct {
}

func (gc FelixConfigurationConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiFelixConfig := aapiObj.(*aapi.FelixConfiguration)
	lcgFelixConfig := &api.FelixConfiguration{}
	lcgFelixConfig.TypeMeta = aapiFelixConfig.TypeMeta
	lcgFelixConfig.ObjectMeta = aapiFelixConfig.ObjectMeta
	lcgFelixConfig.Kind = api.KindFelixConfiguration
	lcgFelixConfig.APIVersion = api.GroupVersionCurrent
	lcgFelixConfig.Spec = aapiFelixConfig.Spec
	return lcgFelixConfig
}

func (gc FelixConfigurationConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgFelixConfig := libcalicoObject.(*api.FelixConfiguration)
	aapiFelixConfig := aapiObj.(*aapi.FelixConfiguration)
	aapiFelixConfig.Spec = lcgFelixConfig.Spec
	aapiFelixConfig.TypeMeta = lcgFelixConfig.TypeMeta
	aapiFelixConfig.ObjectMeta = lcgFelixConfig.ObjectMeta
}

func (gc FelixConfigurationConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgFelixConfigList := libcalicoListObject.(*api.FelixConfigurationList)
	aapiFelixConfigList := aapiListObj.(*aapi.FelixConfigurationList)
	if libcalicoListObject == nil {
		aapiFelixConfigList.Items = []aapi.FelixConfiguration{}
		return
	}
	aapiFelixConfigList.TypeMeta = lcgFelixConfigList.TypeMeta
	aapiFelixConfigList.ListMeta = lcgFelixConfigList.ListMeta
	for _, item := range lcgFelixConfigList.Items {
		aapiFelixConfig := aapi.FelixConfiguration{}
		gc.convertToAAPI(&item, &aapiFelixConfig)
		if matched, err := pred.Matches(&aapiFelixConfig); err == nil && matched {
			aapiFelixConfigList.Items = append(aapiFelixConfigList.Items, aapiFelixConfig)
		}
	}
}
