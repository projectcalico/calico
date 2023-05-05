// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package calico

import (
	"fmt"
	"reflect"

	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"

	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"

	aapi "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

// NewIPAMConfigurationStorage creates a new libcalico-based storage.Interface implementation for IPAMConfig
func NewIPAMConfigurationStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*libapi.IPAMConfig)
		if res.Name != libapi.GlobalIPAMConfigName {
			return nil, fmt.Errorf("IPAM config resource name has to be default")
		}
		return c.IPAMConfig().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*libapi.IPAMConfig)
		return c.IPAMConfig().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.IPAMConfig().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.IPAMConfig().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.IPAMConfig().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.IPAMConfig().Watch(ctx, olo)
	}
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeOf(aapi.IPAMConfiguration{}),
		aapiListType:      reflect.TypeOf(aapi.IPAMConfigurationList{}),
		libCalicoType:     reflect.TypeOf(libapi.IPAMConfig{}),
		libCalicoListType: reflect.TypeOf(libapi.IPAMConfigList{}),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "IPAMConfiguration",
		converter:         IPAMConfigConverter{},
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type IPAMConfigConverter struct{}

func (gc IPAMConfigConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiIPAMConfig := aapiObj.(*aapi.IPAMConfiguration)
	lcgIPAMConfig := &libapi.IPAMConfig{}
	lcgIPAMConfig.TypeMeta = aapiIPAMConfig.TypeMeta
	lcgIPAMConfig.ObjectMeta = aapiIPAMConfig.ObjectMeta
	lcgIPAMConfig.Kind = libapi.KindIPAMConfig
	lcgIPAMConfig.APIVersion = aapi.GroupVersionCurrent
	lcgIPAMConfig.Spec.StrictAffinity = aapiIPAMConfig.Spec.StrictAffinity
	lcgIPAMConfig.Spec.MaxBlocksPerHost = int(aapiIPAMConfig.Spec.MaxBlocksPerHost)

	// AutoAllocatBlocks is an internal field and should be set to true.
	lcgIPAMConfig.Spec.AutoAllocateBlocks = true

	return lcgIPAMConfig
}

func (gc IPAMConfigConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgIPAMConfig := libcalicoObject.(*libapi.IPAMConfig)
	aapiIPAMConfig := aapiObj.(*aapi.IPAMConfiguration)

	// Copy spec but ignore internal field AutoAllocateBlocks.
	aapiIPAMConfig.Spec.StrictAffinity = lcgIPAMConfig.Spec.StrictAffinity
	aapiIPAMConfig.Spec.MaxBlocksPerHost = int32(lcgIPAMConfig.Spec.MaxBlocksPerHost)
	aapiIPAMConfig.TypeMeta = lcgIPAMConfig.TypeMeta
	aapiIPAMConfig.ObjectMeta = lcgIPAMConfig.ObjectMeta

	// libcalico uses a different Kind for these resources - IPAMConfig.
	aapiIPAMConfig.TypeMeta.APIVersion = aapi.GroupVersionCurrent
	aapiIPAMConfig.Kind = aapi.KindIPAMConfiguration
}

func (gc IPAMConfigConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgIPAMConfigList := libcalicoListObject.(*libapi.IPAMConfigList)
	aapiIPAMConfigList := aapiListObj.(*aapi.IPAMConfigurationList)
	if libcalicoListObject == nil {
		aapiIPAMConfigList.Items = []aapi.IPAMConfiguration{}
		return
	}
	aapiIPAMConfigList.TypeMeta = lcgIPAMConfigList.TypeMeta
	aapiIPAMConfigList.TypeMeta.Kind = aapi.KindIPAMConfigurationList
	aapiIPAMConfigList.ListMeta = lcgIPAMConfigList.ListMeta
	for _, item := range lcgIPAMConfigList.Items {
		aapiIPAMConfig := aapi.IPAMConfiguration{}
		gc.convertToAAPI(&item, &aapiIPAMConfig)
		if matched, err := pred.Matches(&aapiIPAMConfig); err == nil && matched {
			aapiIPAMConfigList.Items = append(aapiIPAMConfigList.Items, aapiIPAMConfig)
		}
	}
}
