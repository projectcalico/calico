// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package calico

import (
	"context"
	"reflect"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// NewProfileStorage creates a new libcalico-based storage.Interface implementation for Profiles
func NewProfileStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.Profile)
		return c.Profiles().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.Profile)
		return c.Profiles().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.Profiles().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.Profiles().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.Profiles().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.Profiles().Watch(ctx, olo)
	}

	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeOf(api.Profile{}),
		aapiListType:      reflect.TypeOf(api.ProfileList{}),
		libCalicoType:     reflect.TypeOf(api.Profile{}),
		libCalicoListType: reflect.TypeOf(api.ProfileList{}),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "Profile",
		converter:         ProfileConverter{},
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type ProfileConverter struct {
}

func (gc ProfileConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiProfile := aapiObj.(*api.Profile)
	lcgProfile := &api.Profile{}
	lcgProfile.TypeMeta = aapiProfile.TypeMeta
	lcgProfile.ObjectMeta = aapiProfile.ObjectMeta
	lcgProfile.Kind = api.KindProfile
	lcgProfile.APIVersion = api.GroupVersionCurrent
	lcgProfile.Spec = aapiProfile.Spec
	return lcgProfile
}

func (gc ProfileConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgProfile := libcalicoObject.(*api.Profile)
	aapiProfile := aapiObj.(*api.Profile)
	aapiProfile.Spec = lcgProfile.Spec
	aapiProfile.TypeMeta = lcgProfile.TypeMeta
	aapiProfile.ObjectMeta = lcgProfile.ObjectMeta
}

func (gc ProfileConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgProfileList := libcalicoListObject.(*api.ProfileList)
	aapiProfileList := aapiListObj.(*api.ProfileList)
	if libcalicoListObject == nil {
		aapiProfileList.Items = []api.Profile{}
		return
	}
	aapiProfileList.TypeMeta = lcgProfileList.TypeMeta
	aapiProfileList.ListMeta = lcgProfileList.ListMeta
	for _, item := range lcgProfileList.Items {
		aapiProfile := api.Profile{}
		gc.convertToAAPI(&item, &aapiProfile)
		if matched, err := pred.Matches(&aapiProfile); err == nil && matched {
			aapiProfileList.Items = append(aapiProfileList.Items, aapiProfile)
		}
	}
}
