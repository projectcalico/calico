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

// NewCalicoNodeStatusStorage creates a new libcalico-based storage.Interface implementation for CalicoNodeStatus
func NewCalicoNodeStatusStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.CalicoNodeStatus)
		return c.CalicoNodeStatus().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.CalicoNodeStatus)
		return c.CalicoNodeStatus().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.CalicoNodeStatus().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.CalicoNodeStatus().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.CalicoNodeStatus().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.CalicoNodeStatus().Watch(ctx, olo)
	}
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeOf(aapi.CalicoNodeStatus{}),
		aapiListType:      reflect.TypeOf(aapi.CalicoNodeStatusList{}),
		libCalicoType:     reflect.TypeOf(api.CalicoNodeStatus{}),
		libCalicoListType: reflect.TypeOf(api.CalicoNodeStatusList{}),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "CalicoNodeStatus",
		converter:         CalicoNodeStatusConverter{},
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type CalicoNodeStatusConverter struct {
}

func (gc CalicoNodeStatusConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiCalicoNodeStatus := aapiObj.(*aapi.CalicoNodeStatus)
	lcgCalicoNodeStatus := &api.CalicoNodeStatus{}
	lcgCalicoNodeStatus.TypeMeta = aapiCalicoNodeStatus.TypeMeta
	lcgCalicoNodeStatus.ObjectMeta = aapiCalicoNodeStatus.ObjectMeta
	lcgCalicoNodeStatus.Kind = api.KindCalicoNodeStatus
	lcgCalicoNodeStatus.APIVersion = api.GroupVersionCurrent
	lcgCalicoNodeStatus.Spec = aapiCalicoNodeStatus.Spec
	return lcgCalicoNodeStatus
}

func (gc CalicoNodeStatusConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgCalicoNodeStatus := libcalicoObject.(*api.CalicoNodeStatus)
	aapiCalicoNodeStatus := aapiObj.(*aapi.CalicoNodeStatus)
	aapiCalicoNodeStatus.Spec = lcgCalicoNodeStatus.Spec
	aapiCalicoNodeStatus.Status = lcgCalicoNodeStatus.Status
	aapiCalicoNodeStatus.TypeMeta = lcgCalicoNodeStatus.TypeMeta
	aapiCalicoNodeStatus.ObjectMeta = lcgCalicoNodeStatus.ObjectMeta
}

func (gc CalicoNodeStatusConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgCalicoNodeStatusList := libcalicoListObject.(*api.CalicoNodeStatusList)
	aapiCalicoNodeStatusList := aapiListObj.(*aapi.CalicoNodeStatusList)
	if libcalicoListObject == nil {
		aapiCalicoNodeStatusList.Items = []aapi.CalicoNodeStatus{}
		return
	}
	aapiCalicoNodeStatusList.TypeMeta = lcgCalicoNodeStatusList.TypeMeta
	aapiCalicoNodeStatusList.ListMeta = lcgCalicoNodeStatusList.ListMeta
	for _, item := range lcgCalicoNodeStatusList.Items {
		aapiCalicoNodeStatus := aapi.CalicoNodeStatus{}
		gc.convertToAAPI(&item, &aapiCalicoNodeStatus)
		if matched, err := pred.Matches(&aapiCalicoNodeStatus); err == nil && matched {
			aapiCalicoNodeStatusList.Items = append(aapiCalicoNodeStatusList.Items, aapiCalicoNodeStatus)
		}
	}
}
