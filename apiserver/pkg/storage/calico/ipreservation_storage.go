// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.

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

// NewIPReservationStorage creates a new libcalico-based storage.Interface implementation for IPReservations
func NewIPReservationStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.IPReservation)
		return c.IPReservations().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.IPReservation)
		return c.IPReservations().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.IPReservations().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.IPReservations().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.IPReservations().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.IPReservations().Watch(ctx, olo)
	}
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeOf(aapi.IPReservation{}),
		aapiListType:      reflect.TypeOf(aapi.IPReservationList{}),
		libCalicoType:     reflect.TypeOf(api.IPReservation{}),
		libCalicoListType: reflect.TypeOf(api.IPReservationList{}),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "IPReservation",
		converter:         IPReservationConverter{},
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type IPReservationConverter struct {
}

func (gc IPReservationConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiIPReservation := aapiObj.(*aapi.IPReservation)
	lcgIPReservation := &api.IPReservation{}
	lcgIPReservation.TypeMeta = aapiIPReservation.TypeMeta
	lcgIPReservation.ObjectMeta = aapiIPReservation.ObjectMeta
	lcgIPReservation.Kind = api.KindIPReservation
	lcgIPReservation.APIVersion = api.GroupVersionCurrent
	lcgIPReservation.Spec = aapiIPReservation.Spec
	return lcgIPReservation
}

func (gc IPReservationConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgIPReservation := libcalicoObject.(*api.IPReservation)
	aapiIPReservation := aapiObj.(*aapi.IPReservation)
	aapiIPReservation.Spec = lcgIPReservation.Spec
	aapiIPReservation.TypeMeta = lcgIPReservation.TypeMeta
	aapiIPReservation.ObjectMeta = lcgIPReservation.ObjectMeta
}

func (gc IPReservationConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgIPReservationList := libcalicoListObject.(*api.IPReservationList)
	aapiIPReservationList := aapiListObj.(*aapi.IPReservationList)
	if libcalicoListObject == nil {
		aapiIPReservationList.Items = []aapi.IPReservation{}
		return
	}
	aapiIPReservationList.TypeMeta = lcgIPReservationList.TypeMeta
	aapiIPReservationList.ListMeta = lcgIPReservationList.ListMeta
	for _, item := range lcgIPReservationList.Items {
		aapiIPReservation := aapi.IPReservation{}
		gc.convertToAAPI(&item, &aapiIPReservation)
		if matched, err := pred.Matches(&aapiIPReservation); err == nil && matched {
			aapiIPReservationList.Items = append(aapiIPReservationList.Items, aapiIPReservation)
		}
	}
}
