// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package calico

import (
	"reflect"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// NewTierStorage creates a new libcalico-based storage.Interface implementation for Tiers
func NewTierStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.Tier)
		return c.Tiers().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.Tier)
		return c.Tiers().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.Tiers().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.Tiers().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.Tiers().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.Tiers().Watch(ctx, olo)
	}

	// TODO(doublek): Inject codec, client for nicer testing.
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeOf(v3.Tier{}),
		aapiListType:      reflect.TypeOf(v3.TierList{}),
		libCalicoType:     reflect.TypeOf(v3.Tier{}),
		libCalicoListType: reflect.TypeOf(v3.TierList{}),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "Tier",
		converter:         TierConverter{},
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type TierConverter struct {
}

func (tc TierConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiTier := aapiObj.(*v3.Tier)
	lcgTier := &v3.Tier{}
	lcgTier.TypeMeta = aapiTier.TypeMeta
	lcgTier.ObjectMeta = aapiTier.ObjectMeta
	lcgTier.Kind = v3.KindTier
	lcgTier.APIVersion = v3.GroupVersionCurrent
	lcgTier.Spec = aapiTier.Spec
	return lcgTier
}

func (tc TierConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgTier := libcalicoObject.(*v3.Tier)
	aapiTier := aapiObj.(*v3.Tier)
	aapiTier.Spec = lcgTier.Spec
	aapiTier.TypeMeta = lcgTier.TypeMeta
	aapiTier.ObjectMeta = lcgTier.ObjectMeta
}

func (tc TierConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgTierList := libcalicoListObject.(*v3.TierList)
	aapiTierList := aapiListObj.(*v3.TierList)
	if libcalicoListObject == nil {
		aapiTierList.Items = []v3.Tier{}
		return
	}
	aapiTierList.TypeMeta = lcgTierList.TypeMeta
	aapiTierList.ListMeta = lcgTierList.ListMeta
	for _, item := range lcgTierList.Items {
		aapiTier := v3.Tier{}
		tc.convertToAAPI(&item, &aapiTier)
		if matched, err := pred.Matches(&aapiTier); err == nil && matched {
			aapiTierList.Items = append(aapiTierList.Items, aapiTier)
		}
	}
}
