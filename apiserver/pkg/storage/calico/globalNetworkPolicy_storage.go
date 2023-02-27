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

// NewGlobalNetworkPolicyStorage creates a new libcalico-based storage.Interface implementation for GlobalNetworkPolicies
func NewGlobalNetworkPolicyStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.GlobalNetworkPolicy)
		return c.GlobalNetworkPolicies().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.GlobalNetworkPolicy)
		return c.GlobalNetworkPolicies().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.GlobalNetworkPolicies().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.GlobalNetworkPolicies().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.GlobalNetworkPolicies().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.GlobalNetworkPolicies().Watch(ctx, olo)
	}
	// TODO(doublek): Inject codec, client for nicer testing.
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeOf(aapi.GlobalNetworkPolicy{}),
		aapiListType:      reflect.TypeOf(aapi.GlobalNetworkPolicyList{}),
		libCalicoType:     reflect.TypeOf(api.GlobalNetworkPolicy{}),
		libCalicoListType: reflect.TypeOf(api.GlobalNetworkPolicyList{}),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "GlobalNetworkPolicy",
		converter:         GlobalNetworkPolicyConverter{},
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type GlobalNetworkPolicyConverter struct {
}

func (gc GlobalNetworkPolicyConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiGlobalNetworkPolicy := aapiObj.(*aapi.GlobalNetworkPolicy)
	lcgGlobalNetworkPolicy := &api.GlobalNetworkPolicy{}
	lcgGlobalNetworkPolicy.TypeMeta = aapiGlobalNetworkPolicy.TypeMeta
	lcgGlobalNetworkPolicy.ObjectMeta = aapiGlobalNetworkPolicy.ObjectMeta
	lcgGlobalNetworkPolicy.Kind = api.KindGlobalNetworkPolicy
	lcgGlobalNetworkPolicy.APIVersion = api.GroupVersionCurrent
	lcgGlobalNetworkPolicy.Spec = aapiGlobalNetworkPolicy.Spec
	return lcgGlobalNetworkPolicy
}

func (gc GlobalNetworkPolicyConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgGlobalNetworkPolicy := libcalicoObject.(*api.GlobalNetworkPolicy)
	aapiGlobalNetworkPolicy := aapiObj.(*aapi.GlobalNetworkPolicy)
	aapiGlobalNetworkPolicy.Spec = lcgGlobalNetworkPolicy.Spec
	aapiGlobalNetworkPolicy.TypeMeta = lcgGlobalNetworkPolicy.TypeMeta
	aapiGlobalNetworkPolicy.ObjectMeta = lcgGlobalNetworkPolicy.ObjectMeta
}

func (gc GlobalNetworkPolicyConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgGlobalNetworkPolicyList := libcalicoListObject.(*api.GlobalNetworkPolicyList)
	aapiGlobalNetworkPolicyList := aapiListObj.(*aapi.GlobalNetworkPolicyList)
	if libcalicoListObject == nil {
		aapiGlobalNetworkPolicyList.Items = []aapi.GlobalNetworkPolicy{}
		return
	}
	aapiGlobalNetworkPolicyList.TypeMeta = lcgGlobalNetworkPolicyList.TypeMeta
	aapiGlobalNetworkPolicyList.ListMeta = lcgGlobalNetworkPolicyList.ListMeta
	for _, item := range lcgGlobalNetworkPolicyList.Items {
		aapiGlobalNetworkPolicy := aapi.GlobalNetworkPolicy{}
		gc.convertToAAPI(&item, &aapiGlobalNetworkPolicy)
		if matched, err := pred.Matches(&aapiGlobalNetworkPolicy); err == nil && matched {
			aapiGlobalNetworkPolicyList.Items = append(aapiGlobalNetworkPolicyList.Items, aapiGlobalNetworkPolicy)
		}
	}
}
