// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package calico

import (
	"context"
	"reflect"

	aapi "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// NewQoSPolicyStorage creates a new libcalico-based storage.Interface implementation for QoSPolicies
func NewQoSPolicyStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.QoSPolicy)
		return c.QoSPolicies().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.QoSPolicy)
		return c.QoSPolicies().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.QoSPolicies().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.QoSPolicies().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.QoSPolicies().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.QoSPolicies().Watch(ctx, olo)
	}
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeOf(aapi.QoSPolicy{}),
		aapiListType:      reflect.TypeOf(aapi.QoSPolicyList{}),
		libCalicoType:     reflect.TypeOf(api.QoSPolicy{}),
		libCalicoListType: reflect.TypeOf(api.QoSPolicyList{}),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "QoSPolicy",
		converter:         QoSPolicyConverter{},
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type QoSPolicyConverter struct {
}

func (gc QoSPolicyConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiQoSPolicy := aapiObj.(*aapi.QoSPolicy)
	lcgQoSPolicy := &api.QoSPolicy{}
	lcgQoSPolicy.TypeMeta = aapiQoSPolicy.TypeMeta
	lcgQoSPolicy.ObjectMeta = aapiQoSPolicy.ObjectMeta
	lcgQoSPolicy.Kind = api.KindQoSPolicy
	lcgQoSPolicy.APIVersion = api.GroupVersionCurrent
	lcgQoSPolicy.Spec = aapiQoSPolicy.Spec
	return lcgQoSPolicy
}

func (gc QoSPolicyConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgQoSPolicy := libcalicoObject.(*api.QoSPolicy)
	aapiQoSPolicy := aapiObj.(*aapi.QoSPolicy)
	aapiQoSPolicy.Spec = lcgQoSPolicy.Spec
	aapiQoSPolicy.TypeMeta = lcgQoSPolicy.TypeMeta
	aapiQoSPolicy.ObjectMeta = lcgQoSPolicy.ObjectMeta
}

func (gc QoSPolicyConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgQoSPolicyList := libcalicoListObject.(*api.QoSPolicyList)
	aapiQoSPolicyList := aapiListObj.(*aapi.QoSPolicyList)
	if libcalicoListObject == nil {
		aapiQoSPolicyList.Items = []aapi.QoSPolicy{}
		return
	}
	aapiQoSPolicyList.TypeMeta = lcgQoSPolicyList.TypeMeta
	aapiQoSPolicyList.ListMeta = lcgQoSPolicyList.ListMeta
	for _, item := range lcgQoSPolicyList.Items {
		aapiQoSPolicy := aapi.QoSPolicy{}
		gc.convertToAAPI(&item, &aapiQoSPolicy)
		if matched, err := pred.Matches(&aapiQoSPolicy); err == nil && matched {
			aapiQoSPolicyList.Items = append(aapiQoSPolicyList.Items, aapiQoSPolicy)
		}
	}
}
