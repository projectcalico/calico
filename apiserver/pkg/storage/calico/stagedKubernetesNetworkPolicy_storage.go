// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// NewStagedKubernetesNetworkPolicyStorage creates a new libcalico-based storage.Interface implementation for Policy
func NewStagedKubernetesNetworkPolicyStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.StagedKubernetesNetworkPolicy)
		return c.StagedKubernetesNetworkPolicies().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.StagedKubernetesNetworkPolicy)
		return c.StagedKubernetesNetworkPolicies().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.StagedKubernetesNetworkPolicies().Get(ctx, ns, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.StagedKubernetesNetworkPolicies().Delete(ctx, ns, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.StagedKubernetesNetworkPolicies().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.StagedKubernetesNetworkPolicies().Watch(ctx, olo)
	}

	// TODO(doublek): Inject codec, client for nicer testing.
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         &APIObjectVersioner{},
		aapiType:          reflect.TypeOf(v3.StagedKubernetesNetworkPolicy{}),
		aapiListType:      reflect.TypeOf(v3.StagedKubernetesNetworkPolicyList{}),
		libCalicoType:     reflect.TypeOf(v3.StagedKubernetesNetworkPolicy{}),
		libCalicoListType: reflect.TypeOf(v3.StagedKubernetesNetworkPolicyList{}),
		isNamespaced:      true,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "StagedKubernetesNetworkPolicy",
		converter:         StagedKubernetesNetworkPolicyConverter{},
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type StagedKubernetesNetworkPolicyConverter struct {
}

func (rc StagedKubernetesNetworkPolicyConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiPolicy := aapiObj.(*v3.StagedKubernetesNetworkPolicy)
	lcgPolicy := &v3.StagedKubernetesNetworkPolicy{}
	lcgPolicy.TypeMeta = aapiPolicy.TypeMeta
	lcgPolicy.ObjectMeta = aapiPolicy.ObjectMeta
	lcgPolicy.Kind = v3.KindStagedKubernetesNetworkPolicy
	lcgPolicy.APIVersion = v3.GroupVersionCurrent
	lcgPolicy.Spec = aapiPolicy.Spec
	return lcgPolicy
}

func (rc StagedKubernetesNetworkPolicyConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgPolicy := libcalicoObject.(*v3.StagedKubernetesNetworkPolicy)
	aapiPolicy := aapiObj.(*v3.StagedKubernetesNetworkPolicy)
	aapiPolicy.Spec = lcgPolicy.Spec
	aapiPolicy.TypeMeta = lcgPolicy.TypeMeta
	aapiPolicy.ObjectMeta = lcgPolicy.ObjectMeta
	// Labeling Purely for kubectl purposes. ex: kubectl get globalnetworkpolicies -l projectcalico.org/tier=net-sec
	// kubectl 1.9 should come out with support for field selector.
	// Workflows associated with label "projectcalico.org/tier" should be deprecated thereafter.
	if aapiPolicy.Labels == nil {
		aapiPolicy.Labels = make(map[string]string)
	}
}

func (rc StagedKubernetesNetworkPolicyConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgPolicyList := libcalicoListObject.(*v3.StagedKubernetesNetworkPolicyList)
	aapiPolicyList := aapiListObj.(*v3.StagedKubernetesNetworkPolicyList)
	if libcalicoListObject == nil {
		aapiPolicyList.Items = []v3.StagedKubernetesNetworkPolicy{}
		return
	}
	aapiPolicyList.TypeMeta = lcgPolicyList.TypeMeta
	aapiPolicyList.ListMeta = lcgPolicyList.ListMeta

	for _, item := range lcgPolicyList.Items {
		aapiPolicy := v3.StagedKubernetesNetworkPolicy{}
		rc.convertToAAPI(&item, &aapiPolicy)
		aapiPolicyList.Items = append(aapiPolicyList.Items, aapiPolicy)
	}
}
