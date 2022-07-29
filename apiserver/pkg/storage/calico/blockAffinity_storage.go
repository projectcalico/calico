// Copyright (c) 2022 Tigera, Inc. All rights reserved.
//
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
	"fmt"
	"reflect"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	etcd "k8s.io/apiserver/pkg/storage/etcd3"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"

	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"

	aapi "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

// NewBlockAffinityStorage creates a new libcalico-based storage.Interface implementation for BlockAffinity
func NewBlockAffinityStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		return nil, fmt.Errorf("Unable to create block affinity. Block affinity resources are read-only.")
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		return nil, fmt.Errorf("Unable to update block affinity. Block affinity resources are read-only.")
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.BlockAffinities().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		return nil, fmt.Errorf("Unable to delete block affinity. Block affinity resources are read-only.")
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.BlockAffinities().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.BlockAffinities().Watch(ctx, olo)
	}
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         etcd.APIObjectVersioner{},
		aapiType:          reflect.TypeOf(aapi.BlockAffinity{}),
		aapiListType:      reflect.TypeOf(aapi.BlockAffinityList{}),
		libCalicoType:     reflect.TypeOf(libapi.BlockAffinity{}),
		libCalicoListType: reflect.TypeOf(libapi.BlockAffinityList{}),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "BlockAffinity",
		converter:         BlockAffinityConverter{},
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type BlockAffinityConverter struct {
}

func (gc BlockAffinityConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	var lcgBlockAffinity *libapi.BlockAffinity
	// This is should not be called since block affinities are read-only through the AAPI.
	log.Error("Block affinity API is read-only. Should not attempt to create/update block affinities through the API.")
	return lcgBlockAffinity
}

func (gc BlockAffinityConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgBlockAffinity := libcalicoObject.(*libapi.BlockAffinity)
	aapiBlockAffinity := aapiObj.(*aapi.BlockAffinity)
	aapiBlockAffinity.Spec.State = lcgBlockAffinity.Spec.State
	aapiBlockAffinity.Spec.Node = lcgBlockAffinity.Spec.Node
	aapiBlockAffinity.Spec.CIDR = lcgBlockAffinity.Spec.CIDR
	// Treat the Deleted field specially. Since it is a string for backwards compatibility reasons,
	// ignore the value if it is "false" so that the field will be omitted when displayed by the API.
	// This is fine because the block affinity API is read-only.
	if lcgBlockAffinity.Spec.Deleted == fmt.Sprintf("%t", true) {
		aapiBlockAffinity.Spec.Deleted = lcgBlockAffinity.Spec.Deleted
	}
	aapiBlockAffinity.TypeMeta = lcgBlockAffinity.TypeMeta
	aapiBlockAffinity.ObjectMeta = lcgBlockAffinity.ObjectMeta
}

func (gc BlockAffinityConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgBlockAffinityList := libcalicoListObject.(*libapi.BlockAffinityList)
	aapiBlockAffinityList := aapiListObj.(*aapi.BlockAffinityList)
	if libcalicoListObject == nil {
		aapiBlockAffinityList.Items = []aapi.BlockAffinity{}
		return
	}
	aapiBlockAffinityList.TypeMeta = lcgBlockAffinityList.TypeMeta
	aapiBlockAffinityList.ListMeta = lcgBlockAffinityList.ListMeta
	for _, item := range lcgBlockAffinityList.Items {
		aapiBlockAffinity := aapi.BlockAffinity{}
		gc.convertToAAPI(&item, &aapiBlockAffinity)
		if matched, err := pred.Matches(&aapiBlockAffinity); err == nil && matched {
			aapiBlockAffinityList.Items = append(aapiBlockAffinityList.Items, aapiBlockAffinity)
		}
	}
}
