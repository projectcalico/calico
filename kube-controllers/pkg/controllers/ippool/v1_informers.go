// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package ippool

import (
	"fmt"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"

	v1scheme "github.com/projectcalico/calico/libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
)

var (
	v1IPPools = schema.GroupVersionResource{
		Group:    v1scheme.GroupName,
		Version:  v1scheme.Version,
		Resource: "ippools",
	}
	v1IPAMBlocks = schema.GroupVersionResource{
		Group:    v1scheme.GroupName,
		Version:  v1scheme.Version,
		Resource: "ipamblocks",
	}
)

// NewV1PoolInformer returns an informer over crd.projectcalico.org/v1 IPPools that stores *v3.IPPool objects.
func NewV1PoolInformer(dyn dynamic.Interface, resync time.Duration) (cache.SharedIndexInformer, error) {
	informer := dynamicinformer.NewDynamicSharedInformerFactory(dyn, resync).ForResource(v1IPPools).Informer()
	if err := informer.SetTransform(transformV1Pool); err != nil {
		return nil, fmt.Errorf("set transform on v1 IPPool informer: %w", err)
	}
	return informer, nil
}

// NewV1BlockInformer returns an informer over crd.projectcalico.org/v1 IPAMBlocks that stores *v3.IPAMBlock objects.
func NewV1BlockInformer(dyn dynamic.Interface, resync time.Duration) (cache.SharedIndexInformer, error) {
	informer := dynamicinformer.NewDynamicSharedInformerFactory(dyn, resync).ForResource(v1IPAMBlocks).Informer()
	if err := informer.SetTransform(transformV1Block); err != nil {
		return nil, fmt.Errorf("set transform on v1 IPAMBlock informer: %w", err)
	}
	return informer, nil
}

// transformV1Pool converts a v1 IPPool into its v3 form, restoring the metadata that v1 keeps in an annotation.
func transformV1Pool(obj any) (any, error) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return obj, nil
	}
	pool := &v3.IPPool{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, pool); err != nil {
		return nil, fmt.Errorf("convert v1 IPPool %s: %w", u.GetName(), err)
	}
	if err := resources.ConvertK8sResourceToCalicoResource(pool); err != nil {
		return nil, fmt.Errorf("restore metadata on v1 IPPool %s: %w", u.GetName(), err)
	}
	pool.TypeMeta = v3.NewIPPool().TypeMeta
	return pool, nil
}

func transformV1Block(obj any) (any, error) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return obj, nil
	}
	block := &v3.IPAMBlock{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, block); err != nil {
		return nil, fmt.Errorf("convert v1 IPAMBlock %s: %w", u.GetName(), err)
	}
	return block, nil
}
