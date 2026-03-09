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

package kubevirt

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	kubevirtv1 "kubevirt.io/api/core/v1"
	kubevirtcorev1 "kubevirt.io/client-go/kubevirt/typed/core/v1"
)

// TryCreateInformers attempts to create SharedIndexInformers for KubeVirt
// VirtualMachine and VirtualMachineInstance resources. Returns (nil, nil, nil)
// if KubeVirt is not installed in the cluster.
func TryCreateInformers(restConfig *rest.Config, resyncPeriod time.Duration) (cache.SharedIndexInformer, cache.SharedIndexInformer, error) {
	if restConfig == nil {
		return nil, nil, nil
	}

	// Check if KubeVirt API group is available.
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(restConfig)
	if err != nil {
		return nil, nil, err
	}
	installed, err := IsKubeVirtInstalled(discoveryClient)
	if err != nil {
		log.WithError(err).Warn("Failed to detect kubevirt installation")
		return nil, nil, nil
	}
	if !installed {
		return nil, nil, nil
	}

	// Create the typed kubevirt client for ListWatch operations.
	kvClient, err := kubevirtcorev1.NewForConfig(restConfig)
	if err != nil {
		return nil, nil, err
	}

	vmInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListWithContextFunc: func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
				return kvClient.VirtualMachines("").List(ctx, options)
			},
			WatchFuncWithContext: func(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
				return kvClient.VirtualMachines("").Watch(ctx, options)
			},
		},
		&kubevirtv1.VirtualMachine{},
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	vmiInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListWithContextFunc: func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
				return kvClient.VirtualMachineInstances("").List(ctx, options)
			},
			WatchFuncWithContext: func(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
				return kvClient.VirtualMachineInstances("").Watch(ctx, options)
			},
		},
		&kubevirtv1.VirtualMachineInstance{},
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	log.Info("Created KubeVirt VM and VMI informers")
	return vmInformer, vmiInformer, nil
}

// NewIndexerFunc returns a GetIndexerFunc that calls TryCreateInformers with
// the given config and resync period.
func NewIndexerFunc(restConfig *rest.Config, resyncPeriod time.Duration) GetIndexerFunc {
	return func() (cache.SharedIndexInformer, cache.SharedIndexInformer, error) {
		return TryCreateInformers(restConfig, resyncPeriod)
	}
}
