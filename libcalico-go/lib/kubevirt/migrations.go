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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	kubevirtv1 "kubevirt.io/api/core/v1"
	kubevirtcorev1 "kubevirt.io/client-go/kubevirt/typed/core/v1"
)

// MigrationsByVMIIndex indexes VirtualMachineInstanceMigrations by the
// namespace/name of the VMI they migrate.
const MigrationsByVMIIndex = "migrationsByVMI"

// GetMigrationInformerFunc creates a KubeVirt VirtualMachineInstanceMigration
// informer, indexed by MigrationsByVMIIndex.
type GetMigrationInformerFunc func() (cache.SharedIndexInformer, error)

// NewDeferredInformersWithMigrations is NewDeferredInformers plus a VMIM
// informer, created by createMigrations once KubeVirt is found. See
// MigrationIndexer and EventHandlers.MigrationsSynced for when it is ready.
func NewDeferredInformersWithMigrations(
	createInformers GetIndexInformerFunc, createMigrations GetMigrationInformerFunc, pollInterval time.Duration, stop <-chan struct{},
) *DeferredInformers {
	d := &DeferredInformers{createMigrations: createMigrations}
	go d.initInformers(createInformers, pollInterval, stop)
	return d
}

// NewMigrationInformerFunc returns a GetMigrationInformerFunc with the given
// config and resync period.
func NewMigrationInformerFunc(restConfig *rest.Config, resyncPeriod time.Duration) GetMigrationInformerFunc {
	return func() (cache.SharedIndexInformer, error) {
		kvClient, err := kubevirtcorev1.NewForConfig(restConfig)
		if err != nil {
			return nil, err
		}
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListWithContextFunc: func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
					return kvClient.VirtualMachineInstanceMigrations("").List(ctx, options)
				},
				WatchFuncWithContext: func(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
					return kvClient.VirtualMachineInstanceMigrations("").Watch(ctx, options)
				},
			},
			&kubevirtv1.VirtualMachineInstanceMigration{},
			resyncPeriod,
			cache.Indexers{MigrationsByVMIIndex: MigrationVMIKey},
		), nil
	}
}

// MigrationVMIKey is the index func behind MigrationsByVMIIndex. It keys a
// VMIM by the namespace/name of the VMI it migrates, and gives no key to a VMIM
// without a VMI name or to any other object.
func MigrationVMIKey(obj any) ([]string, error) {
	m, ok := obj.(*kubevirtv1.VirtualMachineInstanceMigration)
	if !ok || m.Spec.VMIName == "" {
		return nil, nil
	}
	return []string{cache.NewObjectName(m.Namespace, m.Spec.VMIName).String()}, nil
}
