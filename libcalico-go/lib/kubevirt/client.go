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

// This file provides utilities for creating KubeVirt clients.
package kubevirt

import (
	"fmt"

	"k8s.io/client-go/rest"
	kubevirtcorev1 "kubevirt.io/client-go/kubevirt/typed/core/v1"
)

// NewVirtClient creates a VirtClientInterface from a rest.Config.
func NewVirtClient(restConfig *rest.Config) (VirtClientInterface, error) {
	kvClient, err := kubevirtcorev1.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain KubeVirt client: %w", err)
	}
	return &virtClientAdapter{client: kvClient}, nil
}

// virtClientAdapter adapts the typed KubeVirt client to our VirtClientInterface.
type virtClientAdapter struct {
	client kubevirtcorev1.KubevirtV1Interface
}

// VirtualMachineInstance implements VirtClientInterface.
func (v *virtClientAdapter) VirtualMachineInstance(namespace string) VMIInterface {
	return v.client.VirtualMachineInstances(namespace)
}

// VirtualMachine implements VirtClientInterface.
func (v *virtClientAdapter) VirtualMachine(namespace string) VMInterface {
	return v.client.VirtualMachines(namespace)
}

// VirtualMachineInstanceMigration implements VirtClientInterface.
func (v *virtClientAdapter) VirtualMachineInstanceMigration(namespace string) VMIMInterface {
	return v.client.VirtualMachineInstanceMigrations(namespace)
}
