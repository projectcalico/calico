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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubevirtv1 "kubevirt.io/api/core/v1"
)

// VirtClientInterface defines the minimal KubeVirt client interface needed for VirtualMachineInstance, VirtualMachine, and VirtualMachineInstanceMigration operations.
// This interface allows for easy mocking and testing without requiring a real KubeVirt cluster.
type VirtClientInterface interface {
	// VirtualMachineInstance returns an interface for VirtualMachineInstance operations in the given namespace.
	VirtualMachineInstance(namespace string) VMIInterface

	// VirtualMachine returns an interface for VirtualMachine operations in the given namespace.
	VirtualMachine(namespace string) VMInterface

	// VirtualMachineInstanceMigration returns an interface for VirtualMachineInstanceMigration operations in the given namespace.
	VirtualMachineInstanceMigration(namespace string) VMIMInterface
}

// VMIInterface defines the VirtualMachineInstance operations we need.
type VMIInterface interface {
	// Get retrieves a VirtualMachineInstance by name.
	Get(ctx context.Context, name string, options metav1.GetOptions) (*kubevirtv1.VirtualMachineInstance, error)
	// List retrieves all VirtualMachineInstances in the namespace.
	List(ctx context.Context, options metav1.ListOptions) (*kubevirtv1.VirtualMachineInstanceList, error)
}

// VMInterface defines the VirtualMachine operations we need.
type VMInterface interface {
	// Get retrieves a VirtualMachine by name.
	Get(ctx context.Context, name string, options metav1.GetOptions) (*kubevirtv1.VirtualMachine, error)
	// List retrieves all VirtualMachines in the namespace.
	List(ctx context.Context, options metav1.ListOptions) (*kubevirtv1.VirtualMachineList, error)
}

// VMIMInterface defines the VirtualMachineInstanceMigration operations we need.
type VMIMInterface interface {
	// Get retrieves a VirtualMachineInstanceMigration by name.
	Get(ctx context.Context, name string, options metav1.GetOptions) (*kubevirtv1.VirtualMachineInstanceMigration, error)
	// List retrieves all VirtualMachineInstanceMigrations in the namespace.
	List(ctx context.Context, options metav1.ListOptions) (*kubevirtv1.VirtualMachineInstanceMigrationList, error)
}
