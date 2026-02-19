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
	"sync"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kubevirtv1 "kubevirt.io/api/core/v1"
)

// FakeVirtClient is a fake implementation of VirtClientInterface for testing.
type FakeVirtClient struct {
	mu         sync.RWMutex
	vmis       map[string]map[string]*kubevirtv1.VirtualMachineInstance          // namespace -> name -> VMI
	vms        map[string]map[string]*kubevirtv1.VirtualMachine                  // namespace -> name -> VM
	migrations map[string]map[string]*kubevirtv1.VirtualMachineInstanceMigration // namespace -> name -> VMIM
}

// NewFakeVirtClient creates a new fake VirtClient for testing.
func NewFakeVirtClient() *FakeVirtClient {
	return &FakeVirtClient{
		vmis:       make(map[string]map[string]*kubevirtv1.VirtualMachineInstance),
		vms:        make(map[string]map[string]*kubevirtv1.VirtualMachine),
		migrations: make(map[string]map[string]*kubevirtv1.VirtualMachineInstanceMigration),
	}
}

// VirtualMachineInstance implements VirtClientInterface.
func (f *FakeVirtClient) VirtualMachineInstance(namespace string) VMIInterface {
	return &fakeVMIInterface{
		client:    f,
		namespace: namespace,
	}
}

// VirtualMachine implements VirtClientInterface.
func (f *FakeVirtClient) VirtualMachine(namespace string) VMInterface {
	return &fakeVMInterface{
		client:    f,
		namespace: namespace,
	}
}

// VirtualMachineInstanceMigration implements VirtClientInterface.
func (f *FakeVirtClient) VirtualMachineInstanceMigration(namespace string) VMIMInterface {
	return &fakeVMIMInterface{
		client:    f,
		namespace: namespace,
	}
}

// AddVMI adds a VMI to the fake client.
func (f *FakeVirtClient) AddVMI(vmi *kubevirtv1.VirtualMachineInstance) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.vmis[vmi.Namespace] == nil {
		f.vmis[vmi.Namespace] = make(map[string]*kubevirtv1.VirtualMachineInstance)
	}
	f.vmis[vmi.Namespace][vmi.Name] = vmi.DeepCopy()
}

// DeleteVMI removes a VMI from the fake client.
func (f *FakeVirtClient) DeleteVMI(namespace, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.vmis[namespace] != nil {
		delete(f.vmis[namespace], name)
	}
}

// UpdateVMI updates a VMI in the fake client.
func (f *FakeVirtClient) UpdateVMI(vmi *kubevirtv1.VirtualMachineInstance) {
	f.AddVMI(vmi) // AddVMI already does deep copy
}

// AddVM adds a VM to the fake client.
func (f *FakeVirtClient) AddVM(vm *kubevirtv1.VirtualMachine) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.vms[vm.Namespace] == nil {
		f.vms[vm.Namespace] = make(map[string]*kubevirtv1.VirtualMachine)
	}
	f.vms[vm.Namespace][vm.Name] = vm.DeepCopy()
}

// UpdateVM updates a VM in the fake client.
func (f *FakeVirtClient) UpdateVM(vm *kubevirtv1.VirtualMachine) {
	f.AddVM(vm) // AddVM already does deep copy
}

// fakeVMIInterface is a fake implementation of VMIInterface.
type fakeVMIInterface struct {
	client    *FakeVirtClient
	namespace string
}

// Get implements VMIInterface.
func (f *fakeVMIInterface) Get(ctx context.Context, name string, options metav1.GetOptions) (*kubevirtv1.VirtualMachineInstance, error) {
	f.client.mu.RLock()
	defer f.client.mu.RUnlock()

	nsVMIs, exists := f.client.vmis[f.namespace]
	if !exists {
		return nil, k8serrors.NewNotFound(schema.GroupResource{Group: "kubevirt.io", Resource: "virtualmachineinstances"}, name)
	}

	vmi, exists := nsVMIs[name]
	if !exists {
		return nil, k8serrors.NewNotFound(schema.GroupResource{Group: "kubevirt.io", Resource: "virtualmachineinstances"}, name)
	}

	return vmi.DeepCopy(), nil
}

// List implements VMIInterface.
func (f *fakeVMIInterface) List(ctx context.Context, options metav1.ListOptions) (*kubevirtv1.VirtualMachineInstanceList, error) {
	f.client.mu.RLock()
	defer f.client.mu.RUnlock()

	list := &kubevirtv1.VirtualMachineInstanceList{
		Items: []kubevirtv1.VirtualMachineInstance{},
	}

	nsVMIs, exists := f.client.vmis[f.namespace]
	if !exists {
		return list, nil
	}

	for _, vmi := range nsVMIs {
		list.Items = append(list.Items, *vmi.DeepCopy())
	}

	return list, nil
}

// fakeVMInterface is a fake implementation of VMInterface.
type fakeVMInterface struct {
	client    *FakeVirtClient
	namespace string
}

// Get implements VMInterface.
func (f *fakeVMInterface) Get(ctx context.Context, name string, options metav1.GetOptions) (*kubevirtv1.VirtualMachine, error) {
	f.client.mu.RLock()
	defer f.client.mu.RUnlock()

	nsVMs, exists := f.client.vms[f.namespace]
	if !exists {
		return nil, k8serrors.NewNotFound(schema.GroupResource{Group: "kubevirt.io", Resource: "virtualmachines"}, name)
	}

	vm, exists := nsVMs[name]
	if !exists {
		return nil, k8serrors.NewNotFound(schema.GroupResource{Group: "kubevirt.io", Resource: "virtualmachines"}, name)
	}

	return vm.DeepCopy(), nil
}

// List implements VMInterface.
func (f *fakeVMInterface) List(ctx context.Context, options metav1.ListOptions) (*kubevirtv1.VirtualMachineList, error) {
	f.client.mu.RLock()
	defer f.client.mu.RUnlock()

	list := &kubevirtv1.VirtualMachineList{
		Items: []kubevirtv1.VirtualMachine{},
	}

	nsVMs, exists := f.client.vms[f.namespace]
	if !exists {
		return list, nil
	}

	for _, vm := range nsVMs {
		list.Items = append(list.Items, *vm.DeepCopy())
	}

	return list, nil
}

// VMIBuilder helps construct VMI objects for testing.
type VMIBuilder struct {
	vmi *kubevirtv1.VirtualMachineInstance
}

// NewVMIBuilder creates a new VMI builder.
func NewVMIBuilder(name, namespace, uid string) *VMIBuilder {
	return &VMIBuilder{
		vmi: &kubevirtv1.VirtualMachineInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				UID:       types.UID(uid),
			},
			Status: kubevirtv1.VirtualMachineInstanceStatus{
				ActivePods: make(map[types.UID]string),
			},
		},
	}
}

// WithDeletionTimestamp sets the deletion timestamp on the VMI.
func (b *VMIBuilder) WithDeletionTimestamp(t metav1.Time) *VMIBuilder {
	b.vmi.DeletionTimestamp = &t
	return b
}

// WithActivePod adds a pod to the VMI's ActivePods.
func (b *VMIBuilder) WithActivePod(podUID, nodeName string) *VMIBuilder {
	if b.vmi.Status.ActivePods == nil {
		b.vmi.Status.ActivePods = make(map[types.UID]string)
	}
	b.vmi.Status.ActivePods[types.UID(podUID)] = nodeName
	return b
}

// WithMigration sets the migration state on the VMI.
func (b *VMIBuilder) WithMigration(migrationUID, sourcePod, targetPod string) *VMIBuilder {
	b.vmi.Status.MigrationState = &kubevirtv1.VirtualMachineInstanceMigrationState{
		MigrationUID: types.UID(migrationUID),
		SourcePod:    sourcePod,
		TargetPod:    targetPod,
	}
	return b
}

// Build returns the constructed VMI.
func (b *VMIBuilder) Build() *kubevirtv1.VirtualMachineInstance {
	return b.vmi
}

// AddMigration adds a VirtualMachineInstanceMigration to the fake client.
func (f *FakeVirtClient) AddMigration(vmim *kubevirtv1.VirtualMachineInstanceMigration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.migrations[vmim.Namespace] == nil {
		f.migrations[vmim.Namespace] = make(map[string]*kubevirtv1.VirtualMachineInstanceMigration)
	}
	f.migrations[vmim.Namespace][vmim.Name] = vmim.DeepCopy()
}

// DeleteMigration removes a VirtualMachineInstanceMigration from the fake client.
func (f *FakeVirtClient) DeleteMigration(namespace, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.migrations[namespace] != nil {
		delete(f.migrations[namespace], name)
	}
}

// UpdateMigration updates a VirtualMachineInstanceMigration in the fake client.
func (f *FakeVirtClient) UpdateMigration(vmim *kubevirtv1.VirtualMachineInstanceMigration) {
	f.AddMigration(vmim) // AddMigration already does deep copy
}

// fakeVMIMInterface is a fake implementation of VMIMInterface.
type fakeVMIMInterface struct {
	client    *FakeVirtClient
	namespace string
}

// Get implements VMIMInterface.
func (f *fakeVMIMInterface) Get(ctx context.Context, name string, options metav1.GetOptions) (*kubevirtv1.VirtualMachineInstanceMigration, error) {
	f.client.mu.RLock()
	defer f.client.mu.RUnlock()

	nsMigrations, exists := f.client.migrations[f.namespace]
	if !exists {
		return nil, k8serrors.NewNotFound(schema.GroupResource{Group: "kubevirt.io", Resource: "virtualmachineinstancemigrations"}, name)
	}

	vmim, exists := nsMigrations[name]
	if !exists {
		return nil, k8serrors.NewNotFound(schema.GroupResource{Group: "kubevirt.io", Resource: "virtualmachineinstancemigrations"}, name)
	}

	return vmim.DeepCopy(), nil
}

// List implements VMIMInterface.
func (f *fakeVMIMInterface) List(ctx context.Context, options metav1.ListOptions) (*kubevirtv1.VirtualMachineInstanceMigrationList, error) {
	f.client.mu.RLock()
	defer f.client.mu.RUnlock()

	list := &kubevirtv1.VirtualMachineInstanceMigrationList{
		Items: []kubevirtv1.VirtualMachineInstanceMigration{},
	}

	nsMigrations, exists := f.client.migrations[f.namespace]
	if !exists {
		return list, nil
	}

	for _, vmim := range nsMigrations {
		list.Items = append(list.Items, *vmim.DeepCopy())
	}

	return list, nil
}
