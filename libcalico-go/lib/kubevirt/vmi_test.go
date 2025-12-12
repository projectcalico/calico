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

package kubevirt_test

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubevirtv1 "kubevirt.io/api/core/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
)

// TestGetPodVMIInfo_NotVirtLauncherPod tests that non-virt-launcher pods return nil.
func TestGetPodVMIInfo_NotVirtLauncherPod(t *testing.T) {
	fakeClient := kubevirt.NewFakeVirtClient()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "regular-pod",
			Namespace: "default",
			UID:       "pod-123",
		},
	}

	info, err := kubevirt.GetPodVMIInfo(pod, fakeClient)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if info != nil {
		t.Errorf("Expected nil info for non-virt-launcher pod, got: %+v", info)
	}
}

// TestGetPodVMIInfo_VirtLauncherPod tests that virt-launcher pods are correctly identified.
func TestGetPodVMIInfo_VirtLauncherPod(t *testing.T) {
	fakeClient := kubevirt.NewFakeVirtClient()

	vmiUID := "vmi-12345"
	vmiName := "test-vmi"
	podUID := "pod-67890"
	namespace := "default"

	// Create a VMI
	vmi := kubevirt.NewVMIBuilder(vmiName, namespace, vmiUID).
		WithActivePod(podUID, "node1").
		Build()
	fakeClient.AddVMI(vmi)

	// Create a pod owned by the VMI
	controllerTrue := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "virt-launcher-test-vmi-abcde",
			Namespace: namespace,
			UID:       types.UID(podUID),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "kubevirt.io/v1",
					Kind:       "VirtualMachineInstance",
					Name:       vmiName,
					UID:        types.UID(vmiUID),
					Controller: &controllerTrue,
				},
			},
		},
	}

	info, err := kubevirt.GetPodVMIInfo(pod, fakeClient)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if info == nil {
		t.Fatal("Expected PodVMIInfo, got nil")
	}

	if info.GetName() != vmiName {
		t.Errorf("Expected VMI name %s, got %s", vmiName, info.GetName())
	}
	if info.GetUID() != vmiUID {
		t.Errorf("Expected VMI UID %s, got %s", vmiUID, info.GetUID())
	}
	if info.VMIResource == nil {
		t.Error("Expected VMIResource to be non-nil")
	}
	if info.IsMigrationTarget() {
		t.Error("Expected IsMigrationTarget to be false")
	}
}

// TestGetPodVMIInfo_MigrationTargetPod tests migration target pod detection.
func TestGetPodVMIInfo_MigrationTargetPod(t *testing.T) {
	fakeClient := kubevirt.NewFakeVirtClient()

	vmiUID := "vmi-12345"
	vmiName := "test-vmi"
	sourcePodUID := "pod-source"
	targetPodUID := "pod-target"
	targetPodName := "virt-launcher-test-vmi-target"
	migrationUID := "migration-99999"
	migrationName := "test-migration"
	namespace := "default"

	// Create a VMI with migration in progress
	vmi := kubevirt.NewVMIBuilder(vmiName, namespace, vmiUID).
		WithActivePod(sourcePodUID, "node1").
		WithActivePod(targetPodUID, "node2").
		WithMigration(migrationUID, "virt-launcher-test-vmi-source", targetPodName).
		Build()
	fakeClient.AddVMI(vmi)

	// Create the VMIM resource that corresponds to the migration
	vmim := &kubevirtv1.VirtualMachineInstanceMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      migrationName,
			Namespace: namespace,
			UID:       types.UID(migrationUID),
		},
		Spec: kubevirtv1.VirtualMachineInstanceMigrationSpec{
			VMIName: vmiName,
		},
	}
	fakeClient.AddMigration(vmim)

	// Create target pod with migration label
	controllerTrue := true
	targetPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      targetPodName,
			Namespace: namespace,
			UID:       types.UID(targetPodUID),
			Labels: map[string]string{
				kubevirt.LabelKubeVirtMigrationJobUID: migrationUID,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "kubevirt.io/v1",
					Kind:       "VirtualMachineInstance",
					Name:       vmiName,
					UID:        types.UID(vmiUID),
					Controller: &controllerTrue,
				},
			},
		},
	}

	info, err := kubevirt.GetPodVMIInfo(targetPod, fakeClient)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if info == nil {
		t.Fatal("Expected PodVMIInfo, got nil")
	}

	if !info.IsMigrationTarget() {
		t.Error("Expected IsMigrationTarget to be true")
	}
	if info.GetVMIMigrationUID() != migrationUID {
		t.Errorf("Expected migration UID %s, got %s", migrationUID, info.GetVMIMigrationUID())
	}
}

// TestGetPodVMIInfo_VMIBeingDeleted tests VMI deletion detection.
func TestGetPodVMIInfo_VMIBeingDeleted(t *testing.T) {
	fakeClient := kubevirt.NewFakeVirtClient()

	vmiUID := "vmi-12345"
	vmiName := "test-vmi"
	vmUID := "vm-12345"
	vmName := "test-vm"
	podUID := "pod-67890"
	namespace := "default"

	// Create a VM with deletion timestamp
	now := metav1.Now()
	vm := &kubevirtv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:              vmName,
			Namespace:         namespace,
			UID:               types.UID(vmUID),
			DeletionTimestamp: &now,
		},
	}
	fakeClient.AddVM(vm)

	// Create a VMI with ownerReference to the VM
	controllerTrue := true
	blockOwnerDeletion := true
	vmi := kubevirt.NewVMIBuilder(vmiName, namespace, vmiUID).
		WithActivePod(podUID, "node1").
		Build()
	vmi.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion:         "kubevirt.io/v1",
			Kind:               "VirtualMachine",
			Name:               vmName,
			UID:                types.UID(vmUID),
			Controller:         &controllerTrue,
			BlockOwnerDeletion: &blockOwnerDeletion,
		},
	}
	fakeClient.AddVMI(vmi)

	// Create a pod owned by the VMI
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "virt-launcher-test-vmi-abcde",
			Namespace: namespace,
			UID:       types.UID(podUID),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "kubevirt.io/v1",
					Kind:       "VirtualMachineInstance",
					Name:       vmiName,
					UID:        types.UID(vmiUID),
					Controller: &controllerTrue,
				},
			},
		},
	}

	info, err := kubevirt.GetPodVMIInfo(pod, fakeClient)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if info == nil {
		t.Fatal("Expected PodVMIInfo, got nil")
	}

	if !info.IsVMObjectDeletionInProgress() {
		t.Error("Expected IsVMObjectDeletionInProgress to be true")
	}
}

// TestVerifyVMIMByUID_Found tests that VerifyVMIMByUID finds a VMIM by UID.
func TestVerifyVMIMByUID_Found(t *testing.T) {
	fakeClient := kubevirt.NewFakeVirtClient()

	migrationUID := "migration-12345"
	migrationName := "test-migration"
	namespace := "default"

	// Create a VMIM
	vmim := &kubevirtv1.VirtualMachineInstanceMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      migrationName,
			Namespace: namespace,
			UID:       types.UID(migrationUID),
		},
		Spec: kubevirtv1.VirtualMachineInstanceMigrationSpec{
			VMIName: "test-vmi",
		},
	}
	fakeClient.AddMigration(vmim)

	// Verify VMIM by UID
	found, err := kubevirt.VerifyVMIMByUID(nil, fakeClient, namespace, migrationUID)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if found == nil {
		t.Fatal("Expected VMIM to be found, got nil")
	}
	if found.Name != migrationName {
		t.Errorf("Expected VMIM name %s, got %s", migrationName, found.Name)
	}
	if string(found.UID) != migrationUID {
		t.Errorf("Expected VMIM UID %s, got %s", migrationUID, found.UID)
	}
}

// TestVerifyVMIMByUID_NotFound tests that VerifyVMIMByUID returns nil when VMIM is not found.
func TestVerifyVMIMByUID_NotFound(t *testing.T) {
	fakeClient := kubevirt.NewFakeVirtClient()

	namespace := "default"
	nonExistentUID := "migration-nonexistent"

	// Verify VMIM by UID (should not be found)
	found, err := kubevirt.VerifyVMIMByUID(nil, fakeClient, namespace, nonExistentUID)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if found != nil {
		t.Errorf("Expected VMIM to be nil (not found), got: %+v", found)
	}
}

// TestVerifyVMIMByUID_EmptyUID tests that VerifyVMIMByUID returns an error for empty UID.
func TestVerifyVMIMByUID_EmptyUID(t *testing.T) {
	fakeClient := kubevirt.NewFakeVirtClient()

	namespace := "default"

	// Verify VMIM with empty UID (should return error)
	found, err := kubevirt.VerifyVMIMByUID(nil, fakeClient, namespace, "")
	if err == nil {
		t.Error("Expected error for empty UID, got nil")
	}
	if found != nil {
		t.Errorf("Expected VMIM to be nil when error occurs, got: %+v", found)
	}
}

// TestVerifyVMIMByUID_MultipleVMIMs tests that VerifyVMIMByUID finds the correct VMIM when multiple exist.
func TestVerifyVMIMByUID_MultipleVMIMs(t *testing.T) {
	fakeClient := kubevirt.NewFakeVirtClient()

	namespace := "default"
	targetUID := "migration-target"
	otherUID := "migration-other"

	// Create multiple VMIMs
	vmim1 := &kubevirtv1.VirtualMachineInstanceMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "migration-1",
			Namespace: namespace,
			UID:       types.UID(targetUID),
		},
		Spec: kubevirtv1.VirtualMachineInstanceMigrationSpec{
			VMIName: "vmi-1",
		},
	}
	vmim2 := &kubevirtv1.VirtualMachineInstanceMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "migration-2",
			Namespace: namespace,
			UID:       types.UID(otherUID),
		},
		Spec: kubevirtv1.VirtualMachineInstanceMigrationSpec{
			VMIName: "vmi-2",
		},
	}
	fakeClient.AddMigration(vmim1)
	fakeClient.AddMigration(vmim2)

	// Verify VMIM by target UID
	found, err := kubevirt.VerifyVMIMByUID(nil, fakeClient, namespace, targetUID)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if found == nil {
		t.Fatal("Expected VMIM to be found, got nil")
	}
	if string(found.UID) != targetUID {
		t.Errorf("Expected VMIM UID %s, got %s", targetUID, found.UID)
	}
	if found.Name != "migration-1" {
		t.Errorf("Expected VMIM name migration-1, got %s", found.Name)
	}
}

// TestGetPodVMIInfo_MigrationTargetPod_NoVMIM tests that GetPodVMIInfo returns an error
// when a pod claims to be a migration target but the VMIM doesn't exist.
func TestGetPodVMIInfo_MigrationTargetPod_NoVMIM(t *testing.T) {
	fakeClient := kubevirt.NewFakeVirtClient()

	vmiUID := "vmi-12345"
	vmiName := "test-vmi"
	targetPodUID := "pod-target"
	targetPodName := "virt-launcher-test-vmi-target"
	migrationUID := "migration-nonexistent"
	namespace := "default"

	// Create a VMI (but no VMIM)
	vmi := kubevirt.NewVMIBuilder(vmiName, namespace, vmiUID).
		WithActivePod(targetPodUID, "node1").
		Build()
	fakeClient.AddVMI(vmi)

	// Create target pod with migration label but no corresponding VMIM
	controllerTrue := true
	targetPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      targetPodName,
			Namespace: namespace,
			UID:       types.UID(targetPodUID),
			Labels: map[string]string{
				kubevirt.LabelKubeVirtMigrationJobUID: migrationUID,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "kubevirt.io/v1",
					Kind:       "VirtualMachineInstance",
					Name:       vmiName,
					UID:        types.UID(vmiUID),
					Controller: &controllerTrue,
				},
			},
		},
	}

	info, err := kubevirt.GetPodVMIInfo(targetPod, fakeClient)
	if err == nil {
		t.Error("Expected error when VMIM doesn't exist, got nil")
	}
	if info != nil {
		t.Errorf("Expected nil info when error occurs, got: %+v", info)
	}
	if err != nil && err.Error() == "" {
		t.Error("Expected non-empty error message")
	}
}
