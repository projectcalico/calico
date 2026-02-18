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

// This file provides utilities for working with KubeVirt VirtualMachineInstance (VMI) pods.
//
// KubeVirt virt-launcher pods are identified by their ownerReferences, which contain a
// reference to the VirtualMachineInstance that owns the pod. This is the Kubernetes-native
// and most reliable way to determine VMI ownership.
//
// Example pod ownerReferences for a virt-launcher pod:
//
//	ownerReferences:
//	  - apiVersion: kubevirt.io/v1
//	    kind: VirtualMachineInstance
//	    name: vm1
//	    uid: d2ad3ee8-1082-4d61-8202-dbc2432cdd88  # VMI UID
//	    controller: true
//
// During live migration, migration target pods have an additional label:
//
//	labels:
//	  kubevirt.io/migrationJobUID: 122eae59-b197-42c1-a58d-67248f8e5be9  # ONLY ON TARGET POD
//
// Migration scenario:
//   - Source pod: Owned by VMI (via ownerReferences), does NOT have migrationJobUID label
//   - Target pod: Owned by same VMI (via ownerReferences), HAS migrationJobUID label
//
// The VMI UID from ownerReferences remains stable across pod recreations and migrations,
// making it suitable as a basis for IPAM handle IDs to ensure IP address persistence.
package kubevirt

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubevirtv1 "kubevirt.io/api/core/v1"
)

const (
	// LabelKubeVirtMigrationJobUID is only present on migration target pods
	// Value from kubevirtv1.MigrationJobLabel
	LabelKubeVirtMigrationJobUID = kubevirtv1.MigrationJobLabel

	// VMI API Group, Version, and Resource for dynamic client
	VMIGroup   = "kubevirt.io"
	VMIVersion = "v1"

	// VM API Group and Version (same as VMI)
	VMGroup   = "kubevirt.io"
	VMVersion = "v1"
)

// PodVMIInfo contains KubeVirt VMI-related information extracted from a pod's
// ownerReferences and verified against the actual VMI resource via the Kubernetes API.
type PodVMIInfo struct {
	*VMIResource // Embedded: Name, Namespace, UID, VMOwner

	// MigrationJobUID is only present on migration target pods
	// (extracted from the kubevirt.io/migrationJobUID label)
	MigrationJobUID string
}

// VMIResource contains information about a VirtualMachineInstance resource queried from the Kubernetes API
type VMIResource struct {
	// Name is the VMI name
	Name string
	// Namespace is the VMI namespace
	Namespace string
	// UID is the VMI UID
	UID string
	// DeletionTimestamp is the VMI's deletion timestamp (nil if not being deleted)
	DeletionTimestamp *metav1.Time
	// VMOwner is a pointer to the VirtualMachine resource that owns this VMI (if any)
	// This is populated if the VMI has an ownerReference pointing to a VM object
	// nil if the VMI is not owned by a VM
	VMOwner *kubevirtv1.VirtualMachine
}

// IsVMObjectDeletionInProgress returns true if the VM owner has a deletion timestamp set
// Returns false if VMOwner is nil or if VMOwner has no deletion timestamp
func (v *VMIResource) IsVMObjectDeletionInProgress() bool {
	if v == nil || v.VMOwner == nil {
		return false
	}
	return v.VMOwner.DeletionTimestamp != nil && !v.VMOwner.DeletionTimestamp.IsZero()
}

// IsVMIObjectDeletionInProgress returns true if the VMI has a deletion timestamp set
func (v *VMIResource) IsVMIObjectDeletionInProgress() bool {
	if v == nil {
		return false
	}
	return v.DeletionTimestamp != nil && !v.DeletionTimestamp.IsZero()
}

// GetName returns the VMI name
func (v *VMIResource) GetName() string {
	if v == nil {
		return ""
	}
	return v.Name
}

// GetVMIUID returns the VMI UID (explicit name for clarity in KubeVirt IPAM context)
func (v *VMIResource) GetVMIUID() string {
	if v == nil {
		return ""
	}
	return v.UID
}

// GetVMUID returns the UID of the VM object that owns this VMI.
// Returns empty string if VMOwner is nil (VMI is not owned by a VM).
func (v *VMIResource) GetVMUID() string {
	if v == nil || v.VMOwner == nil {
		return ""
	}
	return string(v.VMOwner.UID)
}

// GetNamespace returns the VMI namespace
func (v *VMIResource) GetNamespace() string {
	if v == nil {
		return ""
	}
	return v.Namespace
}

// GetPodVMIInfo determines if a pod is a KubeVirt virt-launcher pod by checking its
// ownerReferences for a VirtualMachineInstance owner, then verifies it against the
// actual VMI resource via the Kubernetes API.
// Returns:
//   - (*PodVMIInfo, nil) if the pod is a valid virt-launcher pod with verified VMI
//   - (nil, nil) if the pod is not owned by a VMI (not a virt-launcher pod)
//   - (nil, error) if verification fails or VMI query fails
func GetPodVMIInfo(pod *corev1.Pod, virtClient VirtClientInterface) (*PodVMIInfo, error) {
	if pod == nil {
		return nil, nil
	}

	// Check ownerReferences to find VMI owner
	// KubeVirt sets the VirtualMachineInstance as the controller owner of virt-launcher pods
	var vmiOwner *metav1.OwnerReference
	for i := range pod.OwnerReferences {
		owner := &pod.OwnerReferences[i]
		if owner.APIVersion == VMIGroup+"/"+VMIVersion &&
			owner.Kind == "VirtualMachineInstance" &&
			owner.Controller != nil && *owner.Controller {
			vmiOwner = owner
			break
		}
	}

	if vmiOwner == nil {
		// Not a virt-launcher pod (no VMI owner)
		return nil, nil
	}

	// Extract VMI name and UID from ownerReference
	vmiName := vmiOwner.Name
	vmiUID := string(vmiOwner.UID)

	if vmiName == "" || vmiUID == "" {
		return nil, fmt.Errorf("pod %s/%s has invalid VMI ownerReference: name=%q uid=%q",
			pod.Namespace, pod.Name, vmiName, vmiUID)
	}

	// Query the actual VMI resource to verify and get complete information
	vmiResource, err := GetVMIResourceByName(
		context.Background(),
		virtClient,
		pod.Namespace,
		vmiName,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query VMI resource %s/%s: %w",
			pod.Namespace, vmiName, err)
	}

	// Verify that the VMI UID from ownerReference matches the actual VMI resource
	if vmiResource.UID != vmiUID {
		return nil, fmt.Errorf("VMI UID mismatch: pod ownerReference has %s but VMI resource has %s",
			vmiUID, vmiResource.UID)
	}

	// Check for migration target label (only label we trust for migration state)
	// This label is only present on migration target pods during live migration
	migrationUIDFromLabel := ""
	if pod.Labels != nil {
		if migrationUID, ok := pod.Labels[LabelKubeVirtMigrationJobUID]; ok {
			migrationUIDFromLabel = migrationUID

			// Verify that the VMIM exists in the cluster
			vmim, err := VerifyVMIMByUID(context.Background(), virtClient, pod.Namespace, migrationUID)
			if err != nil {
				return nil, fmt.Errorf("failed to verify VirtualMachineInstanceMigration with UID %s: %w", migrationUID, err)
			}
			if vmim == nil {
				return nil, fmt.Errorf("pod %s/%s claims to be migration target but VirtualMachineInstanceMigration with UID %s does not exist",
					pod.Namespace, pod.Name, migrationUID)
			}
		}
	}

	// Create PodVMIInfo with embedded VMIResource
	info := &PodVMIInfo{
		VMIResource:     vmiResource,
		MigrationJobUID: migrationUIDFromLabel,
	}

	return info, nil
}

// IsMigrationTarget returns true if this pod is a migration target pod.
// Migration target pods have the kubevirt.io/migrationJobUID label set.
func (v *PodVMIInfo) IsMigrationTarget() bool {
	return v.MigrationJobUID != ""
}

// GetVMIMigrationUID returns the migration job UID.
// Returns empty string if this is not a migration target pod.
func (v *PodVMIInfo) GetVMIMigrationUID() string {
	return v.MigrationJobUID
}

// VerifyVMIMByUID verifies that a VirtualMachineInstanceMigration exists with the given UID
// by querying all VMIMs in the namespace and finding the one matching the UID.
// Returns:
//   - (*VirtualMachineInstanceMigration, nil) if the VMIM is found
//   - (nil, nil) if the VMIM is not found (no error)
//   - (nil, error) if there was an error querying the API
func VerifyVMIMByUID(ctx context.Context, virtClient VirtClientInterface, namespace, migrationUID string) (*kubevirtv1.VirtualMachineInstanceMigration, error) {
	if migrationUID == "" {
		return nil, fmt.Errorf("migration UID cannot be empty")
	}

	// List all VMIMs in the namespace
	vmimList, err := virtClient.VirtualMachineInstanceMigration(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list VirtualMachineInstanceMigrations in namespace %s: %w", namespace, err)
	}

	// Find the VMIM with matching UID
	for i := range vmimList.Items {
		vmim := &vmimList.Items[i]
		if string(vmim.UID) == migrationUID {
			return vmim, nil
		}
	}

	// VMIM not found - return nil, nil (not an error condition)
	return nil, nil
}

// GetVMIResourceByName queries the Kubernetes API for a VirtualMachineInstance with the given name
// and returns a VMIResource containing its metadata.
// If the VMI has an ownerReference pointing to a VirtualMachine, the VM resource is also fetched and stored in VMOwner.
// Returns:
//   - (*VMIResource, nil) if the VMI is found
//   - (nil, error) if there was an error querying the API or VMI not found
func GetVMIResourceByName(ctx context.Context, virtClient VirtClientInterface, namespace, vmiName string) (*VMIResource, error) {
	// Get the VMI
	vmi, err := virtClient.VirtualMachineInstance(namespace).Get(ctx, vmiName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get VMI %s in namespace %s: %w", vmiName, namespace, err)
	}

	vmiResource := &VMIResource{
		Name:              vmi.Name,
		Namespace:         vmi.Namespace,
		UID:               string(vmi.UID),
		DeletionTimestamp: vmi.DeletionTimestamp,
		VMOwner:           nil,
	}

	// Check if VMI has an ownerReference pointing to a VirtualMachine
	var vmOwner *metav1.OwnerReference
	for i := range vmi.OwnerReferences {
		owner := &vmi.OwnerReferences[i]
		if owner.APIVersion == VMGroup+"/"+VMVersion &&
			owner.Kind == "VirtualMachine" {
			vmOwner = owner
			break
		}
	}

	// If VMI is owned by a VM, fetch the VM resource
	if vmOwner != nil && vmOwner.Name != "" {
		vm, err := virtClient.VirtualMachine(namespace).Get(ctx, vmOwner.Name, metav1.GetOptions{})
		if err != nil {
			// VMI has blockOwnerDeletion: true in its ownerReference to VM, Kubernetes will
			// block VM deletion until the VMI is deleted. The VMI has finalizers that must be removed
			// before deletion can proceed.
			return nil, fmt.Errorf("failed to fetch VM owner object %s/%s: %w", namespace, vmOwner.Name, err)
		}
		vmiResource.VMOwner = vm
	}

	return vmiResource, nil
}
