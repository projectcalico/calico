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

package ipam

import (
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"

	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/hash"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Error types for EnsureActiveVMOwnerAttrs
var (
	// ErrAlternateOwnerEmpty is returned when AlternateOwnerAttrs is empty,
	// indicating the target pod was deleted before the promotion could complete.
	ErrAlternateOwnerEmpty = errors.New("AlternateOwnerAttrs is empty")

	// ErrAlternateOwnerMismatch is returned when AlternateOwnerAttrs doesn't match
	// the expected target owner, indicating an unexpected state.
	ErrAlternateOwnerMismatch = errors.New("AlternateOwnerAttrs doesn't match expected target owner")
)

// CreateVMHandleID generates a consistent handle ID for a KubeVirt VM allocation.
// This ensures both CNI plugin and Felix use the same handle format.
//
// The handle ID is constructed with a prefix and suffix, and is length-limited to 128
// characters. If the full ID would exceed this limit, the suffix is hashed and truncated.
//
// Parameters:
//   - networkName: The Calico network name (from annotation "projectcalico.org/network").
//     If empty, defaults to "k8s-pod-network".
//   - namespace: The Kubernetes namespace of the VM.
//   - vmName: The name of the VirtualMachine (VM and VMI share the same name).
//
// Returns:
//   - Handle ID in format: "{networkName}.vmi.{namespace}.{vmName}" (length-limited to 128 chars)
//
// Examples:
//   - CreateVMHandleID("", "default", "vm1") -> "k8s-pod-network.vmi.default.vm1"
//   - CreateVMHandleID("multus-net1", "default", "vm1") -> "multus-net1.vmi.default.vm1"
//   - CreateVMHandleID("net", "ns", "very-long-name...") -> "net.vmi._<hash>" (if exceeds 128 chars)
func CreateVMHandleID(networkName, namespace, vmName string) string {
	if networkName == "" {
		networkName = "k8s-pod-network"
	}

	// Create suffix from namespace and VM name.
	// Use dot separator instead of slash to ensure valid Kubernetes resource name.
	// Kubernetes namespace names follow RFC 1123 DNS label rules which do not allow dots,
	// so the first '.' after 'vmi.' is always the namespace/vmName boundary.
	// We don't need to escape dots in vmName.
	suffix := fmt.Sprintf("%s.%s", namespace, vmName)

	// Build prefix: networkName.vmi.
	prefix := fmt.Sprintf("%s.vmi.", networkName)

	// Use GetLengthLimitedID with max length 128
	// This will keep the suffix unhashed if it fits, otherwise hash and truncate
	return hash.GetLengthLimitedID(prefix, suffix, 128)
}

// EnsureActiveVMOwnerAttrs atomically verifies the target pod is in AlternateOwnerAttrs
// and promotes it to ActiveOwnerAttrs for all IPs allocated to a migrated VMI.
//
// This is called by Felix when KubeVirt live migration completes to transfer
// IP ownership to the target pod. Unlike a strict swap, this function only verifies
// the target pod is registered in AlternateOwnerAttrs - the source pod may have
// already been deleted and its attributes cleared from ActiveOwnerAttrs.
//
// This function is idempotent - it can be safely retried. If an IP already has the target
// as the active owner, it will be skipped (success). This handles partial success scenarios
// where some IPs were swapped successfully before an error occurred.
//
// The function operates on all IPs allocated to the VMI handle, ensuring consistent
// ownership transfer across all IP addresses (IPv4 and IPv6) associated with the VMI.
//
// Parameters:
//   - ctx: Context for the operation
//   - ipamClient: IPAM client interface for performing the operations
//   - networkName: The Calico network name (empty string defaults to "k8s-pod-network")
//   - namespace: The Kubernetes namespace of the VMI
//   - vmiName: The name of the VirtualMachineInstance
//   - targetPodName: The name of the target pod (for verification)
//
// Returns:
//   - nil: Success, target is active owner for all IPs (already was or just swapped)
//   - ErrAlternateOwnerEmpty: AlternateOwnerAttrs is empty and target is not active (target pod deleted)
//   - ErrAlternateOwnerMismatch: AlternateOwnerAttrs contains a different pod than expected
//   - other error: Transient failure (network, CAS conflict, no IPs found, etc.) - caller should retry
//
// After a successful operation, the L3 route resolver will automatically update
// IPIP/VXLAN routes based on the new ActiveOwnerAttrs, directing traffic to the
// target node.
func EnsureActiveVMOwnerAttrs(
	ctx context.Context,
	ipamClient Interface,
	networkName string,
	namespace string,
	vmiName string,
	targetPodName string,
) error {
	// Step 1: Generate handleID using the same logic as CNI plugin
	handleID := CreateVMHandleID(networkName, namespace, vmiName)

	// Step 2: Get all IPs allocated to this handle
	ips, err := ipamClient.IPsByHandle(ctx, handleID)
	if err != nil {
		return fmt.Errorf("failed to get IPs for handle %s: %w", handleID, err)
	}

	if len(ips) == 0 {
		return fmt.Errorf("no IPs found for handle %s", handleID)
	}

	// Step 3: Build expected target owner
	expectedTargetOwner := &AttributeOwner{
		Namespace: namespace,
		Name:      targetPodName,
	}

	var lastErr error
	for _, ip := range ips {
		if err := verifyAndSwapSingleIP(ctx, ipamClient, ip, handleID, expectedTargetOwner); err != nil {
			lastErr = err
			log.WithError(err).WithField("ip", ip).Warning("Failed to swap owner for IP")

			// If this is a non-retryable error, return immediately
			if errors.Is(err, ErrAlternateOwnerEmpty) || errors.Is(err, ErrAlternateOwnerMismatch) {
				return err
			}
			// For transient errors, continue to try other IPs
		}
	}

	// If we had any transient errors, return the last one for retry
	// On retry, already-swapped IPs will be detected as already correct and skipped
	return lastErr
}

const swapRetries = 5

// verifyAndSwapSingleIP reads the current owner attributes, verifies the target is
// in AlternateOwnerAttrs, and atomically promotes it to ActiveOwnerAttrs.
//
// Both active and alternate owners are verified as preconditions to prevent
// resurrecting a deleted owner due to races (e.g., source pod deleted between
// our read and the CAS write). If a precondition fails, the function re-reads
// the current state and retries with updated preconditions.
func verifyAndSwapSingleIP(
	ctx context.Context,
	ipamClient Interface,
	ip cnet.IP,
	handleID string,
	expectedTargetOwner *AttributeOwner,
) error {
	for attempt := 0; attempt < swapRetries; attempt++ {
		allocAttr, err := ipamClient.GetAssignmentAttributes(ctx, ip)
		if err != nil {
			return fmt.Errorf("failed to get assignment attributes for IP %s: %w", ip, err)
		}
		if allocAttr == nil {
			return fmt.Errorf("IP %s is not assigned", ip)
		}

		// Verify handle ID matches
		if allocAttr.HandleID == nil || *allocAttr.HandleID != handleID {
			return fmt.Errorf("IP %s is not assigned to handle %s (current handle: %v)",
				ip, handleID, allocAttr.HandleID)
		}

		// IDEMPOTENCY: If target is already the active owner, nothing to do
		if expectedTargetOwner.Matches(allocAttr.ActiveOwnerAttrs) {
			return nil
		}

		// Check if AlternateOwnerAttrs is empty
		if len(allocAttr.AlternateOwnerAttrs) == 0 {
			return fmt.Errorf("%w for IP %s", ErrAlternateOwnerEmpty, ip)
		}

		// Verify AlternateOwnerAttrs matches expected target owner
		if !expectedTargetOwner.Matches(allocAttr.AlternateOwnerAttrs) {
			return fmt.Errorf("%w: expected %v, got namespace=%s pod=%s for IP %s",
				ErrAlternateOwnerMismatch,
				expectedTargetOwner,
				allocAttr.AlternateOwnerAttrs[AttributeNamespace],
				allocAttr.AlternateOwnerAttrs[AttributePod],
				ip)
		}

		// Build updates and preconditions based on the current state.
		// Both active and alternate are verified to prevent resurrecting a deleted owner.
		updates := &OwnerAttributeUpdates{
			ActiveOwnerAttrs: allocAttr.AlternateOwnerAttrs, // Target becomes active
		}
		preconditions := &OwnerAttributePreconditions{
			ExpectedAlternateOwner: expectedTargetOwner,
		}

		// ActiveOwnerAttrs may be empty if the source pod was already deleted and its
		// attributes were cleared by CNI cleanup before this swap runs.
		if len(allocAttr.ActiveOwnerAttrs) > 0 {
			updates.AlternateOwnerAttrs = allocAttr.ActiveOwnerAttrs // Source becomes alternate
			preconditions.ExpectedActiveOwner = &AttributeOwner{
				Namespace: allocAttr.ActiveOwnerAttrs[AttributeNamespace],
				Name:      allocAttr.ActiveOwnerAttrs[AttributePod],
			}
		} else {
			updates.ClearAlternateOwner = true // No source to swap in, clear alternate
			preconditions.VerifyActiveOwnerEmpty = true
		}

		err = ipamClient.SetOwnerAttributes(ctx, ip, handleID, updates, preconditions)
		if err != nil {
			if _, ok := err.(cerrors.ErrorResourceUpdateConflict); ok {
				log.WithField("ip", ip).Debug("Precondition conflict during swap, retrying")
				continue
			}
			return fmt.Errorf("failed to promote target to active owner for IP %s: %w", ip, err)
		}
		return nil
	}
	return fmt.Errorf("max retries (%d) exceeded for IP %s", swapRetries, ip)
}
