// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/hash"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Error types for VerifyAndSwapOwnerAttributeForVM
var (
	// ErrAlternateOwnerEmpty is returned when AlternateOwnerAttrs is empty,
	// indicating the target pod was deleted before the promotion could complete.
	ErrAlternateOwnerEmpty = errors.New("AlternateOwnerAttrs is empty")

	// ErrAlternateOwnerMismatch is returned when AlternateOwnerAttrs doesn't match
	// the expected target owner, indicating an unexpected state.
	ErrAlternateOwnerMismatch = errors.New("AlternateOwnerAttrs doesn't match expected target owner")
)

// CreateVMIHandleID generates a consistent handle ID for a KubeVirt VMI allocation.
// This ensures both CNI plugin and Felix use the same handle format.
//
// The handle ID is constructed with a prefix and suffix, and is length-limited to 128
// characters. If the full ID would exceed this limit, the suffix is hashed and truncated.
//
// Parameters:
//   - networkName: The Calico network name (from annotation "projectcalico.org/network").
//     If empty, defaults to "k8s-pod-network".
//   - namespace: The Kubernetes namespace of the VMI.
//   - vmiName: The name of the VirtualMachineInstance.
//
// Returns:
//   - Handle ID in format: "{networkName}.vmi.{namespace}.{vmiName}" (length-limited to 128 chars)
//
// Examples:
//   - CreateVMIHandleID("", "default", "vm1") -> "k8s-pod-network.vmi.default.vm1"
//   - CreateVMIHandleID("multus-net1", "default", "vm1") -> "multus-net1.vmi.default.vm1"
//   - CreateVMIHandleID("net", "ns", "very-long-name...") -> "net.vmi.-<hash>" (if exceeds 128 chars)
func CreateVMIHandleID(networkName, namespace, vmiName string) string {
	if networkName == "" {
		networkName = "k8s-pod-network"
	}

	// Create suffix from namespace and VMI name
	// Use dot separator instead of slash to ensure valid Kubernetes resource name
	suffix := fmt.Sprintf("%s.%s", namespace, vmiName)

	// Build prefix: networkName.vmi.
	prefix := fmt.Sprintf("%s.vmi.", networkName)

	// Use GetLengthLimitedID with max length 128
	// This will keep the suffix unhashed if it fits, otherwise hash and truncate
	return hash.GetLengthLimitedID(prefix, suffix, 128)
}

// VerifyAndSwapOwnerAttributeForVM atomically verifies the target pod is in AlternateOwnerAttrs
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
func VerifyAndSwapOwnerAttributeForVM(
	ctx context.Context,
	ipamClient Interface,
	networkName string,
	namespace string,
	vmiName string,
	targetPodName string,
) error {
	// Step 1: Generate handleID using the same logic as CNI plugin
	handleID := CreateVMIHandleID(networkName, namespace, vmiName)

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
	skippedCount := 0

	for _, ip := range ips {
		// Get current attributes to check if already correct
		allocAttr, err := ipamClient.GetAssignmentAttributes(ctx, ip)
		if err != nil {
			lastErr = fmt.Errorf("failed to get assignment attributes for IP %s: %w", ip, err)
			log.WithError(lastErr).WithField("ip", ip).Warning("Failed to get attributes for IP")
			continue
		}

		if allocAttr == nil {
			lastErr = fmt.Errorf("IP %s is not assigned", ip)
			log.WithError(lastErr).WithField("ip", ip).Warning("IP not assigned")
			continue
		}

		// IDEMPOTENCY CHECK: If target is already the active owner, skip this IP
		if ownerMatches(allocAttr.ActiveOwnerAttrs, expectedTargetOwner) {
			log.WithField("ip", ip).Debug("Target is already active owner, skipping swap")
			skippedCount++
			continue
		}

		// Perform the swap for this IP
		if err := verifyAndSwapSingleIP(ctx, ipamClient, ip, handleID, allocAttr, expectedTargetOwner); err != nil {
			lastErr = err
			log.WithError(err).WithField("ip", ip).Warning("Failed to swap owner for IP")

			// If this is a non-retryable error, return immediately
			if errors.Is(err, ErrAlternateOwnerEmpty) || errors.Is(err, ErrAlternateOwnerMismatch) {
				return err
			}
			// For transient errors, continue to try other IPs
		}
	}

	// If all IPs were already correct, that's success
	if skippedCount == len(ips) {
		log.WithField("count", skippedCount).Info("All IPs already have target as active owner")
		return nil
	}

	// If we had any transient errors, return the last one for retry
	// On retry, already-swapped IPs will be detected as already correct and skipped
	return lastErr
}

// verifyAndSwapSingleIP performs the verify and swap operation for a single IP address.
// It takes the pre-fetched allocAttr to avoid redundant GetAssignmentAttributes calls.
func verifyAndSwapSingleIP(
	ctx context.Context,
	ipamClient Interface,
	ip cnet.IP,
	handleID string,
	allocAttr *model.AllocationAttribute,
	expectedTargetOwner *AttributeOwner,
) error {
	// Verify handle ID matches
	if allocAttr.HandleID == nil || *allocAttr.HandleID != handleID {
		return fmt.Errorf("IP %s is not assigned to handle %s (current handle: %v)",
			ip, handleID, allocAttr.HandleID)
	}

	// Check if AlternateOwnerAttrs is empty
	if len(allocAttr.AlternateOwnerAttrs) == 0 {
		// Target pod was deleted before we could promote it
		return fmt.Errorf("%w for IP %s", ErrAlternateOwnerEmpty, ip)
	}

	// Verify AlternateOwnerAttrs matches expected target owner
	if !ownerMatches(allocAttr.AlternateOwnerAttrs, expectedTargetOwner) {
		// AlternateOwnerAttrs contains a different pod than expected
		return fmt.Errorf("%w: expected %v, got namespace=%s pod=%s for IP %s",
			ErrAlternateOwnerMismatch,
			expectedTargetOwner,
			allocAttr.AlternateOwnerAttrs[AttributeNamespace],
			allocAttr.AlternateOwnerAttrs[AttributePod],
			ip)
	}

	// Promote alternate to active
	// Move alternate (target) to active, move active (source or empty) to alternate
	// The L3 route resolver will use the new ActiveOwnerAttrs to update IPIP/VXLAN routes
	updates := &OwnerAttributeUpdates{
		ActiveOwnerAttrs: allocAttr.AlternateOwnerAttrs, // Target becomes active
	}
	if len(allocAttr.ActiveOwnerAttrs) > 0 {
		updates.AlternateOwnerAttrs = allocAttr.ActiveOwnerAttrs // Source becomes alternate
	} else {
		updates.ClearAlternateOwner = true // No source to swap in, clear alternate
	}

	// Only verify the target is still in alternate position
	// Don't verify ActiveOwnerAttrs - source may have been deleted already
	preconditions := &OwnerAttributePreconditions{
		ExpectedAlternateOwner: expectedTargetOwner, // Verify target is still alternate
	}

	err := ipamClient.SetOwnerAttributes(ctx, ip, handleID, updates, preconditions)
	if err != nil {
		return fmt.Errorf("failed to promote target to active owner for IP %s: %w", ip, err)
	}

	return nil
}

// ownerMatches checks if the attributes map matches the expected AttributeOwner.
// Returns true if:
//   - Both are nil/empty
//   - The namespace and pod name in attrs match the owner
func ownerMatches(attrs map[string]string, owner *AttributeOwner) bool {
	if owner == nil {
		return len(attrs) == 0
	}

	if len(attrs) == 0 {
		return false
	}

	return attrs[AttributeNamespace] == owner.Namespace &&
		attrs[AttributePod] == owner.Name
}
