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

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// GetAssignmentAttributes returns the AllocationAttribute for the given IP address,
// which includes the handle ID, ActiveOwnerAttrs, and AlternateOwnerAttrs.
// This provides an atomic snapshot of all allocation attributes for the IP.
// Returns nil if the IP is not assigned.
func (c ipamClient) GetAssignmentAttributes(ctx context.Context, addr cnet.IP) (*model.AllocationAttribute, error) {
	pool, err := c.blockReaderWriter.getPoolForIP(ctx, addr, nil)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		log.Errorf("Error reading pool for %s", addr.String())
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: addr.String(), Err: errors.New("No valid IPPool")}
	}
	blockCIDR := getBlockCIDRForAddress(addr, pool)
	obj, err := c.blockReaderWriter.queryBlock(ctx, blockCIDR, "")
	if err != nil {
		log.Errorf("Error reading block %s: %v", blockCIDR, err)
		return nil, err
	}
	block := allocationBlock{obj.Value.(*model.AllocationBlock)}

	// Get both ActiveOwnerAttrs and AlternateOwnerAttrs
	activeAttrs, err := block.attributesForIP(addr, OwnerAttributeTypeActive)
	if err != nil {
		return nil, err
	}
	alternateAttrs, err := block.attributesForIP(addr, OwnerAttributeTypeAlternate)
	if err != nil {
		return nil, err
	}

	handle, err := block.handleForIP(addr)
	if err != nil {
		return nil, err
	}

	return &model.AllocationAttribute{
		HandleID:            handle,
		ActiveOwnerAttrs:    activeAttrs,
		AlternateOwnerAttrs: alternateAttrs,
	}, nil
}

// GetEmptyAttributeOwner returns an AttributeOwner with empty namespace and name.
// This can be used with MatchAttributeOwner to check if attributes are empty.
func GetEmptyAttributeOwner() *AttributeOwner {
	return &AttributeOwner{
		Namespace: "",
		Name:      "",
	}
}

// MatchAttributeOwner checks if the given attributes match the expected owner.
func MatchAttributeOwner(attrs map[string]string, expectedOwner *AttributeOwner) bool {
	if expectedOwner == nil {
		log.Panic("MatchAttributeOwner called with nil expectedOwner")
	}

	// If expectedOwner is the empty owner, match if attrs is empty
	if expectedOwner.Namespace == "" && expectedOwner.Name == "" {
		return attrs == nil || len(attrs) == 0
	}

	// Otherwise, compare pod and namespace
	if attrs == nil || len(attrs) == 0 {
		return false
	}

	actualPod, podExists := attrs[AttributePod]
	actualNamespace, nsExists := attrs[AttributeNamespace]

	return podExists && nsExists && actualPod == expectedOwner.Name && actualNamespace == expectedOwner.Namespace
}

// SetOwnerAttributes sets ActiveOwnerAttrs and/or AlternateOwnerAttrs for an IP atomically.
func (c ipamClient) SetOwnerAttributes(ctx context.Context, ip cnet.IP, handleID string, updates *OwnerAttributeUpdates, preconditions *OwnerAttributePreconditions) error {
	if updates == nil {
		return fmt.Errorf("updates cannot be nil")
	}

	// Validate that ClearActiveOwner and ActiveOwnerAttrs are not both set
	if updates.ClearActiveOwner && updates.ActiveOwnerAttrs != nil {
		return fmt.Errorf("cannot set both ClearActiveOwner=true and ActiveOwnerAttrs: these are mutually exclusive")
	}

	// Validate that ClearAlternateOwner and AlternateOwnerAttrs are not both set
	if updates.ClearAlternateOwner && updates.AlternateOwnerAttrs != nil {
		return fmt.Errorf("cannot set both ClearAlternateOwner=true and AlternateOwnerAttrs: these are mutually exclusive")
	}

	var attrsActiveOwner, attrsAlternateOwner map[string]string

	// Determine what to set for ActiveOwnerAttrs
	if updates.ClearActiveOwner {
		// Clear flag - use empty map to signal clear
		attrsActiveOwner = map[string]string{}
	} else {
		attrsActiveOwner = updates.ActiveOwnerAttrs
	}

	// Determine what to set for AlternateOwnerAttrs
	if updates.ClearAlternateOwner {
		// Clear flag - use empty map to signal clear
		attrsAlternateOwner = map[string]string{}
	} else {
		attrsAlternateOwner = updates.AlternateOwnerAttrs
	}

	var expectedActiveOwner, expectedAlternateOwner *AttributeOwner

	if preconditions != nil {
		// Validate that ExpectedActiveOwner and VerifyActiveOwnerEmpty are not both set
		if preconditions.ExpectedActiveOwner != nil && preconditions.VerifyActiveOwnerEmpty {
			return fmt.Errorf("cannot set both ExpectedActiveOwner and VerifyActiveOwnerEmpty: these are mutually exclusive")
		}

		// Validate that ExpectedAlternateOwner and VerifyAlternateOwnerEmpty are not both set
		if preconditions.ExpectedAlternateOwner != nil && preconditions.VerifyAlternateOwnerEmpty {
			return fmt.Errorf("cannot set both ExpectedAlternateOwner and VerifyAlternateOwnerEmpty: these are mutually exclusive")
		}

		// If VerifyActiveOwnerEmpty is set, use GetEmptyAttributeOwner() to represent empty verification
		if preconditions.VerifyActiveOwnerEmpty {
			expectedActiveOwner = GetEmptyAttributeOwner()
		} else {
			expectedActiveOwner = preconditions.ExpectedActiveOwner
		}

		// If VerifyAlternateOwnerEmpty is set, use GetEmptyAttributeOwner() to represent empty verification
		if preconditions.VerifyAlternateOwnerEmpty {
			expectedAlternateOwner = GetEmptyAttributeOwner()
		} else {
			expectedAlternateOwner = preconditions.ExpectedAlternateOwner
		}
	}

	logCtx := log.WithFields(log.Fields{
		"ip":                     ip,
		"handleID":               handleID,
		"attrsActiveOwner":       attrsActiveOwner,
		"attrsAlternateOwner":    attrsAlternateOwner,
		"expectedActiveOwner":    expectedActiveOwner,
		"expectedAlternateOwner": expectedAlternateOwner,
	})
	logCtx.Info("Setting owner attributes")

	// Find the pool for this IP.
	pool, err := c.blockReaderWriter.getPoolForIP(ctx, ip, nil)
	if err != nil {
		return err
	}
	if pool == nil {
		return fmt.Errorf("the provided IP address %s is not in a configured pool", ip)
	}

	// Get the block CIDR for this IP.
	blockCIDR := getBlockCIDRForAddress(ip, pool)
	logCtx.Debugf("IP %s is in block '%s'", ip, blockCIDR)

	// Retry loop for CAS operations.
	for i := 0; i < datastoreRetries; i++ {
		// Get the allocation block.
		obj, err := c.blockReaderWriter.queryBlock(ctx, blockCIDR, "")
		if err != nil {
			logCtx.WithError(err).Error("Error getting block")
			return err
		}

		// Set owner attributes in the block.
		block := allocationBlock{obj.Value.(*model.AllocationBlock)}
		err = block.setOwnerAttributes(ip, handleID, attrsActiveOwner, attrsAlternateOwner, expectedActiveOwner, expectedAlternateOwner)
		if err != nil {
			logCtx.WithError(err).Error("Failed to set owner attributes")
			return err
		}

		// Update the block using CAS.
		_, err = c.blockReaderWriter.updateBlock(ctx, obj)
		if err != nil {
			if _, ok := err.(cerrors.ErrorResourceUpdateConflict); ok {
				logCtx.WithError(err).Debug("CAS error setting owner attributes - retry")
				continue
			}
			logCtx.WithError(err).Error("Failed to update block")
			return err
		}

		logCtx.Info("Successfully set owner attributes")
		return nil
	}

	return fmt.Errorf("max retries hit - excessive concurrent IPAM requests")
}
