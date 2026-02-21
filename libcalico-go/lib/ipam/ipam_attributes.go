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
	return block.allocationAttributesForIP(addr)
}
