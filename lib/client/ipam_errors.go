// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package client

import (
	"fmt"
	"net"
)

// casError incidates an error performing a compare-and-swap atomic update.
type casError string

func (e casError) Error() string {
	return string(e)
}

// invalidSizeError indicates that the requested IP network size is not valid.
type invalidSizeError string

func (e invalidSizeError) Error() string {
	return string(e)
}

// ipamConfigConflictError indicates an attempt to change IPAM configuration
// that conflicts with existing allocations.
type ipamConfigConflictError string

func (e ipamConfigConflictError) Error() string {
	return string(e)
}

// noSuchBlock error indicates that the requested block does not exist.
type noSuchBlockError struct {
	CIDR net.IPNet
}

func (e noSuchBlockError) Error() string {
	return fmt.Sprintf("No such block: %s", e.CIDR)
}

// noFreeBlocksError indicates an attempt to claim a block
// when there are none available.
type noFreeBlocksError string

func (e noFreeBlocksError) Error() string {
	return string(e)
}

// affinityClaimedError indicates that a given block has already
// been claimed by another host.
type affinityClaimedError struct {
	Block allocationBlock
}

func (e affinityClaimedError) Error() string {
	return fmt.Sprintf("%s already claimed by %s", e.Block.CIDR, e.Block.HostAffinity)
}
