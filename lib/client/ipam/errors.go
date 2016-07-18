package ipam

import (
	"fmt"
	"net"
)

// AffinityClaimedError indicates that a given block has already
// been claimed by another host.
type AffinityClaimedError struct {
	Block allocationBlock
}

func (e AffinityClaimedError) Error() string {
	return fmt.Sprintf("%s already claimed by %s", e.Block.Cidr, e.Block.HostAffinity)
}

// CASError incidates an error performing a compare-and-swap atomic update.
type CASError string

func (e CASError) Error() string {
	return string(e)
}

// InvalidSizeError indicates that the requested size is not valid.
type InvalidSizeError string

func (e InvalidSizeError) Error() string {
	return string(e)
}

// IPAMConfigConflictError indicates an attempt to change IPAM configuration
// that conflicts with existing allocations.
type IPAMConfigConflictError string

func (e IPAMConfigConflictError) Error() string {
	return string(e)
}

// noSuchBlock error indicates that the requested block does not exist.
type noSuchBlockError struct {
	Cidr net.IPNet
}

func (e noSuchBlockError) Error() string {
	return fmt.Sprintf("No such block: %s", e.Cidr)
}

// noFreeBlocksError indicates an attempt to claim a block
// when there are none available.
type noFreeBlocksError string

func (e noFreeBlocksError) Error() string {
	return string(e)
}
