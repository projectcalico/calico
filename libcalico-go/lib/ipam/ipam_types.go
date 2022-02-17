// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.

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
	"fmt"
	"net"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// AssignIPArgs defines the set of arguments for assigning a specific IP address.
type AssignIPArgs struct {
	// The IP address to assign.
	IP cnet.IP

	// If specified, a handle which can be used to retrieve / release
	// the allocated IP addresses in the future.
	HandleID *string

	// A key/value mapping of metadata to store with the allocations.
	Attrs map[string]string

	// If specified, the hostname of the host on which IP addresses
	// will be allocated.  If not specified, this will default
	// to the value provided by os.Hostname.
	Hostname string

	// If specified, the attributes of reserved IPv4 addresses in the block.
	HostReservedAttr *HostReservedAttr
}

// AutoAssignArgs defines the set of arguments for assigning one or more
// IP addresses.
type AutoAssignArgs struct {
	// The number of IPv4 addresses to automatically assign.
	Num4 int

	// The number of IPv6 addresses to automatically assign.
	Num6 int

	// If specified, a handle which can be used to retrieve / release
	// the allocated IP addresses in the future.
	HandleID *string

	// A key/value mapping of metadata to store with the allocations.
	Attrs map[string]string

	// If specified, the hostname of the host on which IP addresses
	// will be allocated.  If not specified, this will default
	// to the value provided by os.Hostname.
	Hostname string

	// If specified, the previously configured IPv4 pools from which
	// to assign IPv4 addresses.  If not specified, this defaults to all IPv4 pools.
	IPv4Pools []cnet.IPNet

	// If specified, the previously configured IPv6 pools from which
	// to assign IPv6 addresses.  If not specified, this defaults to all IPv6 pools.
	IPv6Pools []cnet.IPNet

	// If non-zero, limit on the number of affine blocks this host is allowed to claim
	// (per IP version).
	MaxBlocksPerHost int

	// If specified, the attributes of reserved IPv4 addresses in the block.
	HostReservedAttrIPv4s *HostReservedAttr

	// If specified, the attributes of reserved IPv6 addresses in the block.
	HostReservedAttrIPv6s *HostReservedAttr

	// The intended use for the IP address.  Used to filter the available IP pools on their AllowedUses field.
	// This field is required.
	IntendedUse v3.IPPoolAllowedUse
}

// IPAMConfig contains global configuration options for Calico IPAM.
// This IPAM configuration is stored in the datastore and configures the behavior
// of Calico IPAM across an entire Calico cluster.
type IPAMConfig struct {
	// When StrictAffinity is true, addresses from a given block can only be
	// assigned by hosts with the blocks affinity.  If false, then AutoAllocateBlocks
	// must be true.  The default value is false.
	StrictAffinity bool

	// When AutoAllocateBlocks is true, Calico will automatically
	// allocate blocks of IP address to hosts as needed to assign addresses.
	// If false, then StrictAffinity must be true.  The default value is true.
	AutoAllocateBlocks bool

	// If non-zero, MaxBlocksPerHost specifies the max number of blocks that may
	// be affine to a node.
	MaxBlocksPerHost int
}

// GetUtilizationArgs defines the set of arguments for requesting IP utilization.
type GetUtilizationArgs struct {
	// If specified, the pools whose utilization should be reported.  Each string here
	// can be a pool name or CIDR.  If not specified, this defaults to all pools.
	Pools []string
}

// BlockUtilization reports IP utilization for a single allocation block.
type BlockUtilization struct {
	// This block's CIDR.
	CIDR net.IPNet

	// Number of possible IPs in this block.
	Capacity int

	// Number of available IPs in this block.
	Available int
}

// PoolUtilization reports IP utilization for a single IP pool.
type PoolUtilization struct {
	// This pool's name.
	Name string

	// This pool's CIDR.
	CIDR net.IPNet

	// Utilization for each of this pool's blocks.
	Blocks []BlockUtilization
}

type HostReservedAttr struct {
	// Number of addresses reserved from start of the block.
	StartOfBlock int

	// Number of addresses reserved from end of the block.
	EndOfBlock int

	// Handle for reserved addresses.
	Handle string

	// A description about the reserves.
	Note string
}

// BlockArgs defines the set of arguments for allocating one block.
type BlockArgs struct {
	// If specified, the hostname of the host on which blocks
	// will be allocated.  If not specified, this will default
	// to the value provided by os.Hostname.
	Hostname string

	// If specified, the previously configured IPv4 pools from which
	// to assign IPv4 addresses.  If not specified, this defaults to all IPv4 pools.
	IPv4Pools []cnet.IPNet

	// If specified, the previously configured IPv6 pools from which
	// to assign IPv6 addresses.  If not specified, this defaults to all IPv6 pools.
	IPv6Pools []cnet.IPNet

	// If specified, the attributes of reserved IPv4 addresses in this block.
	HostReservedAttrIPv4s *HostReservedAttr

	// If specified, the attributes of reserved IPv6 addresses in this block.
	HostReservedAttrIPv6s *HostReservedAttr
}

type ReleaseOptions struct {
	// Address to release.
	Address string

	// If provided, handle and sequence number will be used to
	// check for race conditions with other users of the IPAM API. It is
	// highly recommended that both values be set on release requests.
	Handle         string
	SequenceNumber *uint64
}

func (opts *ReleaseOptions) AsNetIP() (*cnet.IP, error) {
	ip := cnet.ParseIP(opts.Address)
	if ip != nil {
		return ip, nil
	}
	return nil, fmt.Errorf("failed to parse IP: %s", opts.Address)
}
