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
	corev1 "k8s.io/api/core/v1"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// VMAddressPersistence controls whether KubeVirt VirtualMachine workloads
// maintain persistent IP addresses across VM lifecycle events.
type VMAddressPersistence string

const (
	// VMAddressPersistenceEnabled enables IP persistence for KubeVirt VMs.
	VMAddressPersistenceEnabled VMAddressPersistence = "Enabled"
	// VMAddressPersistenceDisabled disables IP persistence for KubeVirt VMs.
	VMAddressPersistenceDisabled VMAddressPersistence = "Disabled"
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

	// The intended use for the IP address.  Used to determine the affinityType of the host.
	IntendedUse v3.IPPoolAllowedUse

	// MaxAllocPerIPVersion specifies the maximum number of IPs per IP version (IPv4/IPv6)
	// that can be allocated for this handle. If 0, no limit is enforced.
	// Used for KubeVirt VMI pods to ensure only one IP allocation per VMI per IP version.
	MaxAllocPerIPVersion int
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

	// MaxAllocPerIPVersion specifies the maximum number of IPs per IP version (IPv4/IPv6)
	// that can be allocated across all blocks for this handle. If 0, no limit is enforced.
	// Used for KubeVirt VMI pods to ensure only one IP allocation per VMI per IP version.
	MaxAllocPerIPVersion int

	// The namespace object for namespaceSelector support.
	Namespace *corev1.Namespace
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

	// KubeVirtVMAddressPersistence controls whether KubeVirt VirtualMachine workloads
	// maintain persistent IP addresses across VM lifecycle events.
	// When set to VMAddressPersistenceEnabled, Calico automatically ensures that KubeVirt VMs retain their
	// IP addresses when their underlying pods are recreated during VM operations such as
	// reboot, live migration, or pod eviction. IP persistency is ensured when the
	// VirtualMachineInstance (VMI) resource is deleted and recreated by the VM controller.
	// When set to VMAddressPersistenceDisabled, VMs receive new IP addresses whenever their pods are recreated,
	// following standard pod IP allocation behavior. Live migration target pods are not allowed
	// when this is set to VMAddressPersistenceDisabled and will result in an error.
	// If nil, defaults to VMAddressPersistenceEnabled (IP persistence enabled if not specified).
	KubeVirtVMAddressPersistence *VMAddressPersistence
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

type AffinityConfig struct {
	AffinityType AffinityType
	Host         string
}

type AffinityType string

const (
	AffinityTypeHost    AffinityType = "host"
	AffinityTypeVirtual AffinityType = "virtual"
)

func (opts *ReleaseOptions) AsNetIP() (*cnet.IP, error) {
	ip := cnet.ParseIP(opts.Address)
	if ip != nil {
		return ip, nil
	}
	return nil, fmt.Errorf("failed to parse IP: %s", opts.Address)
}

// OwnerAttributeType specifies which owner attribute to operate on.
type OwnerAttributeType string

const (
	// OwnerAttributeTypeActive refers to ActiveOwnerAttrs (current/primary owner).
	OwnerAttributeTypeActive OwnerAttributeType = "active"

	// OwnerAttributeTypeAlternate refers to AlternateOwnerAttrs (secondary owner during migration).
	OwnerAttributeTypeAlternate OwnerAttributeType = "alternate"
)

// AttributeOwner represents the owner of an IP allocation attribute.
type AttributeOwner struct {
	// Namespace is the Kubernetes namespace of the pod.
	Namespace string
	// Name is the name of the pod.
	Name string
}

// OwnerAttributeUpdates specifies the attribute values to set for ActiveOwnerAttrs and/or AlternateOwnerAttrs.
// These are the actual values that will be written to the IP allocation.
type OwnerAttributeUpdates struct {
	// ActiveOwnerAttrs specifies attributes to set for ActiveOwnerAttrs.
	// If nil and ClearActiveOwner is false, ActiveOwnerAttrs is not modified.
	// If ClearActiveOwner is true, ActiveOwnerAttrs must be nil (error if both are set).
	ActiveOwnerAttrs map[string]string

	// ClearActiveOwner indicates that ActiveOwnerAttrs should be cleared (set to nil).
	// If true, ActiveOwnerAttrs must be nil. An error is returned if both are set.
	ClearActiveOwner bool

	// AlternateOwnerAttrs specifies attributes to set for AlternateOwnerAttrs.
	// If nil and ClearAlternateOwner is false, AlternateOwnerAttrs is not modified.
	// If ClearAlternateOwner is true, AlternateOwnerAttrs must be nil (error if both are set).
	AlternateOwnerAttrs map[string]string

	// ClearAlternateOwner indicates that AlternateOwnerAttrs should be cleared (set to nil).
	// If true, AlternateOwnerAttrs must be nil. An error is returned if both are set.
	ClearAlternateOwner bool
}

// OwnerAttributePreconditions specifies expected owners for verification before setting attributes.
// These are used to prevent overwriting attributes that belong to a different pod.
type OwnerAttributePreconditions struct {
	// ExpectedActiveOwner verifies current ActiveOwnerAttrs matches the specified owner before setting.
	// If nil, no match on ExpectedActiveOwner is performed.
	// Verification can still occur via VerifyActiveOwnerEmpty if that field is true.
	// An error is returned if both ExpectedActiveOwner and VerifyActiveOwnerEmpty are set.
	ExpectedActiveOwner *AttributeOwner

	// VerifyActiveOwnerEmpty verifies that ActiveOwnerAttrs is empty (nil or empty map) before setting.
	// If true, ActiveOwnerAttrs must be empty for the operation to proceed.
	// An error is returned if both ExpectedActiveOwner and VerifyActiveOwnerEmpty are set.
	VerifyActiveOwnerEmpty bool

	// ExpectedAlternateOwner verifies current AlternateOwnerAttrs matches the specified owner before setting.
	// If nil, no match on ExpectedAlternateOwner is performed.
	// Verification can still occur via VerifyAlternateOwnerEmpty if that field is true.
	// An error is returned if both ExpectedAlternateOwner and VerifyAlternateOwnerEmpty are set.
	ExpectedAlternateOwner *AttributeOwner

	// VerifyAlternateOwnerEmpty verifies that AlternateOwnerAttrs is empty (nil or empty map) before setting.
	// If true, AlternateOwnerAttrs must be empty for the operation to proceed.
	// An error is returned if both ExpectedAlternateOwner and VerifyAlternateOwnerEmpty are set.
	VerifyAlternateOwnerEmpty bool
}

// expectedActiveOwner returns the expected active owner for precondition verification.
// Returns nil if no check is needed. Safe to call on a nil receiver.
func (p *OwnerAttributePreconditions) expectedActiveOwner() *AttributeOwner {
	if p == nil {
		return nil
	}
	if p.VerifyActiveOwnerEmpty {
		return GetEmptyAttributeOwner()
	}
	return p.ExpectedActiveOwner
}

// expectedAlternateOwner returns the expected alternate owner for precondition verification.
// Returns nil if no check is needed. Safe to call on a nil receiver.
func (p *OwnerAttributePreconditions) expectedAlternateOwner() *AttributeOwner {
	if p == nil {
		return nil
	}
	if p.VerifyAlternateOwnerEmpty {
		return GetEmptyAttributeOwner()
	}
	return p.ExpectedAlternateOwner
}
