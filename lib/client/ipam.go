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
	"errors"
	"fmt"
	"os"

	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/backend"
	"github.com/tigera/libcalico-go/lib/common"
)

const (
	// Number of retries when we have an error writing data
	// to etcd.
	ipamEtcdRetries   = 100
	ipamKeyErrRetries = 3
)

// IPAMInterface has methods to perform IP address management.
type IPAMInterface interface {
	// AssignIP assigns the provided IP address to the provided host.  The IP address
	// must fall within a configured pool.  AssignIP will claim block affinity as needed
	// in order to satisfy the assignment.  An error will be returned if the IP address
	// is already assigned, or if StrictAffinity is enabled and the address is within
	// a block that does not have affinity for the given host.
	AssignIP(args AssignIPArgs) error

	// AutoAssign automatically assigns one or more IP addresses as specified by the
	// provided AutoAssignArgs.  AutoAssign returns the list of the assigned IPv4 addresses,
	// and the list of the assigned IPv6 addresses.
	AutoAssign(args AutoAssignArgs) ([]common.IP, []common.IP, error)

	// ReleaseIPs releases any of the given IP addresses that are currently assigned,
	// so that they are available to be used in another assignment.
	ReleaseIPs(ips []common.IP) ([]common.IP, error)

	// GetAssignmentAttributes returns the attributes stored with the given IP address
	// upon assignment.
	GetAssignmentAttributes(addr common.IP) (map[string]string, error)

	// IpsByHandle returns a list of all IP addresses that have been
	// assigned using the provided handle.
	IPsByHandle(handleID string) ([]common.IP, error)

	// ReleaseByHandle releases all IP addresses that have been assigned
	// using the provided handle.  Returns an error if no addresses
	// are assigned with the given handle.
	ReleaseByHandle(handleID string) error

	// ClaimAffinity claims affinity to the given host for all blocks
	// within the given CIDR.  The given CIDR must fall within a configured
	// pool.
	ClaimAffinity(cidr common.IPNet, host *string) ([]common.IPNet, []common.IPNet, error)

	// ReleaseAffinity releases affinity for all blocks within the given CIDR
	// on the given host.  If host is not specified, then the value returned by os.Hostname
	// will be used.
	ReleaseAffinity(cidr common.IPNet, host *string) error

	// ReleaseHostAffinities releases affinity for all blocks that are affine
	// to the given host.  If host is not specified, the value returned by os.Hostname
	// will be used.
	ReleaseHostAffinities(host *string) error

	// ReleasePoolAffinities releases affinity for all blocks within
	// the specified pool across all hosts.
	ReleasePoolAffinities(pool common.IPNet) error

	// GetIPAMConfig returns the global IPAM configuration.  If no IPAM configuration
	// has been set, returns a default configuration with StrictAffinity disabled
	// and AutoAllocateBlocks enabled.
	GetIPAMConfig() (*IPAMConfig, error)

	// SetIPAMConfig sets global IPAM configuration.  This can only
	// be done when there are no allocated blocks and IP addresses.
	SetIPAMConfig(cfg IPAMConfig) error

	// RemoveIPAMHost releases affinity for all blocks on the given host,
	// and removes all host-specific IPAM data from the datastore.
	// RemoveIPAMHost does not release any IP addresses claimed on the given host.
	RemoveIPAMHost(host *string) error
}

// newIPAM returns a new ipamClient, which implements the IPAMInterface
func newIPAM(c *Client) *ipams {
	return &ipams{c, blockReaderWriter{c}}
}

// ipamClient implements the IPAMInterface
type ipams struct {
	client            *Client
	blockReaderWriter blockReaderWriter
}

// AutoAssign automatically assigns one or more IP addresses as specified by the
// provided AutoAssignArgs.  AutoAssign returns the list of the assigned IPv4 addresses,
// and the list of the assigned IPv6 addresses.
func (c ipams) AutoAssign(args AutoAssignArgs) ([]common.IP, []common.IP, error) {
	// Determine the hostname to use - prefer the provided hostname if
	// non-nil, otherwise use the hostname reported by os.
	hostname := decideHostname(args.Hostname)
	glog.V(2).Infof("Auto-assign %d ipv4, %d ipv6 addrs for host '%s'", args.Num4, args.Num6, hostname)

	var v4list, v6list []common.IP
	var err error

	if args.Num4 != 0 {
		// Assign IPv4 addresses.
		glog.V(4).Infof("Assigning IPv4 addresses")
		v4list, err = c.autoAssign(args.Num4, args.HandleID, args.Attrs, args.IPv4Pool, ipv4, hostname)
		if err != nil {
			glog.Errorf("Error assigning IPV4 addresses: %s", err)
			return nil, nil, err
		}
	}

	if args.Num6 != 0 {
		// If no err assigning V4, try to assign any V6.
		glog.V(4).Infof("Assigning IPv6 addresses")
		v6list, err = c.autoAssign(args.Num6, args.HandleID, args.Attrs, args.IPv6Pool, ipv6, hostname)
		if err != nil {
			glog.Errorf("Error assigning IPV6 addresses: %s", err)
			return nil, nil, err
		}
	}

	return v4list, v6list, nil
}

func (c ipams) autoAssign(num int, handleID *string, attrs map[string]string, pool *common.IPNet, version ipVersion, host string) ([]common.IP, error) {

	// Start by trying to assign from one of the host-affine blocks.  We
	// always do strict checking at this stage, so it doesn't matter whether
	// globally we have strict_affinity or not.
	glog.V(4).Infof("Looking for addresses in current affine blocks for host '%s'", host)
	affBlocks, err := c.blockReaderWriter.getAffineBlocks(host, version, pool)
	if err != nil {
		return nil, err
	}
	glog.V(4).Infof("Found %d affine IPv%d blocks for host '%s': %v", len(affBlocks), version.Number, host, affBlocks)
	ips := []common.IP{}
	for len(ips) < num {
		if len(affBlocks) == 0 {
			glog.V(2).Infof("Ran out of existing affine blocks for host '%s'", host)
			break
		}
		cidr := affBlocks[0]
		affBlocks = affBlocks[1:]
		ips, _ = c.assignFromExistingBlock(cidr, num, handleID, attrs, host, nil)
		glog.V(3).Infof("Block '%s' provided addresses: %v", cidr.String(), ips)
	}

	// If there are still addresses to allocate, then we've run out of
	// blocks with affinity.  Before we can assign new blocks or assign in
	// non-affine blocks, we need to check that our IPAM configuration
	// allows that.
	config, err := c.GetIPAMConfig()
	if err != nil {
		return nil, err
	}
	glog.V(3).Infof("Allocate new blocks? Config: %+v", config)
	if config.AutoAllocateBlocks == true {
		rem := num - len(ips)
		retries := ipamEtcdRetries
		for rem > 0 && retries > 0 {
			// Claim a new block.
			glog.V(2).Infof("Need to allocate %d more addresses - allocate another block", rem)
			retries = retries - 1
			b, err := c.blockReaderWriter.claimNewAffineBlock(host, version, pool, *config)
			if err != nil {
				// Error claiming new block.
				glog.Errorf("Error claiming new block: %s", err)
				return nil, err
			} else {
				// Claim successful.  Assign addresses from the new block.
				glog.V(2).Infof("Claimed new block %s - assigning %d addresses", b.String(), rem)
				newIPs, err := c.assignFromExistingBlock(*b, rem, handleID, attrs, host, &config.StrictAffinity)
				if err != nil {
					glog.Warningf("Failed to assign IPs:", err)
					break
				}
				glog.V(3).Infof("Assigned IPs from new block: %s", newIPs)
				ips = append(ips, newIPs...)
				rem = num - len(ips)
			}
		}

		if retries == 0 {
			return nil, errors.New("Max retries hit")
		}
	}

	// If there are still addresses to allocate, we've now tried all blocks
	// with some affinity to us, and tried (and failed) to allocate new
	// ones.  If we do not require strict host affinity, our last option is
	// a random hunt through any blocks we haven't yet tried.
	//
	// Note that this processing simply takes all of the IP pools and breaks
	// them up into block-sized CIDRs, then shuffles and searches through each
	// CIDR.  This algorithm does not work if we disallow auto-allocation of
	// blocks because the allocated blocks may be sparsely populated in the
	// pools resulting in a very slow search for free addresses.
	//
	// If we need to support non-strict affinity and no auto-allocation of
	// blocks, then we should query the actual allocation blocks and assign
	// from those.
	rem := num - len(ips)
	if config.StrictAffinity != true && rem != 0 {
		glog.V(1).Infof("Attempting to assign %d more addresses from non-affine blocks", rem)
		// TODO: this
	}

	glog.V(2).Infof("Auto-assigned %d out of %d IPv%ds: %v", len(ips), num, version.Number, ips)
	return ips, nil
}

// AssignIP assigns the provided IP address to the provided host.  The IP address
// must fall within a configured pool.  AssignIP will claim block affinity as needed
// in order to satisfy the assignment.  An error will be returned if the IP address
// is already assigned, or if StrictAffinity is enabled and the address is within
// a block that does not have affinity for the given host.
func (c ipams) AssignIP(args AssignIPArgs) error {
	hostname := decideHostname(args.Hostname)
	glog.V(2).Infof("Assigning IP %s to host: %s", args.IP, hostname)

	if !c.blockReaderWriter.withinConfiguredPools(args.IP) {
		return errors.New("The provided IP address is not in a configured pool\n")
	}

	blockCIDR := getBlockCIDRForAddress(args.IP)
	glog.V(3).Infof("IP %s is in block '%s'", args.IP.String(), blockCIDR.String())
	for i := 0; i < ipamEtcdRetries; i++ {
		obj, err := c.client.backend.Get(backend.BlockKey{blockCIDR})
		if err != nil {
			if _, ok := err.(common.ErrorResourceDoesNotExist); ok {
				// Block doesn't exist, we need to create it.  First,
				// validate the given IP address is within a configured pool.
				if !c.blockReaderWriter.withinConfiguredPools(args.IP) {
					estr := fmt.Sprintf("The given IP address (%s) is not in any configured pools", args.IP.String())
					glog.Errorf(estr)
					return errors.New(estr)
				}
				glog.V(3).Infof("Block for IP %s does not yet exist, creating", args.IP)
				cfg := IPAMConfig{StrictAffinity: false, AutoAllocateBlocks: true}
				err := c.blockReaderWriter.claimBlockAffinity(blockCIDR, hostname, cfg)
				if err != nil {
					if _, ok := err.(*affinityClaimedError); ok {
						glog.Warningf("Someone else claimed block %s before us", blockCIDR.String())
						continue
					} else {
						return err
					}
				}
				glog.V(2).Infof("Claimed new block: %s", blockCIDR)
				continue
			} else {
				// Unexpected error
				return err
			}
		}
		block := allocationBlock{obj.Object.(backend.AllocationBlock)}
		err = block.assign(args.IP, args.HandleID, args.Attrs, hostname)
		if err != nil {
			glog.Errorf("Failed to assign address %s: %s", args.IP, err)
			return err
		}

		// Increment handle.
		if args.HandleID != nil {
			c.incrementHandle(*args.HandleID, blockCIDR, 1)
		}

		// Update the block using the original DatastoreObject
		// to do a CAS.
		obj.Object = block.AllocationBlock
		_, err = c.client.backend.Update(obj)
		if err != nil {
			glog.Warningf("Update failed on block %s", block.CIDR.String())
			if args.HandleID != nil {
				c.decrementHandle(*args.HandleID, blockCIDR, 1)
			}
			return err
		}
		return nil
	}
	return errors.New("Max retries hit")
}

// ReleaseIPs releases any of the given IP addresses that are currently assigned,
// so that they are available to be used in another assignment.
func (c ipams) ReleaseIPs(ips []common.IP) ([]common.IP, error) {
	glog.V(2).Infof("Releasing IP addresses: %v", ips)
	unallocated := []common.IP{}
	for _, ip := range ips {
		blockCIDR := getBlockCIDRForAddress(ip)
		// TODO: Group IP addresses per-block to minimize writes to etcd.
		unalloc, err := c.releaseIPsFromBlock([]common.IP{ip}, blockCIDR)
		if err != nil {
			glog.Errorf("Error releasing IPs: %s", err)
			return nil, err
		}
		unallocated = append(unallocated, unalloc...)
	}
	return unallocated, nil
}

func (c ipams) releaseIPsFromBlock(ips []common.IP, blockCIDR common.IPNet) ([]common.IP, error) {
	for i := 0; i < ipamEtcdRetries; i++ {
		obj, err := c.client.backend.Get(backend.BlockKey{CIDR: blockCIDR})
		if err != nil {
			if _, ok := err.(common.ErrorResourceDoesNotExist); ok {
				// The block does not exist - all addresses must be unassigned.
				return ips, nil
			} else {
				// Unexpected error reading block.
				return nil, err
			}
		}

		// Block exists - get the allocationBlock from the DatastoreObject.
		b := allocationBlock{obj.Object.(backend.AllocationBlock)}

		// Release the IPs.
		unallocated, handles, err2 := b.release(ips)
		if err2 != nil {
			return nil, err2
		}
		if len(ips) == len(unallocated) {
			// All the given IP addresses are already unallocated.
			// Just return.
			return unallocated, nil
		}

		// If the block is empty and has no affinity, we can delete it.
		// Otherwise, update the block using CAS.
		var updateErr error
		if b.empty() && b.HostAffinity == nil {
			glog.V(3).Infof("Deleting non-affine block '%s'", b.CIDR.String())
			updateErr = c.client.backend.Delete(&backend.DatastoreObject{
				Key: backend.BlockKey{CIDR: blockCIDR},
			})
		} else {
			glog.V(3).Infof("Updating assignments in block '%s'", b.CIDR.String())
			obj.Object = b.AllocationBlock
			_, updateErr = c.client.backend.Update(obj)
		}

		if updateErr != nil {
			if _, ok := updateErr.(common.ErrorResourceUpdateConflict); ok {
				// Comparison error - retry.
				glog.Warningf("Failed to update block '%s' - retry #%d", b.CIDR.String(), i)
				continue
			} else {
				// Something else - return the error.
				glog.Errorf("Error updating block '%s': %s", b.CIDR.String(), updateErr)
				return nil, updateErr
			}
		}

		// Success - decrement handles.
		glog.V(3).Infof("Decrementing handles: %v", handles)
		for handleID, amount := range handles {
			c.decrementHandle(handleID, blockCIDR, amount)
		}
		return unallocated, nil
	}
	return nil, errors.New("Max retries hit")
}

func (c ipams) assignFromExistingBlock(
	blockCIDR common.IPNet, num int, handleID *string, attrs map[string]string, host string, affCheck *bool) ([]common.IP, error) {
	// Limit number of retries.
	var ips []common.IP
	for i := 0; i < ipamEtcdRetries; i++ {
		glog.V(4).Infof("Auto-assign from %s - retry %d", blockCIDR.String(), i)
		obj, err := c.client.backend.Get(backend.BlockKey{blockCIDR})
		if err != nil {
			glog.Errorf("Error getting block: %s", err)
			return nil, err
		}

		// Pull out the block.
		b := allocationBlock{obj.Object.(backend.AllocationBlock)}

		glog.V(4).Infof("Got block: %v", b)
		ips, err = b.autoAssign(num, handleID, host, attrs, true)
		if err != nil {
			glog.Errorf("Error in auto assign: %s", err)
			return nil, err
		}
		if len(ips) == 0 {
			glog.V(2).Infof("Block %s is full", blockCIDR)
			return []common.IP{}, nil
		}

		// Increment handle count.
		if handleID != nil {
			c.incrementHandle(*handleID, blockCIDR, num)
		}

		// Update the block using CAS by passing back the original
		// DatastoreObject.
		obj.Object = b.AllocationBlock
		_, err = c.client.backend.Update(obj)
		if err != nil {
			glog.V(2).Infof("Failed to update block '%s' - try again", b.CIDR.String())
			if handleID != nil {
				c.decrementHandle(*handleID, blockCIDR, num)
			}
			continue
		}
		break
	}
	return ips, nil
}

// ClaimAffinity makes a best effort to claim affinity to the given host for all blocks
// within the given CIDR.  The given CIDR must fall within a configured
// pool.  Returns a list of blocks that were claimed, as well as a
// list of blocks that were claimed by another host.
func (c ipams) ClaimAffinity(cidr common.IPNet, host *string) ([]common.IPNet, []common.IPNet, error) {
	// Validate that the given CIDR is at least as big as a block.
	if !largerThanBlock(cidr) {
		estr := fmt.Sprintf("The requested CIDR (%s) is smaller than the minimum.", cidr.String())
		return nil, nil, invalidSizeError(estr)
	}

	// Determine the hostname to use.
	hostname := decideHostname(host)
	failed := []common.IPNet{}
	claimed := []common.IPNet{}

	// Verify the requested CIDR falls within a configured pool.
	if !c.blockReaderWriter.withinConfiguredPools(common.IP{cidr.IP}) {
		estr := fmt.Sprintf("The requested CIDR (%s) is not within any configured pools.", cidr.String())
		return nil, nil, errors.New(estr)
	}

	// Get IPAM config.
	cfg, err := c.GetIPAMConfig()
	if err != nil {
		glog.Errorf("Failed to get IPAM Config: %s", err)
		return nil, nil, err
	}

	// Claim all blocks within the given cidr.
	for _, blockCIDR := range blocks(cidr) {
		err := c.blockReaderWriter.claimBlockAffinity(blockCIDR, hostname, *cfg)
		if err != nil {
			if _, ok := err.(affinityClaimedError); ok {
				// Claimed by someone else - add to failed list.
				failed = append(failed, blockCIDR)
			} else {
				glog.Errorf("Failed to claim block: %s", err)
				return claimed, failed, err
			}
		} else {
			claimed = append(claimed, blockCIDR)
		}
	}
	return claimed, failed, nil

}

// ReleaseAffinity releases affinity for all blocks within the given CIDR
// on the given host.  If a block does not have affinity for the given host,
// its affinity will not be released and no error will be returned.
// If host is not specified, then the value returned by os.Hostname
// will be used.
func (c ipams) ReleaseAffinity(cidr common.IPNet, host *string) error {
	// Validate that the given CIDR is at least as big as a block.
	if !largerThanBlock(cidr) {
		estr := fmt.Sprintf("The requested CIDR (%s) is smaller than the minimum.", cidr.String())
		return invalidSizeError(estr)
	}

	// Determine the hostname to use.
	hostname := decideHostname(host)

	// Release all blocks within the given cidr.
	for _, blockCIDR := range blocks(cidr) {
		err := c.blockReaderWriter.releaseBlockAffinity(hostname, blockCIDR)
		if err != nil {
			if _, ok := err.(affinityClaimedError); ok {
				// Not claimed by this host - ignore.
			} else if _, ok := err.(common.ErrorResourceDoesNotExist); ok {
				// Block does not exist - ignore.
			} else {
				glog.Errorf("Error releasing affinity for '%s': %s", blockCIDR, err)
				return err
			}
		}
	}
	return nil
}

// ReleaseHostAffinities releases affinity for all blocks that are affine
// to the given host.  If host is not specified, the value returned by os.Hostname
// will be used.
func (c ipams) ReleaseHostAffinities(host *string) error {
	hostname := decideHostname(host)

	versions := []ipVersion{ipv4, ipv6}
	for _, version := range versions {
		blockCIDRs, err := c.blockReaderWriter.getAffineBlocks(hostname, version, nil)
		if err != nil {
			return err
		}

		for _, blockCIDR := range blockCIDRs {
			err := c.ReleaseAffinity(blockCIDR, &hostname)
			if err != nil {
				if _, ok := err.(affinityClaimedError); ok {
					// Claimed by a different host.
				} else {
					return err
				}
			}
		}
	}
	return nil
}

// ReleasePoolAffinities releases affinity for all blocks within
// the specified pool across all hosts.
func (c ipams) ReleasePoolAffinities(pool common.IPNet) error {
	glog.V(2).Infof("Releasing block affinities within pool '%s'", pool.String())
	for i := 0; i < ipamKeyErrRetries; i++ {
		retry := false
		pairs, err := c.hostBlockPairs(pool)
		if err != nil {
			return err
		}

		if len(pairs) == 0 {
			glog.V(4).Infof("No blocks have affinity")
			return nil
		}

		for blockString, host := range pairs {
			_, blockCIDR, _ := common.ParseCIDR(blockString)
			err = c.blockReaderWriter.releaseBlockAffinity(host, *blockCIDR)
			if err != nil {
				if _, ok := err.(affinityClaimedError); ok {
					retry = true
				} else if _, ok := err.(common.ErrorResourceDoesNotExist); ok {
					glog.V(4).Infof("No such block '%s'", blockCIDR.String())
					continue
				} else {
					glog.Errorf("Error releasing affinity for '%s': %s", blockCIDR.String(), err)
					return err
				}
			}

		}

		if !retry {
			return nil
		}
	}
	return errors.New("Max retries hit")
}

// RemoveIPAMHost releases affinity for all blocks on the given host,
// and removes all host-specific IPAM data from the datastore.
// RemoveIPAMHost does not release any IP addresses claimed on the given host.
func (c ipams) RemoveIPAMHost(host *string) error {
	// Determine the hostname to use.
	hostname := decideHostname(host)

	// Release host affinities.
	c.ReleaseHostAffinities(&hostname)

	// Remove the host ipam tree.
	// TODO: Support this in the backend.
	// key := fmt.Sprintf(ipamHostPath, hostname)
	// opts := client.DeleteOptions{Recursive: true}
	// _, err := c.blockReaderWriter.etcd.Delete(context.Background(), key, &opts)
	// if err != nil {
	// 	if eerr, ok := err.(client.Error); ok && eerr.Code == client.ErrorCodeNodeExist {
	// 		// Already deleted.  Carry on.

	// 	} else {
	// 		return err
	// 	}
	// }
	return nil
}

func (c ipams) hostBlockPairs(pool common.IPNet) (map[string]string, error) {
	pairs := map[string]string{}

	// Get all blocks and their affinities.
	objs, err := c.client.backend.List(backend.BlockAffinityListOptions{})
	if err != nil {
		glog.Errorf("Error querying block affinities: %s", err)
		return nil, err
	}

	// Iterate through each block affinity and build up a mapping
	// of blockCidr -> host.
	glog.V(4).Infof("Getting block -> host mappings")
	for _, o := range objs {
		k := o.Key.(backend.BlockAffinityKey)
		pairs[k.CIDR.String()] = k.Host
		glog.V(4).Infof("Block %s -> %s", k.CIDR.String(), k.Host)
	}

	return pairs, nil
}

// IpsByHandle returns a list of all IP addresses that have been
// assigned using the provided handle.
func (c ipams) IPsByHandle(handleID string) ([]common.IP, error) {
	obj, err := c.client.backend.Get(backend.IPAMHandleKey{HandleID: handleID})
	if err != nil {
		return nil, err
	}
	handle := allocationHandle{obj.Object.(backend.IPAMHandle)}

	assignments := []common.IP{}
	for k, _ := range handle.Block {
		_, blockCIDR, _ := common.ParseCIDR(k)
		obj, err := c.client.backend.Get(backend.BlockKey{*blockCIDR})
		if err != nil {
			glog.Warningf("Couldn't read block %s referenced by handle %s", blockCIDR, handleID)
			continue
		}

		// Pull out the allocationBlock and get all the assignments
		// from it.
		b := allocationBlock{obj.Object.(backend.AllocationBlock)}
		assignments = append(assignments, b.ipsByHandle(handleID)...)
	}
	return assignments, nil
}

// ReleaseByHandle releases all IP addresses that have been assigned
// using the provided handle.
func (c ipams) ReleaseByHandle(handleID string) error {
	glog.V(2).Infof("Releasing all IPs with handle '%s'", handleID)
	obj, err := c.client.backend.Get(backend.IPAMHandleKey{HandleID: handleID})
	if err != nil {
		return err
	}
	handle := allocationHandle{obj.Object.(backend.IPAMHandle)}

	for blockStr, _ := range handle.Block {
		_, blockCIDR, _ := common.ParseCIDR(blockStr)
		err = c.releaseByHandle(handleID, *blockCIDR)
	}
	return nil
}

func (c ipams) releaseByHandle(handleID string, blockCIDR common.IPNet) error {
	for i := 0; i < ipamEtcdRetries; i++ {
		obj, err := c.client.backend.Get(backend.BlockKey{CIDR: blockCIDR})
		if err != nil {
			if _, ok := err.(common.ErrorResourceDoesNotExist); ok {
				// Block doesn't exist, so all addresses are already
				// unallocated.  This can happen when a handle is
				// overestimating the number of assigned addresses.
				return nil
			} else {
				return err
			}
		}
		block := allocationBlock{obj.Object.(backend.AllocationBlock)}
		num := block.releaseByHandle(handleID)
		if num == 0 {
			// Block has no addresses with this handle, so
			// all addresses are already unallocated.
			return nil
		}

		if block.empty() && block.HostAffinity == nil {
			err = c.client.backend.Delete(&backend.DatastoreObject{
				Key: backend.BlockKey{blockCIDR},
			})
			if err != nil {
				if _, ok := err.(common.ErrorResourceDoesNotExist); ok {
					// Already deleted - carry on.
				} else {
					glog.Errorf("Error deleting block: %s", err)
				}
			}
		} else {
			// Compare and swap the AllocationBlock using the original
			// DatastoreObject read from before.
			obj.Object = block.AllocationBlock
			_, err = c.client.backend.Update(obj)
			if err != nil {
				if _, ok := err.(common.ErrorResourceUpdateConflict); ok {
					// Comparison failed - retry.
					glog.Warningf("CAS error for block, retry #%d: %s", i, err)
					continue
				} else {
					// Something else - return the error.
					glog.Errorf("Error updating block '%s': %s", block.CIDR.String(), err)
					return err
				}
			}
		}

		c.decrementHandle(handleID, blockCIDR, num)
		return nil
	}
	return errors.New("Hit max retries")
}

func (c ipams) incrementHandle(handleID string, blockCIDR common.IPNet, num int) error {
	var obj *backend.DatastoreObject
	var err error
	for i := 0; i < ipamEtcdRetries; i++ {
		obj, err = c.client.backend.Get(backend.IPAMHandleKey{HandleID: handleID})
		if err != nil {
			if _, ok := err.(common.ErrorResourceDoesNotExist); ok {
				// Handle doesn't exist - create it.
				glog.V(2).Infof("Creating new handle:", handleID)
				bh := backend.IPAMHandle{
					HandleID: handleID,
					Block:    map[string]int{},
				}
				obj = &backend.DatastoreObject{
					Key:    backend.IPAMHandleKey{HandleID: handleID},
					Object: bh,
				}
			} else {
				// Unexpected error reading handle.
				return err
			}
		}

		// Get the handle from the DatastoreObject.
		handle := allocationHandle{obj.Object.(backend.IPAMHandle)}

		// Increment the handle for this block.
		handle.incrementBlock(blockCIDR, num)

		// Compare and swap the handle using the DatastoreObject from above.
		obj.Object = handle.IPAMHandle
		_, err = c.client.backend.Apply(obj)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.New("Max retries hit")

}

func (c ipams) decrementHandle(handleID string, blockCIDR common.IPNet, num int) error {
	for i := 0; i < ipamEtcdRetries; i++ {
		obj, err := c.client.backend.Get(backend.IPAMHandleKey{HandleID: handleID})
		if err != nil {
			glog.Fatalf("Can't decrement block because it doesn't exist")
		}
		handle := allocationHandle{obj.Object.(backend.IPAMHandle)}

		_, err = handle.decrementBlock(blockCIDR, num)
		if err != nil {
			glog.Fatalf("Can't decrement block - too few allocated")
		}

		// Update / Delete as appropriate.
		if handle.empty() {
			glog.V(3).Infof("Deleting handle: %s", handleID)
			err = c.client.backend.Delete(&backend.DatastoreObject{
				Key: backend.IPAMHandleKey{HandleID: handleID},
			})
		} else {
			glog.V(3).Infof("Updating handle: %s", handleID)
			obj.Object = handle.IPAMHandle
			_, err = c.client.backend.Update(obj)
		}

		// Check error.
		if err != nil {
			continue
		}
		glog.V(2).Infof("Decremented handle '%s' by %d", handleID, num)
		return nil
	}
	return errors.New("Max retries hit")
}

// GetAssignmentAttributes returns the attributes stored with the given IP address
// upon assignment.
func (c ipams) GetAssignmentAttributes(addr common.IP) (map[string]string, error) {
	blockCIDR := getBlockCIDRForAddress(addr)
	obj, err := c.client.backend.Get(backend.BlockKey{blockCIDR})
	if err != nil {
		glog.Errorf("Error reading block %s: %s", blockCIDR, err)
		return nil, errors.New(fmt.Sprintf("%s is not assigned", addr))
	}
	block := allocationBlock{obj.Object.(backend.AllocationBlock)}
	return block.attributesForIP(addr)
}

// GetIPAMConfig returns the global IPAM configuration.  If no IPAM configuration
// has been set, returns a default configuration with StrictAffinity disabled
// and AutoAllocateBlocks enabled.
func (c ipams) GetIPAMConfig() (*IPAMConfig, error) {
	obj, err := c.client.backend.Get(backend.IPAMConfigKey{})
	if err != nil {
		if _, ok := err.(common.ErrorResourceDoesNotExist); ok {
			// IPAMConfig has not been explicitly set.  Return
			// a default IPAM configuration.
			return &IPAMConfig{AutoAllocateBlocks: true, StrictAffinity: false}, nil
		}
		glog.Errorf("Error getting IPAMConfig: %s", err)
		return nil, err
	}
	return c.convertBackendToIPAMConfig(obj.Object.(backend.IPAMConfig)), nil
}

// SetIPAMConfig sets global IPAM configuration.  This can only
// be done when there are no allocated blocks and IP addresses.
func (c ipams) SetIPAMConfig(cfg IPAMConfig) error {
	current, err := c.GetIPAMConfig()
	if err != nil {
		return err
	}

	if *current == cfg {
		return nil
	}

	if !cfg.StrictAffinity && !cfg.AutoAllocateBlocks {
		return errors.New("Cannot disable 'StrictAffinity' and 'AutoAllocateBlocks' at the same time")
	}

	allObjs, err := c.client.backend.List(backend.BlockListOptions{})
	if len(allObjs) != 0 {
		return errors.New("Cannot change IPAM config while allocations exist")
	}

	// Write to datastore.
	obj := backend.DatastoreObject{
		Key:    backend.IPAMConfigKey{},
		Object: c.convertIPAMConfigToBackend(cfg),
	}
	_, err = c.client.backend.Apply(&obj)
	if err != nil {
		glog.Errorf("Error applying IPAMConfig: %s", err)
		return err
	}
	return nil
}

func (c ipams) convertIPAMConfigToBackend(cfg IPAMConfig) *backend.IPAMConfig {
	return &backend.IPAMConfig{
		StrictAffinity:     cfg.StrictAffinity,
		AutoAllocateBlocks: cfg.AutoAllocateBlocks,
	}
}

func (c ipams) convertBackendToIPAMConfig(cfg backend.IPAMConfig) *IPAMConfig {
	return &IPAMConfig{
		StrictAffinity:     cfg.StrictAffinity,
		AutoAllocateBlocks: cfg.AutoAllocateBlocks,
	}
}

func decideHostname(host *string) string {
	// Determine the hostname to use - prefer the provided hostname if
	// non-nil, otherwise use the hostname reported by os.
	var hostname string
	var err error
	if host != nil {
		hostname = *host
	} else {
		hostname, err = os.Hostname()
		if err != nil {
			glog.Fatalf("Failed to acquire hostname")
		}
	}
	return hostname
}
