// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package client

import (
	goerrors "errors"
	"fmt"
	"os"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"
	log "github.com/sirupsen/logrus"
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
	AutoAssign(args AutoAssignArgs) ([]net.IP, []net.IP, error)

	// ReleaseIPs releases any of the given IP addresses that are currently assigned,
	// so that they are available to be used in another assignment.
	ReleaseIPs(ips []net.IP) ([]net.IP, error)

	// GetAssignmentAttributes returns the attributes stored with the given IP address
	// upon assignment.
	GetAssignmentAttributes(addr net.IP) (map[string]string, error)

	// IpsByHandle returns a list of all IP addresses that have been
	// assigned using the provided handle.
	IPsByHandle(handleID string) ([]net.IP, error)

	// ReleaseByHandle releases all IP addresses that have been assigned
	// using the provided handle.  Returns an error if no addresses
	// are assigned with the given handle.
	ReleaseByHandle(handleID string) error

	// ClaimAffinity claims affinity to the given host for all blocks
	// within the given CIDR.  The given CIDR must fall within a configured
	// pool. If an empty string is passed as the host, then the value returned by os.Hostname is used.
	ClaimAffinity(cidr net.IPNet, host string) ([]net.IPNet, []net.IPNet, error)

	// ReleaseAffinity releases affinity for all blocks within the given CIDR
	// on the given host.  If an empty string is passed as the host, then the
	// value returned by os.Hostname will be used.
	ReleaseAffinity(cidr net.IPNet, host string) error

	// ReleaseHostAffinities releases affinity for all blocks that are affine
	// to the given host.  If an empty string is passed as the host, the value returned by
	// os.Hostname will be used.
	ReleaseHostAffinities(host string) error

	// ReleasePoolAffinities releases affinity for all blocks within
	// the specified pool across all hosts.
	ReleasePoolAffinities(pool net.IPNet) error

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
	// If an empty string is passed as the host then the value returned by os.Hostname is used.
	RemoveIPAMHost(host string) error
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
func (c ipams) AutoAssign(args AutoAssignArgs) ([]net.IP, []net.IP, error) {
	// Determine the hostname to use - prefer the provided hostname if
	// non-nil, otherwise use the hostname reported by os.
	hostname := decideHostname(args.Hostname)
	log.Infof("Auto-assign %d ipv4, %d ipv6 addrs for host '%s'", args.Num4, args.Num6, hostname)

	var v4list, v6list []net.IP
	var err error

	if args.Num4 != 0 {
		// Assign IPv4 addresses.
		log.Debugf("Assigning IPv4 addresses")
		for _, pool := range args.IPv4Pools {
			if pool.IP.To4() == nil {
				return nil, nil, fmt.Errorf("provided IPv4 IPPools list contains one or more IPv6 IPPools")
			}
		}
		v4list, err = c.autoAssign(args.Num4, args.HandleID, args.Attrs, args.IPv4Pools, ipv4, hostname)
		if err != nil {
			log.Errorf("Error assigning IPV4 addresses: %s", err)
			return nil, nil, err
		}
	}

	if args.Num6 != 0 {
		// If no err assigning V4, try to assign any V6.
		log.Debugf("Assigning IPv6 addresses")
		for _, pool := range args.IPv6Pools {
			if pool.IP.To4() != nil {
				return nil, nil, fmt.Errorf("provided IPv6 IPPools list contains one or more IPv4 IPPools")
			}
		}
		v6list, err = c.autoAssign(args.Num6, args.HandleID, args.Attrs, args.IPv6Pools, ipv6, hostname)
		if err != nil {
			log.Errorf("Error assigning IPV6 addresses: %s", err)
			return nil, nil, err
		}
	}

	return v4list, v6list, nil
}

func (c ipams) autoAssign(num int, handleID *string, attrs map[string]string, pools []net.IPNet, version ipVersion, host string) ([]net.IP, error) {

	// Start by trying to assign from one of the host-affine blocks.  We
	// always do strict checking at this stage, so it doesn't matter whether
	// globally we have strict_affinity or not.
	log.Debugf("Looking for addresses in current affine blocks for host '%s'", host)
	affBlocks, err := c.blockReaderWriter.getAffineBlocks(host, version, pools)
	if err != nil {
		return nil, err
	}
	log.Debugf("Found %d affine IPv%d blocks for host '%s': %v", len(affBlocks), version.Number, host, affBlocks)
	ips := []net.IP{}
	for len(ips) < num {
		if len(affBlocks) == 0 {
			log.Infof("Ran out of existing affine blocks for host '%s'", host)
			break
		}
		cidr := affBlocks[0]
		affBlocks = affBlocks[1:]
		ips, _ = c.assignFromExistingBlock(cidr, num, handleID, attrs, host, true)
		log.Debugf("Block '%s' provided addresses: %v", cidr.String(), ips)
	}

	// If there are still addresses to allocate, then we've run out of
	// blocks with affinity.  Before we can assign new blocks or assign in
	// non-affine blocks, we need to check that our IPAM configuration
	// allows that.
	config, err := c.GetIPAMConfig()
	if err != nil {
		return nil, err
	}
	log.Debugf("Allocate new blocks? Config: %+v", config)
	if config.AutoAllocateBlocks == true {
		rem := num - len(ips)
		retries := ipamEtcdRetries
		for rem > 0 && retries > 0 {
			// Claim a new block.
			log.Infof("Need to allocate %d more addresses - allocate another block", rem)
			retries = retries - 1
			b, err := c.blockReaderWriter.claimNewAffineBlock(host, version, pools, *config)
			if err != nil {
				// Error claiming new block.
				if _, ok := err.(noFreeBlocksError); ok {
					// No free blocks.  Break.
					break
				}
				log.Errorf("Error claiming new block: %s", err)
				return nil, err
			} else {
				// Claim successful.  Assign addresses from the new block.
				log.Infof("Claimed new block %s - assigning %d addresses", b.String(), rem)
				newIPs, err := c.assignFromExistingBlock(*b, rem, handleID, attrs, host, config.StrictAffinity)
				if err != nil {
					log.Warningf("Failed to assign IPs:", err)
					break
				}
				log.Debugf("Assigned IPs from new block: %s", newIPs)
				ips = append(ips, newIPs...)
				rem = num - len(ips)
			}
		}

		if retries == 0 {
			return nil, goerrors.New("Max retries hit")
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
		log.Infof("Attempting to assign %d more addresses from non-affine blocks", rem)
		// Figure out the pools to allocate from.
		if len(pools) == 0 {
			// Default to all configured pools.
			allPools, err := c.client.IPPools().List(api.IPPoolMetadata{})
			if err != nil {
				log.Errorf("Error reading configured pools: %s", err)
				return ips, nil
			}

			// Grab all the IP networks in these pools.
			for _, p := range allPools.Items {
				// Don't include disabled pools.
				if !p.Spec.Disabled {
					pools = append(pools, p.Metadata.CIDR)
				}
			}
		}

		// Iterate over pools and assign addresses until we either run out of pools,
		// or the request has been satisfied.
		for _, p := range pools {
			log.Debugf("Assigning from random blocks in pool %s", p.String())
			newBlock := randomBlockGenerator(p, host)
			for rem > 0 {
				// Grab a new random block.
				blockCIDR := newBlock()
				if blockCIDR == nil {
					log.Warningf("All addresses exhausted in pool %s", p.String())
					break
				}

				// Attempt to assign from the block.
				newIPs, err := c.assignFromExistingBlock(*blockCIDR, rem, handleID, attrs, host, false)
				if err != nil {
					log.Warningf("Failed to assign IPs in pool %s: %s", p.String(), err)
					break
				}
				ips = append(ips, newIPs...)
				rem = num - len(ips)
			}
		}
	}

	log.Infof("Auto-assigned %d out of %d IPv%ds: %v", len(ips), num, version.Number, ips)
	return ips, nil
}

// AssignIP assigns the provided IP address to the provided host.  The IP address
// must fall within a configured pool.  AssignIP will claim block affinity as needed
// in order to satisfy the assignment.  An error will be returned if the IP address
// is already assigned, or if StrictAffinity is enabled and the address is within
// a block that does not have affinity for the given host.
func (c ipams) AssignIP(args AssignIPArgs) error {
	hostname := decideHostname(args.Hostname)
	log.Infof("Assigning IP %s to host: %s", args.IP, hostname)

	if !c.blockReaderWriter.withinConfiguredPools(args.IP) {
		return goerrors.New("The provided IP address is not in a configured pool\n")
	}

	blockCIDR := getBlockCIDRForAddress(args.IP)
	log.Debugf("IP %s is in block '%s'", args.IP.String(), blockCIDR.String())
	for i := 0; i < ipamEtcdRetries; i++ {
		obj, err := c.client.Backend.Get(model.BlockKey{blockCIDR})
		if err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
				// Block doesn't exist, we need to create it.  First,
				// validate the given IP address is within a configured pool.
				if !c.blockReaderWriter.withinConfiguredPools(args.IP) {
					estr := fmt.Sprintf("The given IP address (%s) is not in any configured pools", args.IP.String())
					log.Errorf(estr)
					return goerrors.New(estr)
				}
				log.Debugf("Block for IP %s does not yet exist, creating", args.IP)
				cfg, err := c.GetIPAMConfig()
				if err != nil {
					log.Errorf("Error getting IPAM Config: %s", err)
					return err
				}
				err = c.blockReaderWriter.claimBlockAffinity(blockCIDR, hostname, *cfg)
				if err != nil {
					if _, ok := err.(*affinityClaimedError); ok {
						log.Warningf("Someone else claimed block %s before us", blockCIDR.String())
						continue
					} else {
						return err
					}
				}
				log.Infof("Claimed new block: %s", blockCIDR)
				continue
			} else {
				// Unexpected error
				return err
			}
		}
		block := allocationBlock{obj.Value.(*model.AllocationBlock)}
		err = block.assign(args.IP, args.HandleID, args.Attrs, hostname)
		if err != nil {
			log.Errorf("Failed to assign address %s: %s", args.IP, err)
			return err
		}

		// Increment handle.
		if args.HandleID != nil {
			c.incrementHandle(*args.HandleID, blockCIDR, 1)
		}

		// Update the block using the original KVPair to do a CAS.  No need to
		// update the Value since we have been manipulating the Value pointed to
		// in the KVPair.
		_, err = c.client.Backend.Update(obj)
		if err != nil {
			log.Warningf("Update failed on block %s", block.CIDR.String())
			if args.HandleID != nil {
				c.decrementHandle(*args.HandleID, blockCIDR, 1)
			}
			return err
		}
		return nil
	}
	return goerrors.New("Max retries hit")
}

// ReleaseIPs releases any of the given IP addresses that are currently assigned,
// so that they are available to be used in another assignment.
func (c ipams) ReleaseIPs(ips []net.IP) ([]net.IP, error) {
	log.Infof("Releasing IP addresses: %v", ips)
	unallocated := []net.IP{}

	// Group IP addresses by block to minimize the number of writes
	// to the datastore required to release the given addresses.
	ipsByBlock := map[string][]net.IP{}
	for _, ip := range ips {
		// Check if we've already got an entry for this block.
		blockCIDR := getBlockCIDRForAddress(ip)
		cidrStr := blockCIDR.String()
		if _, exists := ipsByBlock[cidrStr]; !exists {
			// Entry does not exist, create it.
			ipsByBlock[cidrStr] = []net.IP{}
		}

		// Append to the list.
		ipsByBlock[cidrStr] = append(ipsByBlock[cidrStr], ip)
	}

	// Release IPs for each block.
	for cidrStr, ips := range ipsByBlock {
		_, cidr, _ := net.ParseCIDR(cidrStr)
		unalloc, err := c.releaseIPsFromBlock(ips, *cidr)
		if err != nil {
			log.Errorf("Error releasing IPs: %s", err)
			return nil, err
		}
		unallocated = append(unallocated, unalloc...)
	}
	return unallocated, nil
}

func (c ipams) releaseIPsFromBlock(ips []net.IP, blockCIDR net.IPNet) ([]net.IP, error) {
	for i := 0; i < ipamEtcdRetries; i++ {
		obj, err := c.client.Backend.Get(model.BlockKey{CIDR: blockCIDR})
		if err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
				// The block does not exist - all addresses must be unassigned.
				return ips, nil
			} else {
				// Unexpected error reading block.
				return nil, err
			}
		}

		// Block exists - get the allocationBlock from the KVPair.
		b := allocationBlock{obj.Value.(*model.AllocationBlock)}

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
		// Otherwise, update the block using CAS.  There is no need to update
		// the Value since we have updated the structure pointed to in the
		// KVPair.
		var updateErr error
		if b.empty() && b.Affinity == nil {
			log.Debugf("Deleting non-affine block '%s'", b.CIDR.String())
			updateErr = c.client.Backend.Delete(obj)
		} else {
			log.Debugf("Updating assignments in block '%s'", b.CIDR.String())
			_, updateErr = c.client.Backend.Update(obj)
		}

		if updateErr != nil {
			if _, ok := updateErr.(errors.ErrorResourceUpdateConflict); ok {
				// Comparison error - retry.
				log.Warningf("Failed to update block '%s' - retry #%d", b.CIDR.String(), i)
				continue
			} else {
				// Something else - return the error.
				log.Errorf("Error updating block '%s': %s", b.CIDR.String(), updateErr)
				return nil, updateErr
			}
		}

		// Success - decrement handles.
		log.Debugf("Decrementing handles: %v", handles)
		for handleID, amount := range handles {
			c.decrementHandle(handleID, blockCIDR, amount)
		}
		return unallocated, nil
	}
	return nil, goerrors.New("Max retries hit")
}

func (c ipams) assignFromExistingBlock(
	blockCIDR net.IPNet, num int, handleID *string, attrs map[string]string, host string, affCheck bool) ([]net.IP, error) {
	// Limit number of retries.
	var ips []net.IP
	for i := 0; i < ipamEtcdRetries; i++ {
		log.Debugf("Auto-assign from %s - retry %d", blockCIDR.String(), i)
		obj, err := c.client.Backend.Get(model.BlockKey{blockCIDR})
		if err != nil {
			log.Errorf("Error getting block: %s", err)
			return nil, err
		}

		// Pull out the block.
		b := allocationBlock{obj.Value.(*model.AllocationBlock)}

		log.Debugf("Got block: %+v", b)
		ips, err = b.autoAssign(num, handleID, host, attrs, affCheck)
		if err != nil {
			log.Errorf("Error in auto assign: %s", err)
			return nil, err
		}
		if len(ips) == 0 {
			log.Infof("Block %s is full", blockCIDR)
			return []net.IP{}, nil
		}

		// Increment handle count.
		if handleID != nil {
			c.incrementHandle(*handleID, blockCIDR, num)
		}

		// Update the block using CAS by passing back the original
		// KVPair.
		obj.Value = b.AllocationBlock
		_, err = c.client.Backend.Update(obj)
		if err != nil {
			log.Infof("Failed to update block '%s' - try again", b.CIDR.String())
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
// If an empty string is passed as the host, then the value of os.Hostname is used.
func (c ipams) ClaimAffinity(cidr net.IPNet, host string) ([]net.IPNet, []net.IPNet, error) {
	// Validate that the given CIDR is at least as big as a block.
	if !largerThanOrEqualToBlock(cidr) {
		estr := fmt.Sprintf("The requested CIDR (%s) is smaller than the minimum.", cidr.String())
		return nil, nil, invalidSizeError(estr)
	}

	// Determine the hostname to use.
	hostname := decideHostname(host)
	failed := []net.IPNet{}
	claimed := []net.IPNet{}

	// Verify the requested CIDR falls within a configured pool.
	if !c.blockReaderWriter.withinConfiguredPools(net.IP{cidr.IP}) {
		estr := fmt.Sprintf("The requested CIDR (%s) is not within any configured pools.", cidr.String())
		return nil, nil, goerrors.New(estr)
	}

	// Get IPAM config.
	cfg, err := c.GetIPAMConfig()
	if err != nil {
		log.Errorf("Failed to get IPAM Config: %s", err)
		return nil, nil, err
	}

	// Claim all blocks within the given cidr.
	blocks := blockGenerator(cidr)
	for blockCIDR := blocks(); blockCIDR != nil; blockCIDR = blocks() {
		err := c.blockReaderWriter.claimBlockAffinity(*blockCIDR, hostname, *cfg)
		if err != nil {
			if _, ok := err.(affinityClaimedError); ok {
				// Claimed by someone else - add to failed list.
				failed = append(failed, *blockCIDR)
			} else {
				log.Errorf("Failed to claim block: %s", err)
				return claimed, failed, err
			}
		} else {
			claimed = append(claimed, *blockCIDR)
		}
	}
	return claimed, failed, nil

}

// ReleaseAffinity releases affinity for all blocks within the given CIDR
// on the given host.  If a block does not have affinity for the given host,
// its affinity will not be released and no error will be returned.
// If an empty string is passed as the host, then the value of os.Hostname is used.
func (c ipams) ReleaseAffinity(cidr net.IPNet, host string) error {
	// Validate that the given CIDR is at least as big as a block.
	if !largerThanOrEqualToBlock(cidr) {
		estr := fmt.Sprintf("The requested CIDR (%s) is smaller than the minimum.", cidr.String())
		return invalidSizeError(estr)
	}

	// Determine the hostname to use.
	hostname := decideHostname(host)

	// Release all blocks within the given cidr.
	blocks := blockGenerator(cidr)
	for blockCIDR := blocks(); blockCIDR != nil; blockCIDR = blocks() {
		err := c.blockReaderWriter.releaseBlockAffinity(hostname, *blockCIDR)
		if err != nil {
			if _, ok := err.(affinityClaimedError); ok {
				// Not claimed by this host - ignore.
			} else if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
				// Block does not exist - ignore.
			} else {
				log.Errorf("Error releasing affinity for '%s': %s", *blockCIDR, err)
				return err
			}
		}
	}
	return nil
}

// ReleaseHostAffinities releases affinity for all blocks that are affine
// to the given host.  If an empty string is passed as the host,
// then the value of os.Hostname is used.
func (c ipams) ReleaseHostAffinities(host string) error {
	hostname := decideHostname(host)

	versions := []ipVersion{ipv4, ipv6}
	for _, version := range versions {
		blockCIDRs, err := c.blockReaderWriter.getAffineBlocks(hostname, version, nil)
		if err != nil {
			return err
		}

		for _, blockCIDR := range blockCIDRs {
			err := c.ReleaseAffinity(blockCIDR, hostname)
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
func (c ipams) ReleasePoolAffinities(pool net.IPNet) error {
	log.Infof("Releasing block affinities within pool '%s'", pool.String())
	for i := 0; i < ipamKeyErrRetries; i++ {
		retry := false
		pairs, err := c.hostBlockPairs(pool)
		if err != nil {
			return err
		}

		if len(pairs) == 0 {
			log.Debugf("No blocks have affinity")
			return nil
		}

		for blockString, host := range pairs {
			_, blockCIDR, _ := net.ParseCIDR(blockString)
			err = c.blockReaderWriter.releaseBlockAffinity(host, *blockCIDR)
			if err != nil {
				if _, ok := err.(affinityClaimedError); ok {
					retry = true
				} else if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
					log.Debugf("No such block '%s'", blockCIDR.String())
					continue
				} else {
					log.Errorf("Error releasing affinity for '%s': %s", blockCIDR.String(), err)
					return err
				}
			}

		}

		if !retry {
			return nil
		}
	}
	return goerrors.New("Max retries hit")
}

// RemoveIPAMHost releases affinity for all blocks on the given host,
// and removes all host-specific IPAM data from the datastore.
// RemoveIPAMHost does not release any IP addresses claimed on the given host.
// If an empty string is passed as the host, then the value of os.Hostname is used.
func (c ipams) RemoveIPAMHost(host string) error {
	// Determine the hostname to use.
	hostname := decideHostname(host)

	// Release affinities for this host.
	c.ReleaseHostAffinities(hostname)

	// Remove the host tree from the datastore.
	err := c.client.Backend.Delete(&model.KVPair{
		Key: model.IPAMHostKey{Host: hostname},
	})
	if err != nil {
		// Return the error unless the resource does not exist.
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			log.Errorf("Error removing IPAM host: %s", err)
			return err
		}
	}
	return nil
}

func (c ipams) hostBlockPairs(pool net.IPNet) (map[string]string, error) {
	pairs := map[string]string{}

	// Get all blocks and their affinities.
	objs, err := c.client.Backend.List(model.BlockAffinityListOptions{})
	if err != nil {
		log.Errorf("Error querying block affinities: %s", err)
		return nil, err
	}

	// Iterate through each block affinity and build up a mapping
	// of blockCidr -> host.
	log.Debugf("Getting block -> host mappings")
	for _, o := range objs {
		k := o.Key.(model.BlockAffinityKey)

		// Only add the pair to the map if the block belongs to the pool.
		if pool.Contains(k.CIDR.IPNet.IP) {
			pairs[k.CIDR.String()] = k.Host
		}
		log.Debugf("Block %s -> %s", k.CIDR.String(), k.Host)
	}

	return pairs, nil
}

// IpsByHandle returns a list of all IP addresses that have been
// assigned using the provided handle.
func (c ipams) IPsByHandle(handleID string) ([]net.IP, error) {
	obj, err := c.client.Backend.Get(model.IPAMHandleKey{HandleID: handleID})
	if err != nil {
		return nil, err
	}
	handle := allocationHandle{obj.Value.(*model.IPAMHandle)}

	assignments := []net.IP{}
	for k, _ := range handle.Block {
		_, blockCIDR, _ := net.ParseCIDR(k)
		obj, err := c.client.Backend.Get(model.BlockKey{*blockCIDR})
		if err != nil {
			log.Warningf("Couldn't read block %s referenced by handle %s", blockCIDR, handleID)
			continue
		}

		// Pull out the allocationBlock and get all the assignments
		// from it.
		b := allocationBlock{obj.Value.(*model.AllocationBlock)}
		assignments = append(assignments, b.ipsByHandle(handleID)...)
	}
	return assignments, nil
}

// ReleaseByHandle releases all IP addresses that have been assigned
// using the provided handle.
func (c ipams) ReleaseByHandle(handleID string) error {
	log.Infof("Releasing all IPs with handle '%s'", handleID)
	obj, err := c.client.Backend.Get(model.IPAMHandleKey{HandleID: handleID})
	if err != nil {
		return err
	}
	handle := allocationHandle{obj.Value.(*model.IPAMHandle)}

	for blockStr, _ := range handle.Block {
		_, blockCIDR, _ := net.ParseCIDR(blockStr)
		err = c.releaseByHandle(handleID, *blockCIDR)
	}
	return nil
}

func (c ipams) releaseByHandle(handleID string, blockCIDR net.IPNet) error {
	for i := 0; i < ipamEtcdRetries; i++ {
		obj, err := c.client.Backend.Get(model.BlockKey{CIDR: blockCIDR})
		if err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
				// Block doesn't exist, so all addresses are already
				// unallocated.  This can happen when a handle is
				// overestimating the number of assigned addresses.
				return nil
			} else {
				return err
			}
		}
		block := allocationBlock{obj.Value.(*model.AllocationBlock)}
		num := block.releaseByHandle(handleID)
		if num == 0 {
			// Block has no addresses with this handle, so
			// all addresses are already unallocated.
			return nil
		}

		if block.empty() && block.Affinity == nil {
			err = c.client.Backend.Delete(&model.KVPair{
				Key: model.BlockKey{blockCIDR},
			})
			if err != nil {
				// Return the error unless the resource does not exist.
				if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
					log.Errorf("Error deleting block: %s", err)
					return err
				}
			}
		} else {
			// Compare and swap the AllocationBlock using the original
			// KVPair read from before.  No need to update the Value since we
			// have been directly manipulating the value referenced by the KVPair.
			_, err = c.client.Backend.Update(obj)
			if err != nil {
				if _, ok := err.(errors.ErrorResourceUpdateConflict); ok {
					// Comparison failed - retry.
					log.Warningf("CAS error for block, retry #%d: %s", i, err)
					continue
				} else {
					// Something else - return the error.
					log.Errorf("Error updating block '%s': %s", block.CIDR.String(), err)
					return err
				}
			}
		}

		c.decrementHandle(handleID, blockCIDR, num)
		return nil
	}
	return goerrors.New("Hit max retries")
}

func (c ipams) incrementHandle(handleID string, blockCIDR net.IPNet, num int) error {
	var obj *model.KVPair
	var err error
	for i := 0; i < ipamEtcdRetries; i++ {
		obj, err = c.client.Backend.Get(model.IPAMHandleKey{HandleID: handleID})
		if err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
				// Handle doesn't exist - create it.
				log.Infof("Creating new handle: %s", handleID)
				bh := model.IPAMHandle{
					HandleID: handleID,
					Block:    map[string]int{},
				}
				obj = &model.KVPair{
					Key:   model.IPAMHandleKey{HandleID: handleID},
					Value: &bh,
				}
			} else {
				// Unexpected error reading handle.
				return err
			}
		}

		// Get the handle from the KVPair.
		handle := allocationHandle{obj.Value.(*model.IPAMHandle)}

		// Increment the handle for this block.
		handle.incrementBlock(blockCIDR, num)

		// Compare and swap the handle using the KVPair from above.  We've been
		// manipulating the structure in the KVPair, so pass straight back to
		// apply the changes.
		_, err = c.client.Backend.Apply(obj)
		if err != nil {
			continue
		}
		return nil
	}
	return goerrors.New("Max retries hit")

}

func (c ipams) decrementHandle(handleID string, blockCIDR net.IPNet, num int) error {
	for i := 0; i < ipamEtcdRetries; i++ {
		obj, err := c.client.Backend.Get(model.IPAMHandleKey{HandleID: handleID})
		if err != nil {
			log.Fatalf("Can't decrement block because it doesn't exist")
		}
		handle := allocationHandle{obj.Value.(*model.IPAMHandle)}

		_, err = handle.decrementBlock(blockCIDR, num)
		if err != nil {
			log.Fatalf("Can't decrement block - too few allocated")
		}

		// Update / Delete as appropriate.  Since we have been manipulating the
		// data in the KVPair, just pass this straight back to the client.
		if handle.empty() {
			log.Debugf("Deleting handle: %s", handleID)
			err = c.client.Backend.Delete(obj)
		} else {
			log.Debugf("Updating handle: %s", handleID)
			_, err = c.client.Backend.Update(obj)
		}

		// Check error.
		if err != nil {
			continue
		}
		log.Infof("Decremented handle '%s' by %d", handleID, num)
		return nil
	}
	return goerrors.New("Max retries hit")
}

// GetAssignmentAttributes returns the attributes stored with the given IP address
// upon assignment.
func (c ipams) GetAssignmentAttributes(addr net.IP) (map[string]string, error) {
	blockCIDR := getBlockCIDRForAddress(addr)
	obj, err := c.client.Backend.Get(model.BlockKey{blockCIDR})
	if err != nil {
		log.Errorf("Error reading block %s: %s", blockCIDR, err)
		return nil, goerrors.New(fmt.Sprintf("%s is not assigned", addr))
	}
	block := allocationBlock{obj.Value.(*model.AllocationBlock)}
	return block.attributesForIP(addr)
}

// GetIPAMConfig returns the global IPAM configuration.  If no IPAM configuration
// has been set, returns a default configuration with StrictAffinity disabled
// and AutoAllocateBlocks enabled.
func (c ipams) GetIPAMConfig() (*IPAMConfig, error) {
	obj, err := c.client.Backend.Get(model.IPAMConfigKey{})
	if err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
			// IPAMConfig has not been explicitly set.  Return
			// a default IPAM configuration.
			return &IPAMConfig{AutoAllocateBlocks: true, StrictAffinity: false}, nil
		}
		log.Errorf("Error getting IPAMConfig: %s", err)
		return nil, err
	}
	return c.convertBackendToIPAMConfig(obj.Value.(*model.IPAMConfig)), nil
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
		return goerrors.New("Cannot disable 'StrictAffinity' and 'AutoAllocateBlocks' at the same time")
	}

	allObjs, err := c.client.Backend.List(model.BlockListOptions{})
	if len(allObjs) != 0 {
		return goerrors.New("Cannot change IPAM config while allocations exist")
	}

	// Write to datastore.
	obj := model.KVPair{
		Key:   model.IPAMConfigKey{},
		Value: c.convertIPAMConfigToBackend(&cfg),
	}
	_, err = c.client.Backend.Apply(&obj)
	if err != nil {
		log.Errorf("Error applying IPAMConfig: %s", err)
		return err
	}
	return nil
}

func (c ipams) convertIPAMConfigToBackend(cfg *IPAMConfig) *model.IPAMConfig {
	return &model.IPAMConfig{
		StrictAffinity:     cfg.StrictAffinity,
		AutoAllocateBlocks: cfg.AutoAllocateBlocks,
	}
}

func (c ipams) convertBackendToIPAMConfig(cfg *model.IPAMConfig) *IPAMConfig {
	return &IPAMConfig{
		StrictAffinity:     cfg.StrictAffinity,
		AutoAllocateBlocks: cfg.AutoAllocateBlocks,
	}
}

func decideHostname(host string) string {
	// Determine the hostname to use - prefer the provided hostname if
	// non-nil, otherwise use the hostname reported by os.
	var hostname string
	var err error
	if host != "" {
		hostname = host
	} else {
		hostname, err = os.Hostname()
		if err != nil {
			log.Fatalf("Failed to acquire hostname")
		}
	}
	log.Debugf("Using hostname=%s", hostname)
	return hostname
}
