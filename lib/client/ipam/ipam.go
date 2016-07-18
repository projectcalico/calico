package ipam

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/coreos/etcd/client"
	"github.com/golang/glog"
	"golang.org/x/net/context"
)

const (
	// Number of retries when we have an error writing data
	// to etcd.
	etcdRetries   = 100
	keyErrRetries = 3

	// IPAM paths
	ipamVersionPath      = "/calico/ipam/v2/"
	ipamConfigPath       = ipamVersionPath + "config"
	ipamHostsPath        = ipamVersionPath + "host"
	ipamHostPath         = ipamHostsPath + "/%s"
	ipamHostAffinityPath = ipamHostPath + "/ipv%d/block/"
	ipamBlockPath        = ipamVersionPath + "assignment/ipv%d/block/"
	ipamHandlePath       = ipamVersionPath + "handle/"
)

// IPAMClient is a client which can be used to configure global IPAM configuration,
// IP allocations, and affinities.
type IPAMClient struct {
	blockReaderWriter blockReaderWriter
}

// Creates a new IPAMClient.
func NewIPAMClient(keysApi client.KeysAPI) (*IPAMClient, error) {
	// Create the interface into etcd for blocks.
	glog.V(1).Infof("Creating new IPAM client")
	b := blockReaderWriter{etcd: keysApi}
	return &IPAMClient{blockReaderWriter: b}, nil
}

// IPAMConfig contains global configuration options for Calico IPAM.
type IPAMConfig struct {
	// When StrictAffinity is true, addresses from a given block can only be
	// assigned by hosts with the blocks affinity.  If false, then AutoAllocateBlocks
	// must be true.
	StrictAffinity bool

	// When AutoAllocateBlocks is true, the IPAM client will automatically
	// allocate blocks as needed to assign addresses.  If false, then
	// StrictAffinity must be true.
	AutoAllocateBlocks bool
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
	Hostname *string

	// If specified, the previously configured IPv4 pool from which
	// to assign IPv4 addresses.  If not specified, this defaults to all IPv4 pools.
	IPv4Pool *net.IPNet

	// If specified, the previously configured IPv6 pool from which
	// to assign IPv6 addresses.  If not specified, this defaults to all IPv6 pools.
	IPv6Pool *net.IPNet
}

// AutoAssign automatically assigns one or more IP addresses as specified by the
// provided AutoAssignArgs.  AutoAssign returns the list of the assigned IPv4 addresses,
// and the list of the assigned IPv6 addresses.
func (c IPAMClient) AutoAssign(args AutoAssignArgs) ([]net.IP, []net.IP, error) {
	// Determine the hostname to use - prefer the provided hostname if
	// non-nil, otherwise use the hostname reported by os.
	hostname := decideHostname(args.Hostname)
	glog.V(2).Infof("Auto-assign %d ipv4, %d ipv6 addrs for host '%s'", args.Num4, args.Num6, hostname)

	var v4list, v6list []net.IP
	var err error

	if args.Num4 != 0 {
		// Assign IPv4 addresses.
		v4list, err = c.autoAssign(args.Num4, args.HandleID, args.Attrs, args.IPv4Pool, ipv4, hostname)
		if err != nil {
			glog.Errorf("Error assigning IPV4 addresses: %s", err)
			return nil, nil, err
		}
	}

	if args.Num6 != 0 {
		// If no err assigning V4, try to assign any V6.
		v6list, err = c.autoAssign(args.Num6, args.HandleID, args.Attrs, args.IPv6Pool, ipv6, hostname)
		if err != nil {
			return nil, nil, err
		}
	}

	return v4list, v6list, nil
}

func (c IPAMClient) autoAssign(num int, handleID *string, attrs map[string]string, pool *net.IPNet, version ipVersion, host string) ([]net.IP, error) {

	// Start by trying to assign from one of the host-affine blocks.  We
	// always do strict checking at this stage, so it doesn't matter whether
	// globally we have strict_affinity or not.
	glog.V(4).Infof("Looking for addresses in current affine blocks for host '%s'", host)
	affBlocks, err := c.blockReaderWriter.getAffineBlocks(host, version, pool)
	if err != nil {
		return nil, err
	}
	glog.V(4).Infof("Found %d affine IPv%d blocks for host '%s': %v", len(affBlocks), version.Number, host, affBlocks)
	ips := []net.IP{}
	for len(ips) < num {
		if len(affBlocks) == 0 {
			glog.V(2).Infof("Ran out of affine blocks for host '%s'", host)
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
	if config.AutoAllocateBlocks == true {
		rem := num - len(ips)
		retries := etcdRetries
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
				glog.V(2).Infof("Claimed new block %s - assigning %s addresses", b.String(), rem)
				newIPs, err := c.assignFromExistingBlock(*b, rem, handleID, attrs, host, &config.StrictAffinity)
				if err != nil {
					glog.Warningf("Failed to assign IPs:", err)
					break
				}
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
		glog.Warningf("Attempting to assign %d more addresses from non-affine blocks", rem)
		// TODO: this
	}

	glog.V(1).Infof("Auto-assigned IPv%ds: %v", version.Number, ips)
	return ips, nil
}

// AssignIPArgs defines the set of arguments for assigning a specific IP address.
type AssignIPArgs struct {
	// The IP address to assign.
	IP net.IP

	// If specified, a handle which can be used to retrieve / release
	// the allocated IP addresses in the future.
	HandleID *string

	// A key/value mapping of metadata to store with the allocations.
	Attrs map[string]string

	// If specified, the hostname of the host on which IP addresses
	// will be allocated.  If not specified, this will default
	// to the value provided by os.Hostname.
	Hostname *string
}

// AssignIP assigns the provided IP address to the provided host.  The IP address
// must fall within a configured pool.  AssignIP will claim block affinity as needed
// in order to satisfy the assignment.  An error will be returned if the IP address
// is already assigned, or if StrictAffinity is enabled and the address is within
// a block that does not have affinity for the given host.
func (c IPAMClient) AssignIP(args AssignIPArgs) error {
	hostname := decideHostname(args.Hostname)
	glog.V(2).Infof("Assigning IP %s to host: %s", args.IP, hostname)

	if !c.blockReaderWriter.withinConfiguredPools(args.IP) {
		return errors.New("The provided IP address is not in a configured pool\n")
	}

	blockCidr := getBlockCIDRForAddress(args.IP)
	glog.V(3).Infof("IP %s is in block '%s'", args.IP.String(), blockCidr.String())
	for i := 0; i < etcdRetries; i++ {
		block, err := c.blockReaderWriter.readBlock(blockCidr)
		if err != nil {
			if _, ok := err.(noSuchBlockError); ok {
				// Block doesn't exist, we need to create it.  First,
				// validate the given IP address is within a configured pool.
				if !c.blockReaderWriter.withinConfiguredPools(args.IP) {
					estr := fmt.Sprintf("The given IP address (%s) is no in any configured pools", args.IP.String())
					return errors.New(estr)
				}
				glog.V(3).Infof("Block for IP %s does not yet exist, creating", args.IP)
				cfg := IPAMConfig{StrictAffinity: false, AutoAllocateBlocks: true}
				err := c.blockReaderWriter.claimBlockAffinity(blockCidr, hostname, cfg)
				if err != nil {
					if _, ok := err.(*AffinityClaimedError); ok {
						glog.Warningf("Someone else claimed block %s before us", blockCidr)
						continue
					} else {
						return err
					}
				}
				glog.V(2).Infof("Claimed new block: %s", blockCidr)
				continue
			} else {
				// Unexpected error
				return err
			}
		}
		err = block.assign(args.IP, args.HandleID, args.Attrs, hostname)
		if err != nil {
			glog.Errorf("Failed to assign address %s: %s", args.IP, err)
			return err
		}

		// Increment handle.
		if args.HandleID != nil {
			c.incrementHandle(*args.HandleID, blockCidr, 1)
		}

		// Update the block.
		err = c.blockReaderWriter.compareAndSwapBlock(*block)
		if err != nil {
			glog.Warningf("CAS failed on block %s", block.Cidr)
			if args.HandleID != nil {
				c.decrementHandle(*args.HandleID, blockCidr, 1)
			}
			return err
		}
		return nil
	}
	return errors.New("Max retries hit")
}

// ReleaseIPs releases any of the given IP addresses that are currently assigned,
// so that they are available to be used in another assignment.
func (c IPAMClient) ReleaseIPs(ips []net.IP) ([]net.IP, error) {
	glog.V(2).Infof("Releasing IP addresses: %v", ips)
	unallocated := []net.IP{}
	for _, ip := range ips {
		blockCidr := getBlockCIDRForAddress(ip)
		// TODO: Group IP addresses per-block to minimize writes to etcd.
		unalloc, err := c.releaseIPsFromBlock([]net.IP{ip}, blockCidr)
		if err != nil {
			glog.Errorf("Error releasing IPs: %s", err)
			return nil, err
		}
		unallocated = append(unallocated, unalloc...)
	}
	return unallocated, nil
}

func (c IPAMClient) releaseIPsFromBlock(ips []net.IP, blockCidr net.IPNet) ([]net.IP, error) {
	for i := 0; i < etcdRetries; i++ {
		b, err := c.blockReaderWriter.readBlock(blockCidr)
		if err != nil {
			if _, ok := err.(noSuchBlockError); ok {
				// The block does not exist - all addresses must be unassigned.
				return ips, nil
			} else {
				// Unexpected error reading block.
				return nil, err
			}
		}

		// Block exists - release the IPs from it.
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
		var casError error
		if b.empty() && b.HostAffinity == nil {
			glog.V(3).Infof("Deleting non-affine block '%s'", b.Cidr.String())
			casError = c.blockReaderWriter.deleteBlock(*b)
		} else {
			glog.V(3).Infof("Updating assignments in block '%s'", b.Cidr.String())
			casError = c.blockReaderWriter.compareAndSwapBlock(*b)
		}

		if casError != nil {
			glog.Warningf("Failed to update block '%s' - retry #%d", b.Cidr.String(), i)
			continue
		}

		// Success - decrement handles.
		glog.V(3).Infof("Decrementing handles: %v", handles)
		for handleID, amount := range handles {
			c.decrementHandle(handleID, blockCidr, amount)
		}
		return unallocated, nil
	}
	return nil, errors.New("Max retries hit")
}

func (c IPAMClient) assignFromExistingBlock(
	blockCidr net.IPNet, num int, handleID *string, attrs map[string]string, host string, affCheck *bool) ([]net.IP, error) {
	// Limit number of retries.
	var ips []net.IP
	for i := 0; i < etcdRetries; i++ {
		glog.V(4).Infof("Auto-assign from %s - retry %d", blockCidr.String(), i)
		b, err := c.blockReaderWriter.readBlock(blockCidr)
		if err != nil {
			return nil, err
		}
		glog.V(4).Infof("Got block: %v", b)
		ips, err = b.autoAssign(num, handleID, host, attrs, true)
		if err != nil {
			glog.Errorf("Error in auto assign: %s", err)
			return nil, err
		}
		if len(ips) == 0 {
			glog.V(2).Infof("Block %s is full", blockCidr)
			return []net.IP{}, nil
		}

		// Increment handle count.
		if handleID != nil {
			c.incrementHandle(*handleID, blockCidr, num)
		}

		// Update the block using CAS.
		err = c.blockReaderWriter.compareAndSwapBlock(*b)
		if err != nil {
			glog.V(2).Infof("Failed to update block '%s' - try again", b.Cidr.String())
			if handleID != nil {
				c.decrementHandle(*handleID, blockCidr, num)
			}
			continue
		}
		break
	}
	return ips, nil
}

// ClaimAffinity claims affinity to the given host for all blocks
// within the given CIDR.  The given CIDR must fall within a configured
// pool.
// TODO: Return indicators of claimed vs already claimed by another host.
func (c IPAMClient) ClaimAffinity(cidr net.IPNet, host *string) error {
	// Validate that the given CIDR is at least as big as a block.
	if !largerThanBlock(cidr) {
		estr := fmt.Sprintf("The requested CIDR (%s) is smaller than the minimum.", cidr.String())
		return InvalidSizeError(estr)
	}

	// Determine the hostname to use.
	hostname := decideHostname(host)

	// Verify the requested CIDR falls within a configured pool.
	if !c.blockReaderWriter.withinConfiguredPools(cidr.IP) {
		estr := fmt.Sprintf("The requested CIDR (%s) is not within any configured pools.", cidr.String())
		return errors.New(estr)
	}

	// Get IPAM config.
	cfg, err := c.GetIPAMConfig()
	if err != nil {
		return err
	}

	// Claim all blocks within the given cidr.
	for _, blockCidr := range blocks(cidr) {
		err := c.blockReaderWriter.claimBlockAffinity(blockCidr, hostname, *cfg)
		if err != nil {
			// TODO: Check error type to determine:
			// 1) claimed by another host.
			return err
		}
	}
	return nil

}

// ReleaseAffinity releases affinity for all blocks within the given CIDR
// on the given host.  If host is not specified, then the value returned by os.Hostname
// will be used.
func (c IPAMClient) ReleaseAffinity(cidr net.IPNet, host *string) error {
	// Validate that the given CIDR is at least as big as a block.
	if !largerThanBlock(cidr) {
		estr := fmt.Sprintf("The requested CIDR (%s) is smaller than the minimum.", cidr.String())
		return InvalidSizeError(estr)
	}

	// Determine the hostname to use.
	hostname := decideHostname(host)

	// Release all blocks within the given cidr.
	for _, blockCidr := range blocks(cidr) {
		err := c.blockReaderWriter.releaseBlockAffinity(hostname, blockCidr)
		if err != nil {
			// TODO: Check error type to determine:
			// 1) claimed by another host.
			// 2) not claimed.
			return err
		}
	}
	return nil
}

// ReleaseHostAffinities releases affinity for all blocks that are affine
// to the given host.  If host is not specified, the value returned by os.Hostname
// will be used.
func (c IPAMClient) ReleaseHostAffinities(host *string) error {
	hostname := decideHostname(host)

	versions := []ipVersion{ipv4, ipv6}
	for _, version := range versions {
		blockCidrs, err := c.blockReaderWriter.getAffineBlocks(hostname, version, nil)
		if err != nil {
			return err
		}

		for _, blockCidr := range blockCidrs {
			err := c.ReleaseAffinity(blockCidr, &hostname)
			if err != nil {
				if _, ok := err.(AffinityClaimedError); ok {
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
func (c IPAMClient) ReleasePoolAffinities(pool net.IPNet) error {
	glog.V(2).Infof("Releasing block affinities within pool '%s'", pool.String())
	for i := 0; i < keyErrRetries; i++ {
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
			_, blockCidr, _ := net.ParseCIDR(blockString)
			err = c.blockReaderWriter.releaseBlockAffinity(host, *blockCidr)
			if err != nil {
				if _, ok := err.(AffinityClaimedError); ok {
					retry = true
				} else if _, ok := err.(noSuchBlockError); ok {
					glog.V(4).Infof("No such block '%s'", blockCidr.String())
					continue
				} else {
					glog.Errorf("Error releasing affinity for '%s': %s", blockCidr.String(), err)
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
func (c IPAMClient) RemoveIPAMHost(host *string) error {
	// Determine the hostname to use.
	hostname := decideHostname(host)

	// Release host affinities.
	c.ReleaseHostAffinities(&hostname)

	// Remove the host ipam tree.
	key := fmt.Sprintf(ipamHostPath, hostname)
	opts := client.DeleteOptions{Recursive: true}
	_, err := c.blockReaderWriter.etcd.Delete(context.Background(), key, &opts)
	if err != nil {
		if eerr, ok := err.(client.Error); ok && eerr.Code == client.ErrorCodeNodeExist {
			// Already deleted.  Carry on.

		} else {
			return err
		}
	}
	return nil
}

func (c IPAMClient) hostBlockPairs(pool net.IPNet) (map[string]string, error) {
	pairs := map[string]string{}

	opts := client.GetOptions{Quorum: true, Recursive: true}
	res, err := c.blockReaderWriter.etcd.Get(context.Background(), ipamHostsPath, &opts)
	if err != nil {
		return nil, err
	}

	if res.Node != nil {
		for _, n := range leaves(*res.Node) {
			if !n.Dir {
				// Extract the block identifier (subnet) which is encoded
				// into the etcd key.  We need to replace "-" with "/" to
				// turn it back into a cidr.  Also pull out the hostname.
				ss := strings.Split(n.Key, "/")
				ipString := strings.Replace(ss[len(ss)-1], "-", "/", 1)
				pairs[ipString] = ss[5]
			}
		}
	}
	return pairs, nil
}

func leaves(root client.Node) []client.Node {
	l := []client.Node{}
	for _, n := range root.Nodes {
		if !n.Dir {
			l = append(l, *n)
		} else {
			l = append(l, leaves(*n)...)
		}
	}
	return l
}

// IpsByHandle returns a list of all IP addresses that have been
// assigned using the provided handle.
func (c IPAMClient) IPsByHandle(handleID string) ([]net.IP, error) {
	handle, err := c.readHandle(handleID)
	if err != nil {
		return nil, err
	}

	assignments := []net.IP{}
	for k, _ := range handle.Block {
		_, blockCidr, _ := net.ParseCIDR(k)
		b, err := c.blockReaderWriter.readBlock(*blockCidr)
		if err != nil {
			glog.Warningf("Couldn't read block %s referenced by handle %s", blockCidr, handleID)
			continue
		}
		assignments = append(assignments, b.ipsByHandle(handleID)...)
	}
	return assignments, nil
}

// ReleaseByHandle releases all IP addresses that have been assigned
// using the provided handle.
func (c IPAMClient) ReleaseByHandle(handleID string) error {
	glog.V(2).Infof("Releasing all IPs with handle '%s'", handleID)
	handle, err := c.readHandle(handleID)
	if err != nil {
		return err
	}

	for blockStr, _ := range handle.Block {
		_, blockCidr, _ := net.ParseCIDR(blockStr)
		err = c.releaseByHandle(handleID, *blockCidr)
	}
	return nil
}

func (c IPAMClient) releaseByHandle(handleID string, blockCidr net.IPNet) error {
	for i := 0; i < etcdRetries; i++ {
		block, err := c.blockReaderWriter.readBlock(blockCidr)
		if err != nil {
			if _, ok := err.(noSuchBlockError); ok {
				// Block doesn't exist, so all addresses are already
				// unallocated.  This can happen when a handle is
				// overestimating the number of assigned addresses.
				return nil
			} else {
				return err
			}
		}
		num := block.releaseByHandle(handleID)
		if num == 0 {
			// Block has no addresses with this handle, so
			// all addresses are already unallocated.
			return nil
		}

		if block.empty() && block.HostAffinity == nil {
			err = c.blockReaderWriter.deleteBlock(*block)
			if err != nil {
				if eerr, ok := err.(client.Error); ok && eerr.Code == client.ErrorCodeNodeExist {
					// Already deleted - carry on.
				} else {
					return err
				}
			}
		} else {
			err = c.blockReaderWriter.compareAndSwapBlock(*block)
			if err != nil {
				// Failed to update - retry.
				glog.Warningf("CAS error for block, retry #%d: %s", i, err)
				continue
			}
		}

		c.decrementHandle(handleID, blockCidr, num)
		return nil
	}
	return errors.New("Hit max retries")
}

func (c IPAMClient) readHandle(handleID string) (*allocationHandle, error) {
	key := ipamHandlePath + handleID
	opts := client.GetOptions{Quorum: true}
	resp, err := c.blockReaderWriter.etcd.Get(context.Background(), key, &opts)
	if err != nil {
		glog.Errorf("Error reading IPAM handle:", err)
		return nil, err
	}
	h := allocationHandle{}
	json.Unmarshal([]byte(resp.Node.Value), &h)
	h.DbResult = resp.Node.Value
	return &h, nil
}

func (c IPAMClient) incrementHandle(handleID string, blockCidr net.IPNet, num int) error {
	for i := 0; i < etcdRetries; i++ {
		handle, err := c.readHandle(handleID)
		if err != nil {
			if client.IsKeyNotFound(err) {
				// Handle doesn't exist - create it.
				glog.V(2).Infof("Creating new handle:", handleID)
				handle = &allocationHandle{
					HandleID: handleID,
					Block:    map[string]int{},
				}
			} else {
				// Unexpected error reading handle.
				return err
			}
		}

		// Increment the handle for this block.
		handle.incrementBlock(blockCidr, num)
		err = c.compareAndSwapHandle(*handle)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.New("Max retries hit")

}

func (c IPAMClient) decrementHandle(handleID string, blockCidr net.IPNet, num int) error {
	for i := 0; i < etcdRetries; i++ {
		handle, err := c.readHandle(handleID)
		if err != nil {
			glog.Fatalf("Can't decrement block because it doesn't exist")
		}

		_, err = handle.decrementBlock(blockCidr, num)
		if err != nil {
			glog.Fatalf("Can't decrement block - too few allocated")
		}

		err = c.compareAndSwapHandle(*handle)
		if err != nil {
			continue
		}
		glog.V(2).Infof("Decremented handle '%s' by %d", handleID, num)
		return nil
	}
	return errors.New("Max retries hit")
}

func (c IPAMClient) compareAndSwapHandle(h allocationHandle) error {
	// If the block has a store result, compare and swap agianst that.
	var opts client.SetOptions
	key := ipamHandlePath + h.HandleID

	// Determine correct Set options.
	if h.DbResult != "" {
		if h.empty() {
			// The handle is empty - delete it instead of an update.
			glog.V(3).Infof("CAS delete handle: %s", h.HandleID)
			deleteOpts := client.DeleteOptions{PrevValue: h.DbResult}
			_, err := c.blockReaderWriter.etcd.Delete(context.Background(),
				key, &deleteOpts)
			return err
		}
		glog.V(3).Infof("CAS update handle: %s", h.HandleID)
		opts = client.SetOptions{PrevExist: client.PrevExist, PrevValue: h.DbResult}
	} else {
		glog.V(3).Infof("CAS write new handle: %s", h.HandleID)
		opts = client.SetOptions{PrevExist: client.PrevNoExist}
	}

	j, err := json.Marshal(h)
	if err != nil {
		glog.Errorf("Error converting handle to json: %s", err)
		return err
	}
	_, err = c.blockReaderWriter.etcd.Set(context.Background(), key, string(j), &opts)
	if err != nil {
		glog.Errorf("CAS error writing json: %s", err)
		return err
	}

	return nil
}

// GetAssignmentAttributes returns the attributes stored with the given IP address
// upon assignment.
func (c IPAMClient) GetAssignmentAttributes(addr net.IP) (map[string]string, error) {
	blockCidr := getBlockCIDRForAddress(addr)
	block, err := c.blockReaderWriter.readBlock(blockCidr)
	if err != nil {
		glog.Errorf("Error reading block %s: %s", blockCidr, err)
		return nil, errors.New(fmt.Sprintf("%s is not assigned", addr))
	}
	return block.attributesForIP(addr)
}

// GetIPAMConfig returns the global IPAM configuration.  If no IPAM configuration
// has been set, returns a default configuration with StrictAffinity disabled
// and AutoAllocateBlocks enabled.
func (c IPAMClient) GetIPAMConfig() (*IPAMConfig, error) {
	opts := client.GetOptions{Quorum: true}
	resp, err := c.blockReaderWriter.etcd.Get(context.Background(), ipamConfigPath, &opts)
	if err != nil {
		if client.IsKeyNotFound(err) {
			cfg := IPAMConfig{
				StrictAffinity:     false,
				AutoAllocateBlocks: true,
			}
			return &cfg, nil
		} else {
			glog.Errorf("Error reading IPAM config:", err)
			return nil, err
		}
	}
	cfg := IPAMConfig{}
	json.Unmarshal([]byte(resp.Node.Value), &cfg)
	return &cfg, nil
}

// SetIPAMConfig sets global IPAM configuration.  This can only
// be done when there are no allocated blocks and IP addresses.
func (c IPAMClient) SetIPAMConfig(cfg IPAMConfig) error {
	current, err := c.GetIPAMConfig()
	if err != nil {
		return err
	}

	if *current == cfg {
		return nil
	}

	if cfg.StrictAffinity && !cfg.AutoAllocateBlocks {
		return errors.New("Cannot disable 'StrictAffinity' and 'AutoAllocateBlocks' at the same time")
	}

	v4Blocks, v6Blocks, err := c.blockReaderWriter.readAllBlocks()
	if len(v4Blocks) != 0 && len(v6Blocks) != 0 {
		return errors.New("Cannot change IPAM config while allocations exist")
	}

	// Write to etcd.
	j, err := json.Marshal(c)
	if err != nil {
		glog.Errorf("Error converting IPAM config to json:", err)
		return err
	}
	_, err = c.blockReaderWriter.etcd.Set(context.Background(), ipamConfigPath, string(j), nil)
	return nil
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
