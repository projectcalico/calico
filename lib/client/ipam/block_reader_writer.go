package ipam

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/coreos/etcd/client"
	"github.com/golang/glog"
	"golang.org/x/net/context"
)

type blockReaderWriter struct {
	etcd client.KeysAPI
}

func (rw blockReaderWriter) getAffineBlocks(host string, ver ipVersion, pool *net.IPNet) ([]net.IPNet, error) {
	key := fmt.Sprintf(ipamHostAffinityPath, host, ver.Number)
	opts := client.GetOptions{Quorum: true, Recursive: true}
	res, err := rw.etcd.Get(context.Background(), key, &opts)
	if err != nil {
		if client.IsKeyNotFound(err) {
			// The block path does not exist yet.  This is OK - it means
			// there are no affine blocks.
			return []net.IPNet{}, nil
		} else {
			glog.Errorf("Error reading blocks from etcd: %s", err)
			return nil, err
		}
	}

	ids := []net.IPNet{}
	if res.Node != nil {
		for _, n := range res.Node.Nodes {
			if !n.Dir {
				// Extract the block identifier (subnet) which is encoded
				// into the etcd key.  We need to replace "-" with "/" to
				// turn it back into a cidr.
				ss := strings.Split(n.Key, "/")
				_, id, _ := net.ParseCIDR(strings.Replace(ss[len(ss)-1], "-", "/", 1))
				ids = append(ids, *id)
			}
		}
	}
	return ids, nil
}

func (rw blockReaderWriter) claimNewAffineBlock(
	host string, version ipVersion, pool *net.IPNet, config IPAMConfig) (*net.IPNet, error) {

	// If pool is not nil, use the given pool.  Otherwise, default to
	// all configured pools.
	var pools []net.IPNet
	if pool != nil {
		// Validate the given pool is actually configured.
		// TODO: Exact match pools check.
		if !rw.withinConfiguredPools(pool.IP) {
			estr := fmt.Sprintf("The given pool (%s) does not exist", pool.String())
			return nil, errors.New(estr)
		}
		pools = []net.IPNet{*pool}
	} else {
		// Default to all configured pools.
		// TODO: Re-implement this.
		//allPools := libcalico.GetPools(rw.etcd, fmt.Sprintf("%d", version.Number))
		//for _, p := range allPools {
		//	_, c, _ := net.ParseCIDR(p.Cidr)
		//	pools = append(pools, *c)
		//}
	}

	// If there are no pools, we cannot assign addresses.
	if len(pools) == 0 {
		return nil, errors.New("No configured Calico pools")
	}

	// Iterate through pools to find a new block.
	glog.V(2).Infof("Claiming a new affine block for host '%s'", host)
	for _, pool := range pools {
		for _, subnet := range blocks(pool) {
			// Check if a block already exists for this subnet.
			key := blockDatastorePath(subnet)
			_, err := rw.etcd.Get(context.Background(), key, nil)
			if client.IsKeyNotFound(err) {
				// The block does not yet exist in etcd.  Try to grab it.
				glog.V(3).Infof("Found free block: %+v", subnet)
				err = rw.claimBlockAffinity(subnet, host, config)
				return &subnet, err
			} else if err != nil {
				glog.Errorf("Error checking block:", err)
				return nil, err
			}
		}
	}
	return nil, noFreeBlocksError("No Free Blocks")
}

func (rw blockReaderWriter) claimBlockAffinity(subnet net.IPNet, host string, config IPAMConfig) error {
	// Claim the block in etcd.
	glog.V(2).Infof("Host %s claiming block affinity for %s", host, subnet)
	affinityPath := blockHostAffinityPath(subnet, host)
	rw.etcd.Set(context.Background(), affinityPath, "", nil)

	// Create the new block.
	block := newBlock(subnet)
	block.HostAffinity = &host
	block.StrictAffinity = config.StrictAffinity

	// Compare and swap the new block.
	err := rw.compareAndSwapBlock(block)
	if err != nil {
		if _, ok := err.(CASError); ok {
			// Block already exists, check affinity.
			glog.Warningf("Problem claiming block affinity:", err)
			b, err := rw.readBlock(subnet)
			if err != nil {
				glog.Errorf("Error reading block:", err)
				return err
			}
			if b.HostAffinity != nil && *b.HostAffinity == host {
				// Block has affinity to this host, meaning another
				// process on this host claimed it.
				glog.V(3).Infof("Block %s already claimed by us.  Success", subnet)
				return nil
			}

			// Some other host beat us to this block.  Cleanup and return error.
			rw.etcd.Delete(context.Background(), affinityPath, &client.DeleteOptions{})
			return &AffinityClaimedError{Block: *b}
		} else {
			return err
		}
	}
	return nil
}

func (rw blockReaderWriter) releaseBlockAffinity(host string, blockCidr net.IPNet) error {
	for i := 0; i < etcdRetries; i++ {
		// Read the block from etcd.
		b, err := rw.readBlock(blockCidr)
		if err != nil {
			return err
		}

		// Check that the block affinity matches the given affinity.
		if b.HostAffinity != nil && *b.HostAffinity != host {
			return AffinityClaimedError{Block: *b}
		}

		if b.empty() {
			// If the block is empty, we can delete it.
			err := rw.deleteBlock(*b)
			if err != nil {
				if eerr, ok := err.(client.Error); ok && eerr.Code == client.ErrorCodeNodeExist {
					// Block already deleted.  Carry on.

				} else {
					glog.Errorf("Error deleting block: %s", err)
					return err
				}
			}
		} else {
			// Otherwise, we need to remove affinity from it.
			// This prevents the host from automatically assigning
			// from this block unless we're allowed to overflow into
			// non-affine blocks.
			b.HostAffinity = nil
			err = rw.compareAndSwapBlock(*b)
			if err != nil {
				if _, ok := err.(CASError); ok {
					// CASError - continue.
					continue
				} else {
					return err
				}
			}
		}

		// We've removed / updated the block, so update the host config
		// to remove the CIDR.
		key := blockHostAffinityPath(b.Cidr, host)
		_, err = rw.etcd.Delete(context.Background(), key, nil)
		if err != nil {
			if eerr, ok := err.(client.Error); ok && eerr.Code == client.ErrorCodeNodeExist {
				// Already deleted.  Carry on.

			} else {
				return err
			}
		}
		return nil

	}
	return errors.New("Max retries hit")
}

func (rw blockReaderWriter) compareAndSwapBlock(b allocationBlock) error {
	// If the block has a store result, compare and swap agianst that.
	var opts client.SetOptions
	key := blockDatastorePath(b.Cidr)

	// Determine correct Set options.
	if b.DbResult != "" {
		glog.V(3).Infof("CAS update block: %s", b.Cidr.String())
		opts = client.SetOptions{PrevExist: client.PrevExist, PrevValue: b.DbResult}
	} else {
		glog.V(3).Infof("CAS write new block: %s", b.Cidr.String())
		opts = client.SetOptions{PrevExist: client.PrevNoExist}
	}

	j, err := json.Marshal(b)
	if err != nil {
		glog.Errorf("Error converting block to json:", err)
		return err
	}
	_, err = rw.etcd.Set(context.Background(), key, string(j), &opts)
	if err != nil {
		if eerr, ok := err.(client.Error); ok && eerr.Code == client.ErrorCodeNodeExist {
			glog.Errorf("CAS error writing block:", err)
			return CASError(fmt.Sprintf("Failed to write block %s", b.Cidr))
		} else {
			return err
		}
	}

	return nil
}

func (rw blockReaderWriter) deleteBlock(b allocationBlock) error {
	opts := client.DeleteOptions{PrevValue: b.DbResult}
	key := blockDatastorePath(b.Cidr)
	_, err := rw.etcd.Delete(context.Background(), key, &opts)
	return err
}

func (rw blockReaderWriter) readBlock(blockCidr net.IPNet) (*allocationBlock, error) {
	key := blockDatastorePath(blockCidr)
	opts := client.GetOptions{Quorum: true}
	resp, err := rw.etcd.Get(context.Background(), key, &opts)
	if err != nil {
		if client.IsKeyNotFound(err) {
			return nil, noSuchBlockError{Cidr: blockCidr}
		}
		return nil, err
	}
	b := newBlock(blockCidr)
	json.Unmarshal([]byte(resp.Node.Value), &b)
	b.DbResult = resp.Node.Value
	return &b, nil
}

func (rw blockReaderWriter) readAllBlocks() ([]allocationBlock, []allocationBlock, error) {
	blocks := map[int][]allocationBlock{
		ipv4.Number: []allocationBlock{},
		ipv6.Number: []allocationBlock{},
	}

	opts := client.GetOptions{Quorum: true}
	for _, version := range []ipVersion{ipv4, ipv6} {
		key := fmt.Sprintf(ipamBlockPath, version.Number)
		resp, err := rw.etcd.Get(context.Background(), key, &opts)
		if err != nil {
			glog.Errorf("Error reading IPAM blocks:", err)
			return nil, nil, err
		}

		for _, node := range resp.Node.Nodes {
			if node.Value != "" {
				b := allocationBlock{}
				json.Unmarshal([]byte(resp.Node.Value), &b)
				b.DbResult = node.Value
				blocks[version.Number] = append(blocks[version.Number], b)
			}
		}
	}
	return blocks[ipv4.Number], blocks[ipv6.Number], nil
}

func (rw blockReaderWriter) withinConfiguredPools(ip net.IP) bool {
	// TODO: Re-implement this.
	// ver := getIPVersion(ip)
	// allPools := libcalico.GetPools(rw.etcd, fmt.Sprintf("%d", ver.Number))
	// for _, p := range allPools {
	// 	_, c, _ := net.ParseCIDR(p.Cidr)
	// 	if c.Contains(ip) {
	// 		return true
	// 	}
	// }
	// return false
	return true
}

func blockDatastorePath(blockCidr net.IPNet) string {
	version := getIPVersion(blockCidr.IP)
	path := fmt.Sprintf(ipamBlockPath, version.Number)
	return path + strings.Replace(blockCidr.String(), "/", "-", 1)
}

func blockHostAffinityPath(blockCidr net.IPNet, host string) string {
	version := getIPVersion(blockCidr.IP)
	path := fmt.Sprintf(ipamHostAffinityPath, host, version.Number)
	return path + strings.Replace(blockCidr.String(), "/", "-", 1)
}

// Return the list of block CIDRs which fall within
// the given pool.
func blocks(pool net.IPNet) []net.IPNet {
	// Determine the IP type to use.
	ipVersion := getIPVersion(pool.IP)
	nets := []net.IPNet{}
	ip := pool.IP
	for pool.Contains(ip) {
		nets = append(nets, net.IPNet{ip, ipVersion.BlockPrefixMask})
		ip = incrementIP(ip, blockSize)
	}
	return nets
}
