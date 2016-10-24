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
	goerrors "errors"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"reflect"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

type blockReaderWriter struct {
	client *Client
}

func (rw blockReaderWriter) getAffineBlocks(host string, ver ipVersion, pool *cnet.IPNet) ([]cnet.IPNet, error) {
	// Lookup all blocks by providing an empty BlockListOptions
	// to the List operation.
	opts := model.BlockAffinityListOptions{Host: host, IPVersion: ver.Number}
	datastoreObjs, err := rw.client.backend.List(opts)
	if err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
			// The block path does not exist yet.  This is OK - it means
			// there are no affine blocks.
			return []cnet.IPNet{}, nil

		} else {
			log.Errorf("Error getting affine blocks: %s", err)
			return nil, err
		}
	}

	// Iterate through and extract the block CIDRs.
	ids := []cnet.IPNet{}
	for _, o := range datastoreObjs {
		k := o.Key.(model.BlockAffinityKey)
		ids = append(ids, k.CIDR)
	}
	return ids, nil
}

func (rw blockReaderWriter) claimNewAffineBlock(
	host string, version ipVersion, pool *cnet.IPNet, config IPAMConfig) (*cnet.IPNet, error) {

	// If pool is not nil, use the given pool.  Otherwise, default to
	// all configured pools.
	var pools []cnet.IPNet
	if pool != nil {
		// Validate the given pool is actually configured and matches the version.
		if !rw.isConfiguredPool(*pool) {
			estr := fmt.Sprintf("The given pool (%s) does not exist", pool.String())
			return nil, goerrors.New(estr)
		} else if version.Number != pool.Version() {
			estr := fmt.Sprintf("The given pool (%s) does not match IP version %d", pool.String(), version.Number)
			return nil, goerrors.New(estr)
		}
		pools = []cnet.IPNet{*pool}
	} else {
		// Default to all configured pools.
		allPools, err := rw.client.Pools().List(api.PoolMetadata{})
		if err != nil {
			log.Errorf("Error reading configured pools: %s", err)
			return nil, err
		}

		// Grab all the IP networks in these pools.
		for _, p := range allPools.Items {
			// Don't include disabled pools or pools that don't match
			// the requested IP version.
			if !p.Spec.Disabled && version.Number == p.Metadata.CIDR.Version() {
				pools = append(pools, p.Metadata.CIDR)
			}
		}
	}

	// If there are no pools, we cannot assign addresses.
	if len(pools) == 0 {
		return nil, goerrors.New("No configured Calico pools")
	}

	// Iterate through pools to find a new block.
	log.Infof("Claiming a new affine block for host '%s'", host)
	for _, pool := range pools {
		// Use a block generator to iterate through all of the blocks
		// that fall within the pool.
		blocks := randomBlockGenerator(pool)
		for subnet := blocks(); subnet != nil; subnet = blocks() {
			// Check if a block already exists for this subnet.
			log.Debugf("Getting block: %s", subnet.String())
			key := model.BlockKey{CIDR: *subnet}
			_, err := rw.client.backend.Get(key)
			if err != nil {
				if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
					// The block does not yet exist in etcd.  Try to grab it.
					log.Debugf("Found free block: %+v", *subnet)
					err = rw.claimBlockAffinity(*subnet, host, config)
					return subnet, err
				} else {
					log.Errorf("Error getting block: %s", err)
					return nil, err
				}
			}
		}
	}
	return nil, noFreeBlocksError("No Free Blocks")
}

func (rw blockReaderWriter) claimBlockAffinity(subnet cnet.IPNet, host string, config IPAMConfig) error {
	// Claim the block affinity for this host.
	log.Infof("Host %s claiming block affinity for %s", host, subnet)
	obj := model.KVPair{
		Key:   model.BlockAffinityKey{Host: host, CIDR: subnet},
		Value: &model.BlockAffinity{},
	}
	_, err := rw.client.backend.Create(&obj)

	// Create the new block.
	block := newBlock(subnet)
	block.HostAffinity = &host
	block.StrictAffinity = config.StrictAffinity

	// Create the new block in the datastore.
	o := model.KVPair{
		Key:   model.BlockKey{block.CIDR},
		Value: &block.AllocationBlock,
	}
	_, err = rw.client.backend.Create(&o)
	if err != nil {
		if _, ok := err.(errors.ErrorResourceAlreadyExists); ok {
			// Block already exists, check affinity.
			log.Warningf("Problem claiming block affinity:", err)
			obj, err := rw.client.backend.Get(model.BlockKey{subnet})
			if err != nil {
				log.Errorf("Error reading block:", err)
				return err
			}

			// Pull out the allocationBlock object.
			b := allocationBlock{obj.Value.(*model.AllocationBlock)}

			if b.HostAffinity != nil && *b.HostAffinity == host {
				// Block has affinity to this host, meaning another
				// process on this host claimed it.
				log.Debugf("Block %s already claimed by us.  Success", subnet)
				return nil
			}

			// Some other host beat us to this block.  Cleanup and return error.
			err = rw.client.backend.Delete(&model.KVPair{
				Key: model.BlockAffinityKey{Host: host, CIDR: b.CIDR},
			})
			if err != nil {
				log.Errorf("Error cleaning up block affinity: %s", err)
				return err
			}
			return affinityClaimedError{Block: b}
		} else {
			return err
		}
	}
	return nil
}

func (rw blockReaderWriter) releaseBlockAffinity(host string, blockCIDR cnet.IPNet) error {
	for i := 0; i < ipamEtcdRetries; i++ {
		// Read the model.KVPair containing the block
		// and pull out the allocationBlock object.  We need to hold on to this
		// so that we can pass it back to the datastore on Update.
		obj, err := rw.client.backend.Get(model.BlockKey{CIDR: blockCIDR})
		if err != nil {
			log.Errorf("Error getting block %s: %s", blockCIDR.String(), err)
			return err
		}
		b := allocationBlock{obj.Value.(*model.AllocationBlock)}

		// Check that the block affinity matches the given affinity.
		if b.HostAffinity != nil && *b.HostAffinity != host {
			log.Errorf("Mismatched affinity: %s != %s", *b.HostAffinity, host)
			return affinityClaimedError{Block: b}
		}

		if b.empty() {
			// If the block is empty, we can delete it.
			err := rw.client.backend.Delete(&model.KVPair{
				Key: model.BlockKey{CIDR: b.CIDR},
			})
			if err != nil {
				// Return the error unless the block didn't exist.
				if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
					log.Errorf("Error deleting block: %s", err)
					return err
				}
			}
		} else {
			// Otherwise, we need to remove affinity from it.
			// This prevents the host from automatically assigning
			// from this block unless we're allowed to overflow into
			// non-affine blocks.
			b.HostAffinity = nil

			// Pass back the original KVPair with the new
			// block information so we can do a CAS.
			obj.Value = &b
			_, err = rw.client.backend.Update(obj)
			if err != nil {
				if _, ok := err.(errors.ErrorResourceUpdateConflict); ok {
					// CASError - continue.
					continue
				} else {
					return err
				}
			}
		}

		// We've removed / updated the block, so update the host config
		// to remove the CIDR.
		err = rw.client.backend.Delete(&model.KVPair{
			Key: model.BlockAffinityKey{Host: host, CIDR: b.CIDR},
		})
		if err != nil {
			// Return the error unless the affinity didn't exist.
			if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
				log.Errorf("Error deleting block affinity: %s", err)
				return err
			}
		}
		return nil

	}
	return goerrors.New("Max retries hit")
}

// withinConfiguredPools returns true if the given IP is within a configured
// Calico pool, and false otherwise.
func (rw blockReaderWriter) withinConfiguredPools(ip cnet.IP) bool {
	allPools, _ := rw.client.Pools().List(api.PoolMetadata{})
	for _, p := range allPools.Items {
		// Compare any enabled pools.
		if !p.Spec.Disabled && p.Metadata.CIDR.Contains(ip.IP) {
			return true
		}
	}
	return false
}

// isConfiguredPool returns true if the given IPNet is a configured
// Calico pool, and false otherwise.
func (rw blockReaderWriter) isConfiguredPool(cidr cnet.IPNet) bool {
	allPools, _ := rw.client.Pools().List(api.PoolMetadata{})
	for _, p := range allPools.Items {
		// Compare any enabled pools.
		if !p.Spec.Disabled && reflect.DeepEqual(p.Metadata.CIDR, cidr) {
			return true
		}
	}
	return false
}

// Generator to get list of block CIDRs which
// fall within the given pool. Returns nil when no more
// blocks can be generated.
func blockGenerator(pool cnet.IPNet) func() *cnet.IPNet {
	// Determine the IP type to use.
	version := getIPVersion(cnet.IP{pool.IP})
	ip := cnet.IP{pool.IP}
	return func() *cnet.IPNet {
		returnIP := ip
		ip = incrementIP(ip, big.NewInt(blockSize))
		if pool.Contains(ip.IP) {
			ipnet := net.IPNet{returnIP.IP, version.BlockPrefixMask}
			cidr := cnet.IPNet{ipnet}
			return &cidr
		} else {
			return nil
		}
	}
}

// Returns a generator that, when called, returns a random
// block from the given pool.  When there are no blocks left,
// the it returns nil.
func randomBlockGenerator(pool cnet.IPNet) func() *cnet.IPNet {

	// Determine the IP type to use.
	version := getIPVersion(cnet.IP{pool.IP})
	baseIP := cnet.IP{pool.IP}

	// Determine the number of blocks within this pool.
	ones, size := pool.Mask.Size()
	prefixLen := size - ones
	numIP := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(prefixLen)), nil)
	numBlocks := new(big.Int)
	numBlocks.Div(numIP, big.NewInt(blockSize))

	// Start at a random offset index
	source := rand.NewSource(time.Now().UnixNano())
	randm := rand.New(source)

	// initialIndex keeps track of the random starting point
	initialIndex := new(big.Int)
	initialIndex.Rand(randm, numBlocks)

	// i keeps track of current index while walking the blocks in a pool
	i := initialIndex

	// numReturned keeps track of number of blocks returned
	numReturned := big.NewInt(0)

	// numDiff = numBlocks - i
	numDiff := new(big.Int)

	return func() *cnet.IPNet {
		// The `big.NewInt(0)` part creates a temp variable and assigns the result of multiplication of `i` and `big.NewInt(blockSize)`
		// Note: we are not using `i.Mul()` because that will assign the result of the multiplication to `i`, which will cause unexpected issues
		ip := incrementIP(baseIP, big.NewInt(0).Mul(i, big.NewInt(blockSize)))
		ipnet := net.IPNet{ip.IP, version.BlockPrefixMask}

		numDiff.Sub(numBlocks, i)

		if numDiff.Cmp(big.NewInt(1)) <= 0 {
			// Index has reached end of the blocks;
			// Loop back to beginning of pool rather than
			// increment, because incrementing would put us outside of the pool.
			i = big.NewInt(0)
		} else {
			// Increment to the next block
			i.Add(i, big.NewInt(1))
		}

		if numReturned.Cmp(numBlocks) >= 0 {
			// Index finished one full circle across the blocks
			// Used all of the blocks in this pool.
			return nil
		}
		numReturned.Add(numReturned, big.NewInt(1))

		// Return the block from this pool that corresponds with the index.
		return &cnet.IPNet{ipnet}
	}
}
