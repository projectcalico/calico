package node

import (
	"net"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Maintains a mapping of blocks to pools, based on whether the block CIDR occupies the pool CIDR.
// Blocks can have a known pool association (handled, occupies a pool), unknown pool association (handled,
// does not occupy a pool), or nil association (not yet handled).
type poolManager struct {
	blocksByPool map[string]map[string]bool
	poolsByBlock map[string]string
	allPools     map[string]*v3.IPPool
}

func newPoolManager() *poolManager {
	return &poolManager{
		blocksByPool: make(map[string]map[string]bool),
		poolsByBlock: make(map[string]string),
		allPools:     make(map[string]*v3.IPPool),
	}
}

const (
	// "no_ippool" is a special pool label that represents when a block has no matching IP pool.
	unknownPoolLabel = "no_ippool"
)

func (p *poolManager) onPoolUpdated(pool *v3.IPPool) {
	// Blocks may not have a known association to an IP Pool. This can happen when a Pool gets deleted, or if block
	// updates appear before their associated pool updates. Blocks lacking association to an IP Pool are grouped under
	// "no_ippool", and we check for transitions from unknown to known pool association on pool creation.
	if p.allPools[pool.Name] == nil {
		_, poolNet, err := cnet.ParseCIDR(pool.Spec.CIDR)
		if err != nil {
			log.WithError(err).Warnf("Unable to parse CIDR for IP Pool %s", pool.Name)
			return
		}

		for block := range p.blocksByPool[unknownPoolLabel] {
			_, blockNet, err := net.ParseCIDR(block)
			if err != nil {
				log.WithError(err).Warnf("Unable to parse block %s to determine if it matches pool %s", block, pool.Name)
				continue
			}

			if blockOccupiesPool(blockNet, poolNet) {
				p.updatePoolForBlock(block, pool.Name)
			}
		}
	}

	p.allPools[pool.Name] = pool
}

func (p *poolManager) onPoolDeleted(poolName string) {
	// When an IP Pool is deleted, its association transitions from known to unknown.
	for block := range p.blocksByPool[poolName] {
		p.updatePoolForBlock(block, unknownPoolLabel)
	}

	delete(p.blocksByPool, poolName)
	delete(p.allPools, poolName)
}

func (p *poolManager) onBlockUpdated(blockCIDR string) {
	// We only update pool association if current association is nil, since block update can only trigger transitions of
	// association from nil to known pool or nil to unknown pool. Transitions from known to nil or unknown to nil
	// occur due to block delete, transitions from known to unknown occur due to pool delete, and transitions from
	// unknown to known occur due to pool update.
	if p.poolsByBlock[blockCIDR] == "" {
		pool := p.getPoolForBlock(blockCIDR)
		p.updatePoolForBlock(blockCIDR, pool)
	}
}

func (p *poolManager) onBlockDeleted(blockCIDR string) {
	// Transition from known or unknown pool association to nil.
	pool := p.poolsByBlock[blockCIDR]
	delete(p.blocksByPool[pool], blockCIDR)
	delete(p.poolsByBlock, blockCIDR)
}

// Resolve the IP Pool that the Block occupies.
func (p *poolManager) getPoolForBlock(blockCIDR string) string {
	_, blockNet, err := net.ParseCIDR(blockCIDR)
	if err != nil {
		log.WithError(err).Warnf("Unable to parse block %s for pool determination", blockCIDR)
		return unknownPoolLabel
	}

	for poolName, pool := range p.allPools {
		_, poolNet, err := cnet.ParseCIDR(pool.Spec.CIDR)
		if err != nil {
			log.WithError(err).Warnf("Failed to parse CIDR for IP Pool %s", poolName)
			continue
		}
		if blockOccupiesPool(blockNet, poolNet) {
			return poolName
		}
	}

	return unknownPoolLabel
}

func (p *poolManager) updatePoolForBlock(blockCIDR string, newPool string) {
	previousPool := p.poolsByBlock[blockCIDR]
	if previousPool == newPool {
		return
	}

	// Update pools by block
	p.poolsByBlock[blockCIDR] = newPool

	// Update blocks by pool
	if previousPoolBlocks, ok := p.blocksByPool[previousPool]; ok {
		delete(previousPoolBlocks, blockCIDR)
	}
	if p.blocksByPool[newPool] == nil {
		p.blocksByPool[newPool] = map[string]bool{}
	}
	p.blocksByPool[newPool][blockCIDR] = true
}

func blockOccupiesPool(blockNet *net.IPNet, poolNet *cnet.IPNet) bool {
	return poolNet.Covers(*blockNet)
}
