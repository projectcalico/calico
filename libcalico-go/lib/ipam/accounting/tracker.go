// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// Package accounting holds the IPAM pool arithmetic every reader shares. It
// takes resources rather than reading them, and reads no datastore.
package accounting

import (
	"bytes"
	"encoding/binary"
	"maps"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"sync"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// Tracker keeps each pool's numbers current as changes arrive, so a read is a lookup. It is safe for concurrent use:
// reads share a lock and never modify state.
type Tracker struct {
	mu sync.RWMutex

	pools            map[string]*trackedPool
	blocks           map[string]*trackedBlock
	blocksWithNoPool *blockSet

	reservations map[string]*v3.IPReservation
	reserved     *reservedState

	// nodes stays nil until AddNodes is called, so a caller that never names nodes sees no stale affinity.
	nodes set.Set[string]

	// Most addresses have one reference, so a slice beats a set.
	refsByAddress map[netip.Addr][]addressRefKey
}

type trackedPool struct {
	ipPool *v3.IPPool
	net    *net.IPNet

	// Attribution compares these for every block, so they are read off the spec once per pool change.
	prefix      int
	blockSize   int
	lostOverlap bool

	blocks *blockSet
	counts *Counts
}

// trackedBlock is a block with its per-block counts, walked once per block change.
type trackedBlock struct {
	key             string
	allocationBlock *model.AllocationBlock
	base            netip.Addr

	// pool is nil when no pool claims the block, and node is empty when it has no host affinity.
	pool    *trackedPool
	node    string
	virtual bool

	inUse           int
	cooling         int
	borrowed        int
	inUseReserved   int
	reserved        int
	addressesByKind [numKinds]int
	assignedByNode  map[string]int
	borrowedByNode  map[string]int
}

type reservedState struct {
	cidrs []cnet.IPNet
	ips   *ReservedIPs
}

// blockSet is a set of blocks kept in address order as they come and go, so reading it in order writes nothing.
type blockSet struct {
	blocks map[string]*trackedBlock
	sorted []*trackedBlock
}

func newBlockSet() *blockSet {
	return &blockSet{blocks: make(map[string]*trackedBlock)}
}

func (s *blockSet) add(block *trackedBlock) {
	i, found := s.search(block)
	if found {
		s.sorted[i] = block
	} else {
		s.sorted = slices.Insert(s.sorted, i, block)
	}
	s.blocks[block.key] = block
}

func (s *blockSet) remove(block *trackedBlock) {
	if _, ok := s.blocks[block.key]; !ok {
		return
	}
	delete(s.blocks, block.key)
	if i, found := s.search(block); found {
		s.sorted = slices.Delete(s.sorted, i, i+1)
	}
}

func (s *blockSet) search(block *trackedBlock) (int, bool) {
	return slices.BinarySearchFunc(s.sorted, block, func(a, b *trackedBlock) int {
		return compareIPNets(&a.allocationBlock.CIDR.IPNet, &b.allocationBlock.CIDR.IPNet)
	})
}

// inOrder is the set in address order. Callers must not modify it.
func (s *blockSet) inOrder() []*trackedBlock {
	return s.sorted
}

func NewTracker() *Tracker {
	return &Tracker{
		pools:            make(map[string]*trackedPool),
		blocks:           make(map[string]*trackedBlock),
		blocksWithNoPool: newBlockSet(),
		reservations:     make(map[string]*v3.IPReservation),
		reserved:         &reservedState{},
		refsByAddress:    make(map[netip.Addr][]addressRefKey),
	}
}

// AddPools replaces any earlier copy of each pool. Only blocks the pool owned, or that sit inside its CIDR, are
// attributed again.
func (t *Tracker) AddPools(ipPools ...*v3.IPPool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, ipPool := range ipPools {
		_, poolNet, err := net.ParseCIDR(ipPool.Spec.CIDR)
		if err != nil {
			// A pool with no usable CIDR can own no blocks, so it is dropped rather than tracked.
			logrus.WithError(err).WithField("pool", ipPool.Name).Warn("Ignoring IPPool with unparseable CIDR")
			t.removePool(ipPool.Name)
			continue
		}

		// Record the new spec. A new pool needs its totals before any block can move into it.
		pool, existed := t.pools[ipPool.Name]
		if !existed {
			pool = &trackedPool{blocks: newBlockSet()}
			t.pools[ipPool.Name] = pool
		}
		ownBlocks := slices.Clone(pool.blocks.inOrder())
		pool.ipPool, pool.net = ipPool, poolNet
		pool.prefix, _ = poolNet.Mask.Size()
		pool.blockSize, pool.lostOverlap = BlockSize(ipPool), lostOverlap(ipPool)
		if !existed {
			t.recountPool(pool)
		}

		// Only the pool's own blocks, and blocks inside its CIDR, can change owner.
		for _, block := range append(ownBlocks, t.blocksWithin(poolNet, pool)...) {
			t.attributeToPool(block)
		}

		// The spec may change the pool's size or block size, so rebuild its totals from its blocks.
		t.recountPool(pool)
	}
}

func (t *Tracker) RemovePool(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.removePool(name)
}

func (t *Tracker) removePool(name string) {
	pool, ok := t.pools[name]
	if !ok {
		return
	}
	delete(t.pools, name)

	// Each block goes to the next best pool, or to none. attributeToPool removes it from pool.blocks, so walk a copy.
	for _, block := range slices.Clone(pool.blocks.inOrder()) {
		t.attributeToPool(block)
	}
}

// AddBlocks replaces any earlier copy of each block. The tracker keeps the pointer, so callers must not mutate it.
func (t *Tracker) AddBlocks(allocationBlocks ...*model.AllocationBlock) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, b := range allocationBlocks {
		// Take the old copy's counts back out before the new one replaces it.
		key := b.CIDR.String()
		if old, ok := t.blocks[key]; ok {
			t.unplace(old)
			delete(t.blocks, key)
		}
		if b.Deleted {
			continue
		}

		// Walk the block once for its counts, then add them to whichever pool owns it.
		block := newTrackedBlock(key, b, t.reserved.ips)
		block.pool = t.poolFor(&b.CIDR.IPNet)
		t.blocks[key] = block
		t.place(block)
	}
}

func (t *Tracker) RemoveBlock(cidr cnet.IPNet) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := cidr.String()
	if block, ok := t.blocks[key]; ok {
		t.unplace(block)
		delete(t.blocks, key)
	}
}

func (t *Tracker) AddReservations(reservations ...*v3.IPReservation) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, r := range reservations {
		t.reservations[r.Name] = r
	}
	t.applyReservedChange()
}

func (t *Tracker) RemoveReservation(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.reservations, name)
	t.applyReservedChange()
}

// AddNodes names nodes that still exist, which decides whether a block's affinity is stale.
func (t *Tracker) AddNodes(names ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nodes == nil {
		// No block could be stale before the first call, so count every pool's stale blocks from scratch.
		t.nodes = set.New[string]()
		t.nodes.AddAll(names)
		for _, pool := range t.pools {
			t.recountStale(pool)
		}
		return
	}
	for _, name := range names {
		if t.nodes.Contains(name) {
			continue
		}

		// The node's blocks stop being stale.
		t.nodes.Add(name)
		for _, pool := range t.pools {
			pool.counts.StaleAffinity -= pool.counts.BlocksByNode[name]
		}
	}
}

func (t *Tracker) RemoveNode(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nodes == nil || !t.nodes.Contains(name) {
		return
	}

	// The node's blocks become stale.
	t.nodes.Discard(name)
	for _, pool := range t.pools {
		pool.counts.StaleAffinity += pool.counts.BlocksByNode[name]
	}
}

// Summarize returns a copy of a pool's counts. False when no pool of that name was added.
func (t *Tracker) Summarize(name string) (*Counts, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	pool, ok := t.pools[name]
	if !ok {
		return nil, false
	}
	return pool.counts.clone(), true
}

// SummarizeNoPool adds up the blocks no pool claims. Total, Reserved and TotalBlocks are zero, since no pool CIDR
// bounds them.
func (t *Tracker) SummarizeNoPool() *Counts {
	t.mu.RLock()
	defer t.mu.RUnlock()
	counts := newCounts()
	for _, block := range t.blocksWithNoPool.blocks {
		t.addToCounts(counts, block)
	}
	return counts
}

// SummarizeAll returns a copy of every pool's counts.
func (t *Tracker) SummarizeAll() map[string]*Counts {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]*Counts, len(t.pools))
	for name, pool := range t.pools {
		out[name] = pool.counts.clone()
	}
	return out
}

// Allocations lists the pool's assigned addresses, cooling excluded, in address order.
func (t *Tracker) Allocations(name string) []Allocation {
	t.mu.RLock()
	defer t.mu.RUnlock()
	pool, ok := t.pools[name]
	if !ok {
		return nil
	}
	return assigned(pool.blocks.inOrder())
}

// PoolBlocks is every block the pool owns, in address order. Nil when no pool of that name was added.
func (t *Tracker) PoolBlocks(name string) []*model.AllocationBlock {
	t.mu.RLock()
	defer t.mu.RUnlock()
	pool, ok := t.pools[name]
	if !ok {
		return nil
	}
	return toAllocationBlocks(pool.blocks)
}

// PoolBlockCounts returns the counts of each block the pool claimed, in address order.
func (t *Tracker) PoolBlockCounts(name string) []*BlockCounts {
	t.mu.RLock()
	defer t.mu.RUnlock()
	pool, ok := t.pools[name]
	if !ok {
		return nil
	}
	var out []*BlockCounts
	for _, block := range pool.blocks.inOrder() {
		out = append(out, block.counts())
	}
	return out
}

// BlockCounts returns one block's counts, whether or not a pool claimed it. False when no block has that CIDR.
func (t *Tracker) BlockCounts(cidr cnet.IPNet) (*BlockCounts, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	block, ok := t.blocks[cidr.String()]
	if !ok {
		return nil, false
	}
	return block.counts(), true
}

// NoPoolBlockCounts is PoolBlockCounts for the blocks no pool claimed.
func (t *Tracker) NoPoolBlockCounts() []*BlockCounts {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []*BlockCounts
	for _, block := range t.blocksWithNoPool.inOrder() {
		out = append(out, block.counts())
	}
	return out
}

// NoPoolBlocks is every block no pool claimed, in address order.
func (t *Tracker) NoPoolBlocks() []*model.AllocationBlock {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return toAllocationBlocks(t.blocksWithNoPool)
}

// BlockPool names the pool that owns the block. False when the block is unknown or no pool claims it.
func (t *Tracker) BlockPool(cidr cnet.IPNet) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	block, ok := t.blocks[cidr.String()]
	if !ok || block.pool == nil {
		return "", false
	}
	return block.pool.ipPool.Name, true
}

func toAllocationBlocks(s *blockSet) []*model.AllocationBlock {
	var out []*model.AllocationBlock
	for _, block := range s.inOrder() {
		out = append(out, block.allocationBlock)
	}
	return out
}

// blocksWithin lists blocks inside n held by pools other than except, or by no pool. A changing pool can only win
// blocks it contains, so only these can move to it.
func (t *Tracker) blocksWithin(n *net.IPNet, except *trackedPool) []*trackedBlock {
	var out []*trackedBlock
	collect := func(s *blockSet) {
		for _, block := range s.blocks {
			if containsNet(n, &block.allocationBlock.CIDR.IPNet) {
				out = append(out, block)
			}
		}
	}
	collect(t.blocksWithNoPool)
	for _, other := range t.pools {
		if other != except && (n.Contains(other.net.IP) || other.net.Contains(n.IP)) {
			collect(other.blocks)
		}
	}
	return out
}

// attributeToPool moves block to the pool poolFor picks for it, when that differs from its current pool.
func (t *Tracker) attributeToPool(block *trackedBlock) {
	next := t.poolFor(&block.allocationBlock.CIDR.IPNet)
	if next == block.pool {
		return
	}
	t.unplace(block)
	block.pool = next
	t.place(block)
}

// place adds block to its pool, or to the blocks no pool claims.
func (t *Tracker) place(block *trackedBlock) {
	if block.pool == nil {
		t.blocksWithNoPool.add(block)
		return
	}
	block.pool.blocks.add(block)
	t.addToCounts(block.pool.counts, block)
}

func (t *Tracker) unplace(block *trackedBlock) {
	if block.pool == nil {
		t.blocksWithNoPool.remove(block)
		return
	}
	block.pool.blocks.remove(block)
	t.removeFromCounts(block.pool.counts, block)
}

// addToCounts adds block's contribution to counts. removeFromCounts is its exact inverse.
func (t *Tracker) addToCounts(counts *Counts, block *trackedBlock) {
	counts.BlocksInUse++
	switch {
	case block.allocationBlock.Affinity == nil:
		counts.NoAffinity++
	case block.virtual:
		counts.VirtualAffinity++
	case block.node != "":
		incrementBy(counts.BlocksByNode, block.node, 1)
		if t.isStale(block.node) {
			counts.StaleAffinity++
		}
	}
	counts.InUse += block.inUse
	counts.Cooling += block.cooling
	counts.Borrowed += block.borrowed
	counts.InUseReserved += block.inUseReserved
	for i, n := range block.addressesByKind {
		incrementBy(counts.AddressesByKind, trackedKinds[i], n)
	}
	for node, n := range block.assignedByNode {
		incrementBy(counts.AssignedByNode, node, n)
	}
	for node, n := range block.borrowedByNode {
		incrementBy(counts.BorrowedByNode, node, n)
	}
}

func (t *Tracker) removeFromCounts(counts *Counts, block *trackedBlock) {
	counts.BlocksInUse--
	switch {
	case block.allocationBlock.Affinity == nil:
		counts.NoAffinity--
	case block.virtual:
		counts.VirtualAffinity--
	case block.node != "":
		decrementBy(counts.BlocksByNode, block.node, 1)
		if t.isStale(block.node) {
			counts.StaleAffinity--
		}
	}
	counts.InUse -= block.inUse
	counts.Cooling -= block.cooling
	counts.Borrowed -= block.borrowed
	counts.InUseReserved -= block.inUseReserved
	for i, n := range block.addressesByKind {
		decrementBy(counts.AddressesByKind, trackedKinds[i], n)
	}
	for node, n := range block.assignedByNode {
		decrementBy(counts.AssignedByNode, node, n)
	}
	for node, n := range block.borrowedByNode {
		decrementBy(counts.BorrowedByNode, node, n)
	}
}

func (t *Tracker) isStale(node string) bool {
	return t.nodes != nil && !t.nodes.Contains(node)
}

// incrementBy adds n to m[k], leaving no entry for a zero count.
func incrementBy[K comparable](m map[K]int, k K, n int) {
	if n != 0 {
		m[k] += n
	}
}

// decrementBy takes n from m[k] and drops the entry when it reaches zero.
func decrementBy[K comparable](m map[K]int, k K, n int) {
	if n == 0 {
		return
	}
	if m[k] -= n; m[k] == 0 {
		delete(m, k)
	}
}

// recountPool rebuilds the pool's totals from its CIDR and its blocks.
func (t *Tracker) recountPool(pool *trackedPool) {
	ones, bits := pool.net.Mask.Size()
	pool.counts = newCounts()
	pool.counts.Total.Lsh(big.NewInt(1), uint(bits-ones))
	pool.counts.TotalBlocks.SetInt64(1)
	if bs := pool.blockSize; bs > ones {
		pool.counts.TotalBlocks.Lsh(big.NewInt(1), uint(bs-ones))
	}
	t.countPoolReserved(pool)
	for _, block := range pool.blocks.inOrder() {
		t.addToCounts(pool.counts, block)
	}
}

func (t *Tracker) countPoolReserved(pool *trackedPool) {
	r, err := countReserved(cnet.IPNet{IPNet: *pool.net}, t.reserved.cidrs)
	if err != nil {
		logrus.WithError(err).WithField("pool", pool.ipPool.Name).Warn("Cannot count the reserved addresses in an IPPool")
		pool.counts.Reserved = big.NewInt(0)
		return
	}
	pool.counts.Reserved = r
}

// recountStale counts the pool's blocks affine to a node not named, for the first AddNodes call.
func (t *Tracker) recountStale(pool *trackedPool) {
	pool.counts.StaleAffinity = 0
	for node, n := range pool.counts.BlocksByNode {
		if t.isStale(node) {
			pool.counts.StaleAffinity += n
		}
	}
}

// applyReservedChange rebuilds the reserved set and recounts only the blocks and pools whose addresses it changed.
func (t *Tracker) applyReservedChange() {
	next := t.buildReserved()
	changed, err := next.ips.changedSince(t.reserved.ips)
	t.reserved = next
	if err != nil {
		logrus.WithError(err).Warn("Cannot compare reserved address sets; recounting every block")
		for _, block := range t.blocks {
			t.recountReserved(block)
		}
		for _, pool := range t.pools {
			t.countPoolReserved(pool)
		}
		return
	}
	if len(changed.Prefixes()) == 0 {
		return
	}

	// A block inside a pool overlaps the change only if its pool does, so the pools narrow the search.
	diff := &ReservedIPs{set: changed}
	recountOverlapping := func(s *blockSet) {
		for _, block := range s.blocks {
			if diff.overlaps(block.allocationBlock.CIDR.IPNet) {
				t.recountReserved(block)
			}
		}
	}
	recountOverlapping(t.blocksWithNoPool)
	for _, pool := range t.pools {
		if diff.overlaps(*pool.net) {
			t.countPoolReserved(pool)
			recountOverlapping(pool.blocks)
		}
	}
}

func (t *Tracker) recountReserved(block *trackedBlock) {
	before := block.inUseReserved
	block.countReserved(t.reserved.ips)
	if block.pool != nil {
		block.pool.counts.InUseReserved += block.inUseReserved - before
	}
}

func (t *Tracker) buildReserved() *reservedState {
	cidrs := ReservationCIDRs(slices.Collect(maps.Values(t.reservations)))
	ips, err := newReservedIPs(cidrs)
	if err != nil {
		logrus.WithError(err).Warn("Cannot build the reserved address set")
	}
	return &reservedState{cidrs: cidrs, ips: ips}
}

// assigned lists the non-cooling allocations in the given blocks, in address order.
func assigned(blocks []*trackedBlock) []Allocation {
	n := 0
	for _, block := range blocks {
		n += block.inUse - block.cooling
	}
	out := make([]Allocation, 0, n)
	for _, block := range blocks {
		for a := range allocations(block.allocationBlock) {
			if !a.IsCooling() {
				a.IP = addrAt(block.base, a.Ordinal).AsSlice()
				out = append(out, a)
			}
		}
	}
	return out
}

func compareIPNets(a, b *net.IPNet) int {
	if c := bytes.Compare(a.IP.To16(), b.IP.To16()); c != 0 {
		return c
	}
	return bytes.Compare(a.Mask, b.Mask)
}

// containsNet is whether outer holds all of inner.
func containsNet(outer, inner *net.IPNet) bool {
	outerOnes, outerBits := outer.Mask.Size()
	innerOnes, innerBits := inner.Mask.Size()
	return outerBits == innerBits && outerOnes <= innerOnes && outer.Contains(inner.IP)
}

// newTrackedBlock walks the block once, counting its reserved overlap against reserved.
func newTrackedBlock(key string, b *model.AllocationBlock, reserved *ReservedIPs) *trackedBlock {
	block := &trackedBlock{
		key:             key,
		allocationBlock: b,
		base:            blockBase(b),
		assignedByNode:  make(map[string]int),
		borrowedByNode:  make(map[string]int),
	}
	block.node, _ = NodeAffinity(b)
	block.virtual = b.Affinity != nil && b.AffinityType() == model.IPAMAffinityTypeVirtual
	checkReserved := reserved.overlaps(b.CIDR.IPNet)
	if checkReserved {
		block.reserved = countReservedIn(b, reserved)
	}
	unknownTypes := set.New[string]()
	valid := 0
	for a := range allocations(b) {
		valid++
		block.inUse++
		if checkReserved && reserved.containsAddr(addrAt(block.base, a.Ordinal)) {
			block.inUseReserved++
		}
		if a.IsCooling() {
			block.cooling++
			continue
		}
		block.assignedByNode[a.Node()]++
		kind := a.Kind()
		if kind == KindUnknown {
			unknownTypes.Add(a.Attr.ActiveOwnerAttrs[model.IPAMBlockAttributeType])
		}
		block.addressesByKind[kindIndex(kind)]++
		if a.IsBorrowed() {
			block.borrowed++
			block.borrowedByNode[a.Node()]++
		}
	}
	if malformed := countAllocated(b) - valid; malformed > 0 {
		logrus.WithFields(logrus.Fields{
			"block":     b.CIDR.String(),
			"malformed": malformed,
		}).Warn("IPAMBlock has allocations with no valid attribute or ordinal; not counting them")
	}
	if unknownTypes.Len() > 0 {
		logrus.WithFields(logrus.Fields{
			"block": b.CIDR.String(),
			"types": slices.Sorted(unknownTypes.All()),
		}).Warn("IPAMBlock has allocation types this code does not classify; reporting them as Unknown")
	}
	return block
}

func (b *trackedBlock) countReserved(reserved *ReservedIPs) {
	b.inUseReserved = 0
	b.reserved = 0
	if !reserved.overlaps(b.allocationBlock.CIDR.IPNet) {
		return
	}
	b.reserved = countReservedIn(b.allocationBlock, reserved)
	for a := range allocations(b.allocationBlock) {
		if reserved.containsAddr(addrAt(b.base, a.Ordinal)) {
			b.inUseReserved++
		}
	}
}

func (b *trackedBlock) counts() *BlockCounts {
	return &BlockCounts{
		Block:         b.allocationBlock,
		Total:         b.allocationBlock.NumAddresses(),
		InUse:         b.inUse,
		Cooling:       b.cooling,
		Reserved:      b.reserved,
		InUseReserved: b.inUseReserved,
	}
}

func countReservedIn(b *model.AllocationBlock, reserved *ReservedIPs) int {
	n, err := reserved.countIn(b.CIDR.IPNet)
	if err != nil {
		logrus.WithError(err).WithField("block", b.CIDR.String()).Warn("Cannot count the reserved addresses in an IPAM block")
		return 0
	}
	return ClampToInt(n)
}

// blockBase is the block's first address, IPv4 unmapped so it matches the keys refsByAddress uses.
func blockBase(b *model.AllocationBlock) netip.Addr {
	addr, _ := netip.AddrFromSlice(b.CIDR.IP)
	return addr.Unmap()
}

// addrAt is the address ord places past base. Blocks are far smaller than 2^64 addresses, so only the low half moves.
func addrAt(base netip.Addr, ord int) netip.Addr {
	b := base.As16()
	lo := binary.BigEndian.Uint64(b[8:])
	sum := lo + uint64(ord)
	binary.BigEndian.PutUint64(b[8:], sum)
	if sum < lo {
		binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(b[:8])+1)
	}
	addr := netip.AddrFrom16(b)
	if base.Is4() {
		return addr.Unmap()
	}
	return addr
}
