// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.

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
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// windowsReservedHandle is the handle used to reserve addresses required for Windows
// networking so that workloads do not get assigned these addresses.
const WindowsReservedHandle = "windows-reserved-ipam-handle"

// Wrap the backend AllocationBlock struct so that we can
// attach methods to it.
type allocationBlock struct {
	*model.AllocationBlock
}

// blockFromBackend creates a new allocationBlock from a backend type, performing
// garbage collection before teturning,
func blockFromBackend(config *IPAMConfig, b *model.AllocationBlock) allocationBlock {
	block := allocationBlock{b}
	block.garbageCollect(config.MinIPReclaimAgeSeconds)
	return block
}

// newBlock creates a new, empty block with the given host reservations in place.
func newBlock(cidr cnet.IPNet, rsvdAttr *HostReservedAttr) allocationBlock {
	ones, size := cidr.Mask.Size()
	numAddresses := 1 << uint(size-ones)
	b := model.AllocationBlock{}
	b.Allocations = make([]*int, numAddresses)
	b.Unallocated = make([]int, numAddresses)
	b.CIDR = cidr
	b.SequenceNumberForAllocation = make(map[string]uint64, 0)

	// When creating a new block, initialize its sequence number based on the timestamp.
	// If a block is deleted / recreated, allocations will get different sequence numbers.
	// This protects against a scenario where IP A is given seq# 0, the block is deleted and recreated,
	// and then the same IP is given seq# 0 again, fooling clients into thinking the address hasn't changed.
	b.SequenceNumber = uint64(time.Now().UnixNano())

	// Initialize unallocated ordinals.
	for i := range numAddresses {
		b.Unallocated[i] = i
	}

	if rsvdAttr != nil {
		// Reserve IPs based on host reserved attributes.
		// For example, with windows OS, the following IP addresses of the block are
		// reserved. This is done by pre-allocating them during initialization
		// time only.
		// IPs : x.0, x.1, x.2 and x.bcastAddr (e.g. x.255 for /24 subnet)

		log.WithField("block", b.CIDR.String()).Info("Block reserving IPs")
		// nil attributes
		attrs := make(map[string]string)
		attrs["note"] = rsvdAttr.Note
		handleID := rsvdAttr.Handle
		b.Unallocated = b.Unallocated[rsvdAttr.StartOfBlock : numAddresses-rsvdAttr.EndOfBlock]
		attrIndex := len(b.Attributes)
		for i := 0; i < rsvdAttr.StartOfBlock; i++ {
			b.Allocations[i] = &attrIndex
		}
		for i := 1; i <= rsvdAttr.EndOfBlock; i++ {
			b.Allocations[numAddresses-i] = &attrIndex
		}

		// Create slice of IPs and perform the allocations.
		log.Debugf("Reserving allocation attribute: %#v handle %s", attrs, handleID)
		attr := model.AllocationAttribute{HandleID: &handleID, ActiveOwnerAttrs: attrs}
		b.Attributes = append(b.Attributes, attr)
	}

	return allocationBlock{&b}
}

func (b *allocationBlock) autoAssign(num int, handleID *string, affinityCfg AffinityConfig, attrs map[string]string, affinityCheck bool, reservations addrFilter) ([]cnet.IPNet, error) {
	// Determine if we need to check for affinity.
	if affinityCheck && b.Affinity != nil && !affinityMatches(affinityCfg, b.AllocationBlock) {
		// Affinity check is enabled but the host does not match - error.
		s := fmt.Sprintf("Block affinity (%s) does not match provided (%s:%s)", *b.Affinity, affinityCfg.Host, affinityCfg.AffinityType)
		return nil, errors.New(s)
	} else if b.Affinity == nil {
		log.Warnf("Attempting to assign IPs from block with no affinity: %v", b)
		if affinityCheck {
			// If we're checking strict affinity, we can't assign from a block with no affinity.
			return nil, fmt.Errorf("Attempt to assign from block %v with no affinity", b.CIDR)
		}
	}

	// Search the "unallocated" list for IPs that we can use. We want to preserve the order of the ordinals list
	// so we copy unused ordinals to the updatedUnallocated slice as we go.
	_, mask, _ := cnet.ParseCIDR(b.CIDR.String())
	var ips []cnet.IPNet
	updatedUnallocated := b.Unallocated[:0]
	var attrIndexPtr *int
	for idx, ordinal := range b.Unallocated {
		// Check if we're done.
		if len(ips) >= num {
			// Got enough IPs, finish copying the remaining ordinals.
			updatedUnallocated = append(updatedUnallocated, b.Unallocated[idx:]...)
			break
		}
		// Check if this IP is reserved.
		addr := b.OrdinalToIP(ordinal)
		if reservations.MatchesIP(addr) {
			log.WithField("addr", addr).Debug("Skipping reserved IP.")
			updatedUnallocated = append(updatedUnallocated, ordinal)
			continue
		}
		// This IP is OK to use.  Allocate it.
		if attrIndexPtr == nil {
			attrIndex := b.findOrAddAttribute(handleID, attrs)
			attrIndexPtr = &attrIndex
		}
		b.Allocations[ordinal] = attrIndexPtr
		ipNet := *mask
		ipNet.IP = addr.IP
		ips = append(ips, ipNet)

		// Set the sequence number for this allocation.
		b.SetSequenceNumberForOrdinal(ordinal)
		continue
	}
	b.Unallocated = updatedUnallocated

	log.Debugf("Block %s returned ips: %v", b.CIDR.String(), ips)
	return ips, nil
}

func (b *allocationBlock) assign(affinityCheck bool, address cnet.IP, handleID *string, attrs map[string]string, affinityCfg AffinityConfig) error {
	if affinityCheck && b.Affinity != nil && !affinityMatches(affinityCfg, b.AllocationBlock) {
		// Affinity check is enabled but the host does not match - error.
		return errors.New("Block host affinity does not match")
	} else if b.Affinity == nil {
		log.Warnf("Attempting to assign IP from block with no affinity: %v", b)
		if affinityCheck {
			// If we're checking strict affinity, we can't assign from a block with no affinity.
			return fmt.Errorf("Attempt to assign from block %v with no affinity", b.CIDR)
		}
	}

	// Convert to an ordinal.
	ordinal, err := b.IPToOrdinal(address)
	if err != nil {
		return err
	}

	// Set the sequence number for this allocation.
	b.SetSequenceNumberForOrdinal(ordinal)

	// Check if already allocated.
	if b.Allocations[ordinal] != nil {
		return cerrors.ErrorResourceAlreadyExists{
			Err:        fmt.Errorf("Address already assigned in block"),
			Identifier: address.String(),
		}
	}

	// Set up attributes.
	attrIndex := b.findOrAddAttribute(handleID, attrs)
	b.Allocations[ordinal] = &attrIndex

	// Remove from unallocated.
	for i, unallocated := range b.Unallocated {
		if unallocated == ordinal {
			b.Unallocated = append(b.Unallocated[:i], b.Unallocated[i+1:]...)
			break
		}
	}
	return nil
}

// affinityMatches checks if the provided host matches the provided affinity.
func affinityMatches(affinityCfg AffinityConfig, block *model.AllocationBlock) bool {
	return *block.Affinity == fmt.Sprintf("%s:%s", affinityCfg.AffinityType, affinityCfg.Host)
}

func getAffinityConfig(block *model.AllocationBlock) (*AffinityConfig, error) {
	if block.Affinity != nil && strings.HasPrefix(*block.Affinity, fmt.Sprintf("%s:", AffinityTypeHost)) {
		return &AffinityConfig{
			AffinityType: AffinityTypeHost,
			Host:         strings.TrimPrefix(*block.Affinity, fmt.Sprintf("%s:", AffinityTypeHost)),
		}, nil
	}
	if block.Affinity != nil && strings.HasPrefix(*block.Affinity, fmt.Sprintf("%s:", AffinityTypeVirtual)) {
		return &AffinityConfig{
			AffinityType: AffinityTypeVirtual,
			Host:         strings.TrimPrefix(*block.Affinity, fmt.Sprintf("%s:", AffinityTypeVirtual)),
		}, nil
	}
	return nil, errors.New("could not parse affinity config")
}

func (b allocationBlock) NumFreeAddresses(reservations addrFilter) int {
	if reservations.MatchesWholeCIDR(&b.CIDR) {
		return 0
	}
	if reservations.MatchesSome(&b.CIDR) {
		// Slow path: some IPs are filtered, need to count the non-filtered ones.
		unfiltered := 0
		for _, ord := range b.Unallocated {
			if reservations.MatchesIP(b.CIDR.NthIP(ord)) {
				continue
			}
			unfiltered++
		}
		return unfiltered
	}
	return len(b.Unallocated)
}

// empty returns true if the block has released all of its assignable addresses,
// and returns false if any assignable addresses are in use.
func (b allocationBlock) empty() bool {
	for _, attrIdx := range b.Allocations {
		if attrIdx == nil {
			continue
		}
		attrs := b.Attributes[*attrIdx]
		if attrs.HandleID == nil || strings.ToLower(*attrs.HandleID) != WindowsReservedHandle {
			return false
		}
	}
	return true
}

// inUseIPs returns a list of IPs currently allocated in this block in string format.
func (b allocationBlock) inUseIPs() []string {
	ips := []string{}
	for o, idx := range b.Allocations {
		if idx == nil {
			// Not allocated.
			continue
		}
		ips = append(ips, b.OrdinalToIP(o).String())
	}
	return ips
}

// release tries to release addresses matching the release options, on success,
// returns slice of IPs that were *skipped* due to not being allocated and a
// map from handle ID to count of IPs released for that handle.
func (b *allocationBlock) release(cfg *IPAMConfig, addresses []ReleaseOptions) ([]cnet.IP, map[string]int, error) {
	// Store return values.
	unallocated := []cnet.IP{}
	countByHandle := map[string]int{}

	// Used internally.
	var ordinals []int
	delRefCounts := map[int]int{}

	// De-duplicate addresses to ensure reference counting is correct
	uniqueAddresses := make(map[string]ReleaseOptions)
	for _, opt := range addresses {
		uniqueAddresses[opt.Address] = opt
	}

	// Determine the ordinals that need to be released and the
	// attributes that need to be cleaned up.
	log.Debugf("Releasing addresses from block: %v", uniqueAddresses)
	for ipStr, opts := range uniqueAddresses {
		ip := cnet.MustParseIP(ipStr)
		// Convert to an ordinal.
		ordinal, err := b.IPToOrdinal(ip)
		if err != nil {
			return nil, nil, err
		}
		log.Debugf("Address %s is ordinal %d", ip, ordinal)

		// Compare sequence numbers if one was given.
		if opts.SequenceNumber != nil && *opts.SequenceNumber != b.GetSequenceNumberForOrdinal(ordinal) {
			// Mismatched sequence number on the request and the stored allocation.
			// This means that whoever is requesting release of this IP address is doing so
			// based on out-of-date information. Fail the request wholesale.
			return nil, nil, cerrors.ErrorResourceUpdateConflict{
				Identifier: opts.Address,
				Err: cerrors.ErrorBadSequenceNumber{
					Requested: *opts.SequenceNumber,
					Expected:  b.GetSequenceNumberForOrdinal(ordinal),
				},
			}
		}

		// Check if allocated.
		log.Debugf("Checking if allocated: %v", b.Allocations)
		attrIdx := b.Allocations[ordinal]
		if attrIdx == nil {
			log.Debugf("Asked to release address that was not allocated")
			unallocated = append(unallocated, ip)
			continue
		}
		ordinals = append(ordinals, ordinal)
		log.Debugf("%s is allocated, ordinals to release are now %v", ip, ordinals)

		// Compare handles.
		handleID := ""
		if h := b.Attributes[*attrIdx].HandleID; h != nil {
			// The handle in the allocation may be malformed, so requires sanitation
			// before use in the code.
			handleID = sanitizeHandle(*h)
		}
		if opts.Handle != "" && handleID != opts.Handle {
			// The handle given on the request doesn't match the stored handle.
			// This means that whoever is requesting release of this IP address is doing so
			// based on out-of-date information. Fail the request wholesale.
			return nil, nil, cerrors.ErrorResourceUpdateConflict{
				Identifier: opts.Address,
				Err: cerrors.ErrorBadHandle{
					Requested: opts.Handle,
					Expected:  handleID,
				},
			}
		}

		// Increment reference counting for attributes.
		cnt := 1
		if cur, exists := delRefCounts[*attrIdx]; exists {
			cnt = cur + 1
		}
		delRefCounts[*attrIdx] = cnt
		log.Debugf("delRefCounts: %v", delRefCounts)

		// Increment count of addresses by handle if a handle
		// exists.
		log.Debugf("Looking up attribute with index %d", *attrIdx)
		if handleID != "" {
			countByHandle[handleID] = countByHandle[handleID] + 1
			log.Debugf("countByHandle %v", countByHandle)
		}
	}

	if len(ordinals) == 0 {
		return unallocated, countByHandle, nil
	}

	releaseAttrIdx := b.addReleaseAfterAttribute()
	log.Debugf("Allocations: %v", b.Allocations)
	log.Debugf("Releasing ordinals: %v", ordinals)
	for _, ordinal := range ordinals {
		log.Debugf("Releasing ordinal %d", ordinal)
		b.Allocations[ordinal] = releaseAttrIdx
	}

	// Perform garbage collection in case this or other IPs can be deallocated
	// by now.
	b.garbageCollect(cfg.MinIPReclaimAgeSeconds)

	return unallocated, countByHandle, nil
}

func (b allocationBlock) attributeIndexesByHandle(handleID string) []int {
	indexes := []int{}
	for i, attr := range b.Attributes {
		if attr.HandleID != nil && sanitizeHandle(*attr.HandleID) == handleID {
			indexes = append(indexes, i)
		}
	}
	return indexes
}

// sanitizeHandle fixes any improperly formatted handles that we might come across.
// Malformed handles were written as part of host-local to Calico IPAM migration after
// host-local IPAM changed its file format: https://github.com/projectcalico/cni-plugin/issues/821.
func sanitizeHandle(handleID string) string {
	return strings.Split(handleID, "\r")[0]
}

// Release all allocations with the handle in opts.
//
// If opts.SequenceNumber is set, and any affected allocations' sequence numbers
// do not match, those allocations are not released.
func (b *allocationBlock) releaseByHandle(cfg *IPAMConfig, opts ReleaseOptions) int {
	handleID := opts.Handle
	attrIndexes := b.attributeIndexesByHandle(handleID)
	log.Debugf("Attribute indexes to release: %v", attrIndexes)
	if len(attrIndexes) == 0 {
		// Nothing to release.
		log.Debugf("No addresses assigned to handle '%s'", handleID)
		return 0
	}

	// Look for all affected allocations, and redirect them to an Attributes entry containing only
	// ReleasedAt.
	var releaseAttrIdx *int
	var releaseCount int
	var o int
	for o = 0; o < b.NumAddresses(); o++ {
		// Only check allocated ordinals.
		if b.Allocations[o] == nil {
			continue
		}

		attrIndex := *b.Allocations[o]
		if intInSlice(attrIndex, attrIndexes) {
			if opts.SequenceNumber == nil || *opts.SequenceNumber == b.GetSequenceNumberForOrdinal(o) {
				// Release this ordinal.
				if releaseAttrIdx == nil {
					releaseAttrIdx = b.addReleaseAfterAttribute()
				}
				b.Allocations[o] = releaseAttrIdx
				releaseCount++
				continue
			}
		}
	}

	// Perform garbage collection in case this or other IPs can be deallocated
	// by now.
	b.garbageCollect(cfg.MinIPReclaimAgeSeconds)

	return releaseCount
}

// addReleaseAfterAttribute adds a new attribute to the block containing a
// ReleaseAfter in the future, and return a pointer to its index for use in
// b.Allocations.
func (b allocationBlock) addReleaseAfterAttribute() *int {
	now := v1.Now()
	releaseAttrIdx := new(len(b.Attributes))
	b.Attributes = append(b.Attributes, model.AllocationAttribute{
		ReleasedAt: &now,
	})
	return releaseAttrIdx
}

func (b allocationBlock) ipsByHandle(handleID string) []cnet.IP {
	ips := []cnet.IP{}
	attrIndexes := b.attributeIndexesByHandle(handleID)
	var o int
	for o = 0; o < b.NumAddresses(); o++ {
		if b.Allocations[o] != nil && intInSlice(*b.Allocations[o], attrIndexes) {
			ip := b.OrdinalToIP(o)
			ips = append(ips, ip)
		}
	}
	return ips
}

// allocationAttributesForIP returns the full AllocationAttribute for the given IP,
// including HandleID, ActiveOwnerAttrs, and AlternateOwnerAttrs in a single lookup.
func (b allocationBlock) allocationAttributesForIP(ip cnet.IP) (*model.AllocationAttribute, error) {
	ordinal, err := b.IPToOrdinal(ip)
	if err != nil {
		return nil, err
	}

	attrIndex := b.Allocations[ordinal]
	if attrIndex == nil {
		log.Debugf("IP %s is not currently assigned in block", ip)
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: ip.String(), Err: errors.New("IP is unassigned")}
	}

	attr := b.Attributes[*attrIndex]
	handle := attr.HandleID
	if handle != nil {
		// The handle in the allocation may be malformed, so requires sanitation
		// before use in the code.
		s := sanitizeHandle(*handle)
		handle = &s
	}
	return &model.AllocationAttribute{
		HandleID:            handle,
		ActiveOwnerAttrs:    attr.ActiveOwnerAttrs,
		AlternateOwnerAttrs: attr.AlternateOwnerAttrs,
	}, nil
}

func (b *allocationBlock) findOrAddAttribute(handleID *string, attrs map[string]string) int {
	logCtx := log.WithField("attrs", attrs)
	if handleID != nil {
		logCtx = log.WithField("handle", *handleID)
	}
	attr := model.AllocationAttribute{HandleID: handleID, ActiveOwnerAttrs: attrs}
	for idx, existing := range b.Attributes {
		if reflect.DeepEqual(attr, existing) {
			log.Debugf("Attribute '%+v' already exists", attr)
			return idx
		}
	}

	// Does not exist - add it.
	logCtx.Debugf("New allocation attribute: %#v", attr)
	attrIndex := len(b.Attributes)
	b.Attributes = append(b.Attributes, attr)
	return attrIndex
}

func (b *allocationBlock) affinityClaimTime() time.Time {
	if b.AllocationBlock == nil {
		return time.Time{}
	}
	if b.AffinityClaimTime == nil {
		return time.Time{}
	}
	return b.AffinityClaimTime.Time
}

func getBlockCIDRForAddress(addr cnet.IP, pool *v3.IPPool) cnet.IPNet {
	var mask net.IPMask
	if addr.Version() == 6 {
		// This is an IPv6 address.
		mask = net.CIDRMask(pool.Spec.BlockSize, 128)
	} else {
		// This is an IPv4 address.
		mask = net.CIDRMask(pool.Spec.BlockSize, 32)
	}
	masked := addr.Mask(mask)
	return cnet.IPNet{IPNet: net.IPNet{IP: masked, Mask: mask}}
}

func getIPVersion(ip cnet.IP) int {
	if ip.To4() == nil {
		return 6
	}
	return 4
}

func largerThanOrEqualToBlock(blockCIDR cnet.IPNet, pool *v3.IPPool) bool {
	ones, _ := blockCIDR.Mask.Size()
	return ones <= pool.Spec.BlockSize
}

func intInSlice(searchInt int, slice []int) bool {
	return slices.Contains(slice, searchInt)
}

// setOwnerAttributes sets ActiveOwnerAttrs and/or AlternateOwnerAttrs for an IP address atomically.
// Callers must validate updates and preconditions before calling this method.
func (b *allocationBlock) setOwnerAttributes(ip cnet.IP, handleID string, updates *OwnerAttributeUpdates, preconditions *OwnerAttributePreconditions) error {
	logCtx := log.WithFields(log.Fields{
		"ip":            ip,
		"handleID":      handleID,
		"updates":       updates,
		"preconditions": preconditions,
	})

	ordinal, err := b.IPToOrdinal(ip)
	if err != nil {
		return err
	}

	attrIndex := b.Allocations[ordinal]
	if attrIndex == nil {
		logCtx.Debug("IP is not currently assigned in block")
		return cerrors.ErrorResourceDoesNotExist{Identifier: ip.String(), Err: errors.New("IP is unassigned")}
	}

	attr := &b.Attributes[*attrIndex]

	if attr.HandleID == nil || sanitizeHandle(*attr.HandleID) != handleID {
		return fmt.Errorf("IP %s is not assigned to handle %s", ip, handleID)
	}

	// Verify all preconditions before making any changes.
	if updates.ActiveOwnerAttrs != nil || updates.ClearActiveOwner {
		if err := verifyExpectedOwner(attr.ActiveOwnerAttrs, preconditions.expectedActiveOwner(), ip, "ActiveOwnerAttrs"); err != nil {
			return err
		}
	}
	if updates.AlternateOwnerAttrs != nil || updates.ClearAlternateOwner {
		if err := verifyExpectedOwner(attr.AlternateOwnerAttrs, preconditions.expectedAlternateOwner(), ip, "AlternateOwnerAttrs"); err != nil {
			return err
		}
	}

	// Apply updates now that all preconditions are verified.
	if updates.ActiveOwnerAttrs != nil || updates.ClearActiveOwner {
		if updates.ClearActiveOwner {
			attr.ActiveOwnerAttrs = nil
		} else {
			attr.ActiveOwnerAttrs = updates.ActiveOwnerAttrs
		}
	}
	if updates.AlternateOwnerAttrs != nil || updates.ClearAlternateOwner {
		if updates.ClearAlternateOwner {
			attr.AlternateOwnerAttrs = nil
		} else {
			attr.AlternateOwnerAttrs = updates.AlternateOwnerAttrs
		}
	}

	return nil
}

// verifyExpectedOwner checks that currentAttrs matches expectedOwner. Returns nil if
// expectedOwner is nil (no check requested) or the match succeeds.
func verifyExpectedOwner(currentAttrs map[string]string, expectedOwner *AttributeOwner, ip cnet.IP, field string) error {
	if expectedOwner == nil {
		return nil
	}
	if expectedOwner.Matches(currentAttrs) {
		return nil
	}
	var currentPod, currentNamespace string
	if currentAttrs != nil {
		currentPod = currentAttrs[AttributePod]
		currentNamespace = currentAttrs[AttributeNamespace]
	}
	return cerrors.ErrorResourceUpdateConflict{
		Err:        fmt.Errorf("cannot set %s: expected pod=%s namespace=%s but found pod=%s namespace=%s", field, expectedOwner.Name, expectedOwner.Namespace, currentPod, currentNamespace),
		Identifier: ip.String(),
	}
}

// garbageCollect normalizes the block, including marking blocks as Unallocated
// if their ReleassedAt property is far enough in the past. Returns true if the
// block was changed.
func (b *allocationBlock) garbageCollect(minIPReclaimAgeSeconds int) bool {
	// First, look for any allocations that were released at least minIPReclaimSeconds ago.
	changed := false
	usedAttrs := map[int]struct{}{}
	var o int
	// Determine the time for comparison of ReleasedAt. The additional millisecond allows
	// minIPReclaimAgeSeconds=0 to reclaim immediately.
	deallocIfReleasedBefore := v1.NewTime(v1.Now().Add(time.Second*time.Duration(-minIPReclaimAgeSeconds) + time.Millisecond))
	for o = 0; o < b.NumAddresses(); o++ {
		if b.Allocations[o] == nil {
			continue
		}
		attr := &b.Attributes[*b.Allocations[o]]
		if attr.ReleasedAt != nil && attr.ReleasedAt.Before(&deallocIfReleasedBefore) {
			log.Debugf("Deallocating ordinal %d", o)
			// Actually deallocate the ordinal; the attribute will be cleaned
			// up below, if it is now unused. Note that this is the only place
			// where ordinals are placed on the Unallocated list.
			b.Allocations[o] = nil
			b.Unallocated = append(b.Unallocated, o)
			b.ClearSequenceNumberForOrdinal(o)
			changed = true
		}
		if b.Allocations[o] != nil {
			usedAttrs[*b.Allocations[o]] = struct{}{}
		}
	}

	// Eliminate any now-unreferenced attributes.
	newIndexes := make([]*int, len(b.Attributes))
	newAttrs := []model.AllocationAttribute{}
	y := 0 // Next free slot in the new attributes list.
	for x := range b.Attributes {
		if _, found := usedAttrs[x]; found {
			// Attribute at x is not being deleted.  Build a mapping
			// of old attribute index (x) to new attribute index (y).
			newIndexes[x] = new(y)
			y += 1
			newAttrs = append(newAttrs, b.Attributes[x])
		}
	}
	if len(newAttrs) != len(b.Attributes) {
		b.Attributes = newAttrs
		changed = true
	}

	// Rewrite attribute indexes for all allocations in this block.
	if changed {
		for i := 0; i < b.NumAddresses(); i++ {
			if b.Allocations[i] != nil {
				b.Allocations[i] = newIndexes[*b.Allocations[i]]
			}
		}
	}

	return changed
}
