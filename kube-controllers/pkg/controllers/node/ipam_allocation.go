// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
package node

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
)

func newBlockReleaseTracker(gracePeriod *time.Duration) *blockReleaseTracker {
	return &blockReleaseTracker{
		blocks:          make(map[string]time.Time),
		leakGracePeriod: gracePeriod,
	}
}

// blockReleaseTracker is used to track if blocks are valid for release. It ensures that the block
// has been empty for at least two syncs.
type blockReleaseTracker struct {
	blocks          map[string]time.Time
	leakGracePeriod *time.Duration
}

// MarkEmpty marks the block as empty, and returns true if the block
// was already empty, indicating that the block can be released.
func (t *blockReleaseTracker) markEmpty(cidr string) bool {
	if t.leakGracePeriod != nil && *t.leakGracePeriod > 0 {
		first, ok := t.blocks[cidr]
		if !ok {
			// This is the first time we've been marked empty.
			log.WithField("block", cidr).Debugf("Block marked as empty. Will be GC'd in %s", *t.leakGracePeriod)
			t.blocks[cidr] = time.Now()
			return false
		}

		// OK to release if this block has been empty for over the grace period.
		return time.Since(first) > *t.leakGracePeriod
	}
	log.WithField("block", cidr).Debug("No grace period set, block GC disabled")
	return false
}

// MarkInUse indicates to the tracker that this block is still in use.
func (t *blockReleaseTracker) markInUse(cidr string) {
	log.WithField("block", cidr).Debug("mark block in use")
	delete(t.blocks, cidr)
}

// OnBlockDeleted clears up any internal state associated with the block.
func (t *blockReleaseTracker) onBlockDeleted(cidr string) {
	log.WithField("block", cidr).Debug("block deleted")
	delete(t.blocks, cidr)
}

// handleTracker is used to aggregate information about all known IP addresses with the given
// handle. It can be used to ensure that all IPs with the given handle are ready for GC.
type handleTracker struct {
	allocationsByHandle map[string]map[string]*allocation
}

func (t *handleTracker) setAllocation(a *allocation) {
	if _, ok := t.allocationsByHandle[a.handle]; !ok {
		t.allocationsByHandle[a.handle] = map[string]*allocation{}
	}
	t.allocationsByHandle[a.handle][a.id()] = a
}

func (t *handleTracker) removeAllocation(a *allocation) {
	delete(t.allocationsByHandle[a.handle], a.id())
	if len(t.allocationsByHandle[a.handle]) == 0 {
		delete(t.allocationsByHandle, a.handle)
	}
}

func (t *handleTracker) isConfirmedLeak(handle string) bool {
	if len(t.allocationsByHandle) == 0 {
		// We shouldn't ever hit this, but handle it just in case.
		log.WithField("handle", handle).Warn("No allocations with handle")
		return false
	}
	for _, a := range t.allocationsByHandle[handle] {
		if !a.isConfirmedLeak() {
			// If any IP with this handle is still valid, the whole
			// handle is valid.
			log.WithFields(a.fields()).Debug("IP allocation that shares a handle is still valid")
			return false
		}
	}
	return true
}

func newHandleTracker() *handleTracker {
	return &handleTracker{
		allocationsByHandle: map[string]map[string]*allocation{},
	}
}

// allocation is an internal structure used by the IPAM garbage collector to track IPAM
// allocations and their status with respect to garbage collection.
type allocation struct {
	ip             string
	handle         string
	attrs          map[string]string
	sequenceNumber uint64
	block          string

	// The Kubernetes node name hosting this allocation.
	knode string

	// leakedAt is the time we first identified this allocation
	// to be a leak candidate.
	leakedAt *time.Time

	// confirmedLeak is set to true when we are confident this allocation
	// is a leaked IP.
	confirmedLeak bool
}

// ReleaseOptions returns the proper arguments to release this allocation.
func (a *allocation) ReleaseOptions() ipam.ReleaseOptions {
	return ipam.ReleaseOptions{
		Address:        a.ip,
		Handle:         a.handle,
		SequenceNumber: &a.sequenceNumber,
	}
}

// id returns a unique ID for this allocation.
func (a *allocation) id() string {
	return fmt.Sprintf("%s/%s", a.handle, a.ip)
}

func (a *allocation) fields() log.Fields {
	f := log.Fields{
		"ip":     a.ip,
		"handle": a.handle,
		"node":   a.attrs[ipam.AttributeNode],
	}

	if a.isPodIP() {
		ns := a.attrs[ipam.AttributeNamespace]
		pod := a.attrs[ipam.AttributePod]
		f["pod"] = fmt.Sprintf("%s/%s", ns, pod)
	}

	return f
}

func (a *allocation) node() string {
	if node, ok := a.attrs[ipam.AttributeNode]; ok {
		return node
	}
	return ""
}

func (a *allocation) markLeak(leakGracePeriod time.Duration) {
	if a.leakedAt == nil {
		t := time.Now()
		a.leakedAt = &t
		log.WithFields(a.fields()).Infof("Candidate IP leak")
	}

	if time.Since(*a.leakedAt) > leakGracePeriod && !a.isConfirmedLeak() {
		if leakGracePeriod > 0 {
			// If the duration is 0, that means the user has turned off IPAM GC.
			// We don't want to mark as a confirmed leak. We still allow marking as a candidate
			// leak for informational purposes.
			a.markConfirmedLeak()
		}
	}
}

func (a *allocation) markConfirmedLeak() {
	if a.confirmedLeak {
		// Already confirmed - nothing to do.
		return
	}
	if a.leakedAt == nil {
		log.WithFields(a.fields()).Warnf("Confirmed IP leak")
	} else {
		log.WithFields(a.fields()).Warnf("Confirmed IP leak after %s", time.Since(*a.leakedAt))
	}
	a.confirmedLeak = true
}

func (a *allocation) markValid() {
	if a.leakedAt != nil {
		log.WithFields(a.fields()).Infof("Confirmed valid IP after %s", time.Since(*a.leakedAt))
	}
	a.confirmedLeak = false
	a.leakedAt = nil
}

func (a *allocation) isConfirmedLeak() bool {
	return a.confirmedLeak
}

func (a *allocation) isCandidateLeak() bool {
	return a.leakedAt != nil && !a.confirmedLeak
}

func (a *allocation) isPodIP() bool {
	ns := a.attrs[ipam.AttributeNamespace]
	pod := a.attrs[ipam.AttributePod]

	return ns != "" && pod != ""
}

func (a *allocation) isTunnelAddress() bool {
	ipip := a.attrs[ipam.AttributeType] == ipam.AttributeTypeIPIP
	vxlan := a.attrs[ipam.AttributeType] == ipam.AttributeTypeVXLAN
	vxlanV6 := a.attrs[ipam.AttributeType] == ipam.AttributeTypeVXLANV6
	wg := a.attrs[ipam.AttributeType] == ipam.AttributeTypeWireguard
	return ipip || vxlan || vxlanV6 || wg
}

func (a *allocation) isWindowsReserved() bool {
	return a.handle == ipam.WindowsReservedHandle
}
