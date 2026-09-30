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

package accounting

import (
	"cmp"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

// AddressRef is a live resource referencing an address, tagged with the allowed use it holds the address for.
type AddressRef struct {
	IP       net.IP
	Kind     v3.IPPoolAllowedUse
	Referrer Referrer
}

// Referrer names the live resource behind a reference, such as a WorkloadEndpoint, Node, Service or VirtualMachine.
// Namespace is empty for a cluster-scoped resource.
type Referrer struct {
	Kind      string
	Namespace string
	Name      string
}

// String is Kind(namespace/name), or Kind(name) for a cluster-scoped resource.
func (r Referrer) String() string {
	if r.Namespace == "" {
		return fmt.Sprintf("%s(%s)", r.Kind, r.Name)
	}
	return fmt.Sprintf("%s(%s/%s)", r.Kind, r.Namespace, r.Name)
}

func (r Referrer) compare(other Referrer) int {
	return cmp.Or(
		strings.Compare(r.Kind, other.Kind),
		strings.Compare(r.Namespace, other.Namespace),
		strings.Compare(r.Name, other.Name),
	)
}

type addressRefKey struct {
	kind     v3.IPPoolAllowedUse
	referrer Referrer
}

// refKey is the map key for ip. IPv4 is unmapped, so a 16-byte IPv4 matches the 4-byte form blocks use.
func refKey(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	return addr.Unmap(), ok
}

// AddRefs records live references. Adding the same reference twice is a no-op.
func (t *Tracker) AddRefs(refs ...AddressRef) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, r := range refs {
		addr, ok := refKey(r.IP)
		if !ok {
			continue
		}
		k := addressRefKey{kind: r.Kind, referrer: r.Referrer}
		if !slices.Contains(t.refsByAddress[addr], k) {
			t.refsByAddress[addr] = append(t.refsByAddress[addr], k)
		}
	}
}

func (t *Tracker) RemoveRefs(refs ...AddressRef) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, r := range refs {
		addr, ok := refKey(r.IP)
		if !ok {
			continue
		}
		k := addressRefKey{kind: r.Kind, referrer: r.Referrer}
		keys := slices.DeleteFunc(t.refsByAddress[addr], func(existing addressRefKey) bool {
			return existing == k
		})
		if len(keys) == 0 {
			delete(t.refsByAddress, addr)
		} else {
			t.refsByAddress[addr] = keys
		}
	}
}

// Refs lists the live references to ip, ordered by referrer.
func (t *Tracker) Refs(ip net.IP) []AddressRef {
	t.mu.RLock()
	defer t.mu.RUnlock()
	addr, ok := refKey(ip)
	if !ok {
		return nil
	}
	return t.refsTo(addr)
}

func (t *Tracker) refsTo(addr netip.Addr) []AddressRef {
	keys := t.refsByAddress[addr]
	if len(keys) == 0 {
		return nil
	}
	out := make([]AddressRef, 0, len(keys))
	for _, k := range keys {
		out = append(out, AddressRef{IP: addr.AsSlice(), Kind: k.kind, Referrer: k.referrer})
	}
	slices.SortFunc(out, func(a, b AddressRef) int {
		return a.Referrer.compare(b.Referrer)
	})
	return out
}

// AllRefs lists every live reference, ordered by address and then referrer.
func (t *Tracker) AllRefs() []AddressRef {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []AddressRef
	for _, addr := range slices.SortedFunc(maps.Keys(t.refsByAddress), netip.Addr.Compare) {
		out = append(out, t.refsTo(addr)...)
	}
	return out
}

// Unreferenced is every assigned allocation in the pool that nothing of its kind references. The IPAM GC calls one
// leaked only once it stays unreferenced for its grace period.
func (t *Tracker) Unreferenced(name string) []Allocation {
	t.mu.RLock()
	defer t.mu.RUnlock()
	pool, ok := t.pools[name]
	if !ok {
		return nil
	}
	return t.unreferenced(pool.blocks.inOrder())
}

// NoPoolUnreferenced is Unreferenced for the blocks no pool claims.
func (t *Tracker) NoPoolUnreferenced() []Allocation {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.unreferenced(t.blocksWithNoPool.inOrder())
}

// unreferenced builds an Allocation's IP only for the unreferenced ones, which are few.
func (t *Tracker) unreferenced(blocks []*trackedBlock) []Allocation {
	var out []Allocation
	for _, block := range blocks {
		for a := range allocations(block.allocationBlock) {
			if a.IsCooling() {
				continue
			}
			addr := addrAt(block.base, a.Ordinal)
			if !t.isReferenced(a, addr) {
				a.IP = addr.AsSlice()
				out = append(out, a)
			}
		}
	}
	return out
}

// isReferenced judges an assigned allocation against the references its kind accepts. It errs toward referenced
// wherever the block alone cannot say who owns the address, the way the IPAM GC does.
func (t *Tracker) isReferenced(a Allocation, addr netip.Addr) bool {
	kind := a.Kind()
	switch kind {
	case KindWindowsReserved, KindUnknown:
		// Nothing could reference these, so they count as referenced.
		return true
	}
	for _, ref := range t.refsByAddress[addr] {
		if kind == ref.kind {
			return true
		}
	}

	// Nothing references the address, or something of another kind does: a node's tunnel field naming a pod's
	// address, or two resources claiming one IP.
	return false
}
