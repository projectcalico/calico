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

//go:generate go run ./gen/endpointdata

package labelindex

import (
	"iter"
	"slices"
	"unique"
	"unsafe"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/lib/std/uniquestr"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// endpointData is the per-endpoint datum stored in the
// SelectorAndNamedPortIndex. In large clusters there is one instance
// per workload/host endpoint/network set — up to ~1M instances — so
// the per-endpoint footprint dominates label-index memory.
//
// It is a single concrete type so its methods can be inlined; the
// variant-specific tail (cidrs, ports, parents) lives in a generated
// per-shape struct that *embeds* endpointData as its prefix. Tail
// fields are accessed via the static shapeTable + unsafe pointer
// arithmetic. We never allocate plain endpointData values; the
// allocated type is always one of the per-shape variants, so the GC
// scans the parent pointers in the tail correctly. See
// endpoint_data_impls_gen.go for the variant struct definitions and
// the shape enum.
type endpointData struct {
	labels uniquelabels.Map     // 8 bytes
	cache  set.Adaptive[string] // 16 bytes; cache.UserData[0] is the shape byte
	// Total 24 bytes. Variants append their tail immediately after.
}

// portHandle is an interned, value-equal handle for a single
// model.EndpointPort. Endpoints sharing port tuples share storage at
// the unique-package level; equality on a portHandle is a single
// pointer compare.
type portHandle = unique.Handle[model.EndpointPort]

func internEndpointPort(p model.EndpointPort) portHandle {
	return unique.Make(p)
}

// portHandleMatches applies the original name + protocol match rule
// to an interned port and, if it matches, returns the port number and
// the canonical protocol enum to emit.
func portHandleMatches(h portHandle, name string, proto ipsetmember.Protocol) (port uint16, emitProto ipsetmember.Protocol, ok bool) {
	p := h.Value()
	if p.Name != name {
		return 0, 0, false
	}
	if !proto.MatchesModelProtocol(p.Protocol) {
		return 0, 0, false
	}
	return p.Port, ipsetmember.ProtocolFrom(p.Protocol), true
}

// shape identifies the concrete variant of endpointData. The
// generator (gen/endpointdata) enumerates the values; do not write
// constants by hand here. shapeGeneral is the slice-based fallback.
type shape uint8

// cidrKind says which CIDR layout a shape has.
//
//   - V4 / V6 / Dual: counted variants for workload-endpoint-style
//     inputs (1 single-address /32 v4, 1 single-address /128 v6, or
//     one of each).
//   - V4Multi / V6Multi: network-set-style variants holding a slice of
//     full ip.V4CIDR / ip.V6CIDR (prefix preserved). Used when every
//     CIDR is the same family and there are no named ports.
//   - General: fallback for mixed v4+v6 multi-CIDR inputs or anything
//     with ports that overflows the counted axes.
type cidrKind uint8

const (
	cidrKindV4 cidrKind = iota
	cidrKindV6
	cidrKindDual
	cidrKindV4Multi
	cidrKindV6Multi
	cidrKindGeneral
)

// shapeInfo records what each variant looks like. The generator emits
// the table shapeTable indexed by shape.
type shapeInfo struct {
	cidr     cidrKind // V4/V6/Dual/General
	portN    uint8    // 0, 1, 2 for counted; portN is undefined for General (use slice len)
	parentN  uint8    // 0, 1, 2 for counted; undefined for General
	portsOff uint8    // absolute offset (from endpointData base) of the ports field; 0 if portN == 0
	parsOff  uint8    // absolute offset of the parents field; 0 if parentN == 0
}

// cidrFieldOffset is the offset of the first variant-tail byte (the
// cidr field) from the struct base. It's the size of endpointData and
// the same for every variant: V6/Dual counted variants put their
// V6Addr there, V4Multi/V6Multi put cidrsPtr there, and epGeneral
// puts v4cidrsPtr there. Computed via unsafe.Sizeof so it tracks the
// target architecture's pointer size automatically.
const cidrFieldOffset = unsafe.Sizeof(endpointData{})

// tailPtr returns a pointer to the variant tail at absOff bytes from
// the endpointData base. Inlinable; callers must guarantee that
// absOff is a valid in-bounds offset for the variant the receiver was
// allocated as.
//
//go:nosplit
func (d *endpointData) tailPtr(absOff uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(d)) + absOff)
}

func (d *endpointData) shape() shape {
	return shape(d.cache.UserData[0])
}

// setShape writes the variant tag into the cache's UserData. Only
// called by the generated variant constructors.
func (d *endpointData) setShape(s shape) {
	d.cache.UserData[0] = byte(s)
}

// userDataV4Offset is the byte offset within cache.UserData where the
// optional embedded IPv4 address lives. UserData[0] holds the shape;
// UserData[3..6] (the last 4 bytes of UserData) hold the v4 address
// for V4 and Dual variants. V4Addr is [4]byte (alignment 1), so the
// load/store is a single 4-byte access regardless of where UserData
// sits inside the parent struct.
const userDataV4Offset = 3

// v4FromUserData reads the IPv4 address stashed in the cache's
// UserData. Only valid when the variant's cidrKind is V4 or Dual; the
// shape byte gates that. V4Addr is [4]byte (alignment 1), so reading
// it from inside the UserData byte array is safe.
func (d *endpointData) v4FromUserData() ip.V4Addr {
	return *(*ip.V4Addr)(unsafe.Pointer(&d.cache.UserData[userDataV4Offset]))
}

// setV4InUserData writes the IPv4 address into the cache's UserData.
// Called by the generated V4 / Dual variant constructors.
func (d *endpointData) setV4InUserData(v4 ip.V4Addr) {
	*(*ip.V4Addr)(unsafe.Pointer(&d.cache.UserData[userDataV4Offset])) = v4
}

// toLen32 narrows an int length to uint32, panicking on overflow. The
// compact (ptr, uint32 length) form used by epV4Multi / epV6Multi /
// epGeneral assumes lengths fit in 32 bits, which is far beyond any
// realistic per-endpoint count (K8s/etcd resource size limits cap
// these in the low-MB range). The guard is here to fail loudly if
// that assumption ever stops holding.
func toLen32(n int) uint32 {
	const maxLen = 1<<32 - 1
	if uint64(n) > maxLen {
		panic("labelindex: slice length exceeds uint32 storage")
	}
	return uint32(n)
}

// ---------------------------------------------------------------------
// Constructor dispatch.
// ---------------------------------------------------------------------

// newEndpointData picks the most compact concrete variant that can
// hold the given inputs.
//
//   - Counted V4/V6/Dual when every CIDR is a single-address /32 or
//     /128 and the counts (CIDRs, ports, parents) fit the 1/1/0-2/0-2
//     slot budget.
//   - V4Multi / V6Multi for network-set-style inputs: every CIDR is
//     the same family (any prefix), no named ports. Parents are
//     supported.
//   - General fallback for everything else (mixed v4+v6 multi-CIDR,
//     or anything with ports that overflows the counted axes).
func newEndpointData(
	labels uniquelabels.Map,
	nets []ip.CIDR,
	ports []model.EndpointPort,
	parents []*npParentData,
) *endpointData {
	kind, v4, v6 := classifyNets(nets)

	// Network-set-style: same-family multi-CIDR, no ports → typed
	// multi variant.
	if len(ports) == 0 {
		switch kind {
		case cidrKindV4Multi:
			return newEpV4Multi(labels, nets, parents)
		case cidrKindV6Multi:
			return newEpV6Multi(labels, nets, parents)
		default:
			// Fall through to general case.
		}
	}

	if kind == cidrKindV4Multi || kind == cidrKindV6Multi ||
		kind == cidrKindGeneral || len(ports) > 2 || len(parents) > 2 {
		return newEpGeneral(labels, nets, ports, parents)
	}
	return newCountedEndpointData(labels, kind, v4, v6, ports, parents)
}

// classifyNets inspects the nets slice and returns the cidr-kind plus
// the canonical v4/v6 addresses (only meaningful for the counted
// V4/V6/Dual cases). Decision tree:
//
//   - all CIDRs are single-address /32 v4 only, at most 1 → V4
//   - all CIDRs are single-address /128 v6 only, at most 1 → V6
//   - exactly 1 single v4 + 1 single v6 → Dual
//   - all CIDRs are v4 (any prefix, any count) → V4Multi
//   - all CIDRs are v6 (any prefix, any count) → V6Multi
//   - empty or mixed families → General
//
// The caller then routes counted shapes to the per-shape generated
// constructors, multi shapes to newEpV4Multi / newEpV6Multi, and
// General to newEpGeneral.
func classifyNets(nets []ip.CIDR) (kind cidrKind, v4 ip.V4Addr, v6 ip.V6Addr) {
	if len(nets) == 0 {
		return cidrKindGeneral, v4, v6
	}
	var v4Count, v6Count int
	var anyMultiAddr bool
	for _, cidr := range nets {
		if !cidr.IsSingleAddress() {
			anyMultiAddr = true
		}
		switch a := cidr.Addr().(type) {
		case ip.V4Addr:
			v4Count++
			if v4Count == 1 {
				v4 = a
			}
		case ip.V6Addr:
			v6Count++
			if v6Count == 1 {
				v6 = a
			}
		default:
			return cidrKindGeneral, v4, v6
		}
	}
	mixed := v4Count > 0 && v6Count > 0
	if mixed {
		// Counted Dual requires exactly 1 of each, single-address.
		if v4Count == 1 && v6Count == 1 && !anyMultiAddr {
			return cidrKindDual, v4, v6
		}
		return cidrKindGeneral, v4, v6
	}
	if v4Count > 0 {
		if v4Count == 1 && !anyMultiAddr {
			return cidrKindV4, v4, v6
		}
		return cidrKindV4Multi, v4, v6
	}
	// v6 only
	if v6Count == 1 && !anyMultiAddr {
		return cidrKindV6, v4, v6
	}
	return cidrKindV6Multi, v4, v6
}

// ---------------------------------------------------------------------
// Selector evaluation: labels.
// ---------------------------------------------------------------------

func (d *endpointData) GetHandle(name uniquestr.Handle) (uniquestr.Handle, bool) {
	if h, ok := d.labels.GetHandle(name); ok {
		return h, true
	}
	// Walk parents inline — no closure, just a small loop.
	for _, parent := range d.parents() {
		if h, ok := parent.labels.GetHandle(name); ok {
			return h, true
		}
	}
	return uniquestr.Handle{}, false
}

func (d *endpointData) OwnLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return d.labels.AllHandles()
}

func (d *endpointData) AllOwnAndParentLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return func(yield func(k, v uniquestr.Handle) bool) {
		seen := set.New[uniquestr.Handle]()
		defer seen.Clear()
		for k, v := range d.labels.AllHandles() {
			if !yield(k, v) {
				return
			}
			seen.Add(k)
		}
		for _, parent := range d.parents() {
			for k, v := range parent.labels.AllHandles() {
				if seen.Contains(k) {
					continue
				}
				if !yield(k, v) {
					return
				}
				seen.Add(k)
			}
		}
	}
}

// ---------------------------------------------------------------------
// Shape-switched iterators.
//
// Each iterator is the single place that knows how to walk a given
// data axis across every shape. The Append* and EqualTo methods below
// are written in terms of these iterators (and the matching slice
// helpers for parents/ports) and contain no shape switching of their
// own.
//
// Receivers are concrete so escape analysis can stack-allocate the
// returned closures at call sites that use `for x := range d.xxx()`.
// ---------------------------------------------------------------------

// v4CIDRs yields one V4CIDR per IPv4 entry on the endpoint. Counted
// V4/Dual variants synthesize a /32 from the address in UserData/tail;
// V4Multi and General yield their typed V4CIDR slices directly.
func (d *endpointData) v4CIDRs() iter.Seq[ip.V4CIDR] {
	return func(yield func(ip.V4CIDR) bool) {
		s := d.shape()
		switch s {
		case shapeGeneral:
			for _, c := range (*epGeneral)(unsafe.Pointer(d)).v4CIDRsSlice() {
				if !yield(c) {
					return
				}
			}
			return
		case shapeV4Multi:
			for _, c := range (*epV4Multi)(unsafe.Pointer(d)).cidrsSlice() {
				if !yield(c) {
					return
				}
			}
			return
		case shapeV6Multi:
			return
		}
		switch shapeTable[s].cidr {
		case cidrKindV4, cidrKindDual:
			yield(d.v4FromUserData().AsV4CIDR())
		}
	}
}

// v6CIDRs yields one V6CIDR per IPv6 entry on the endpoint. Counterpart
// to v4CIDRs; counted V6/Dual variants synthesize /128s from the V6Addr
// stored in the tail.
func (d *endpointData) v6CIDRs() iter.Seq[ip.V6CIDR] {
	return func(yield func(ip.V6CIDR) bool) {
		s := d.shape()
		switch s {
		case shapeGeneral:
			for _, c := range (*epGeneral)(unsafe.Pointer(d)).v6CIDRsSlice() {
				if !yield(c) {
					return
				}
			}
			return
		case shapeV6Multi:
			for _, c := range (*epV6Multi)(unsafe.Pointer(d)).cidrsSlice() {
				if !yield(c) {
					return
				}
			}
			return
		case shapeV4Multi:
			return
		}
		switch shapeTable[s].cidr {
		case cidrKindV6, cidrKindDual:
			v6 := *(*ip.V6Addr)(d.tailPtr(cidrFieldOffset))
			yield(v6.AsV6CIDR())
		}
	}
}

// ports returns the endpoint's interned port handles as a Go slice.
// For counted variants the slice header points directly into the
// variant's fixed-size ports array; for V4Multi/V6Multi the result is
// always empty (those variants have no ports by construction). No
// allocation.
func (d *endpointData) ports() []portHandle {
	s := d.shape()
	switch s {
	case shapeGeneral:
		return (*epGeneral)(unsafe.Pointer(d)).portsSlice()
	case shapeV4Multi, shapeV6Multi:
		return nil
	}
	info := &shapeTable[s]
	if info.portN == 0 {
		return nil
	}
	base := d.tailPtr(uintptr(info.portsOff))
	return unsafe.Slice((*portHandle)(base), info.portN)
}

// ---------------------------------------------------------------------
// Parents.
// ---------------------------------------------------------------------

// parents returns the endpoint's parent pointers as a Go slice. See
// the comment on ports() for the per-shape layout. No allocation.
func (d *endpointData) parents() []*npParentData {
	s := d.shape()
	switch s {
	case shapeGeneral:
		return (*epGeneral)(unsafe.Pointer(d)).parentsSlice()
	case shapeV4Multi:
		return (*epV4Multi)(unsafe.Pointer(d)).parentsSlice()
	case shapeV6Multi:
		return (*epV6Multi)(unsafe.Pointer(d)).parentsSlice()
	}
	info := &shapeTable[s]
	if info.parentN == 0 {
		return nil
	}
	base := d.tailPtr(uintptr(info.parsOff))
	return unsafe.Slice((**npParentData)(base), info.parentN)
}

// Parents returns an iter.Seq over the endpoint's parent pointers.
// The receiver is concrete, so escape analysis can stack-allocate the
// returned closure when the caller writes `for p := range d.Parents()`.
func (d *endpointData) Parents() iter.Seq[*npParentData] {
	return func(yield func(*npParentData) bool) {
		for _, p := range d.parents() {
			if !yield(p) {
				return
			}
		}
	}
}

func (d *endpointData) HasParent(parent *npParentData) bool {
	return slices.Contains(d.parents(), parent)
}

// ---------------------------------------------------------------------
// IP-set contributions.
// ---------------------------------------------------------------------

// AppendCIDROrIPMembers appends a CIDROrIPOnly IP-set member per CIDR
// to buf and returns the new slice. Iteration goes through v4CIDRs /
// v6CIDRs so the shape switch lives in those helpers, not here.
func (d *endpointData) AppendCIDROrIPMembers(buf []ipsetmember.IPSetMember) []ipsetmember.IPSetMember {
	for c := range d.v4CIDRs() {
		buf = append(buf, ipsetmember.MakeCIDROrIPOnlyV4(c))
	}
	for c := range d.v6CIDRs() {
		buf = append(buf, ipsetmember.MakeCIDROrIPOnlyV6(c))
	}
	return buf
}

// AppendIPPortMembers appends one IPSetMember per matching named-port
// × address pair to buf and returns the new slice. The cross product
// is expressed as nested iter.Seq loops; the only shape switching is
// inside ports() / v4CIDRs() / v6CIDRs().
func (d *endpointData) AppendIPPortMembers(
	buf []ipsetmember.IPSetMember,
	name string, proto ipsetmember.Protocol,
) []ipsetmember.IPSetMember {
	ports := d.ports()
	if len(ports) == 0 {
		return buf
	}
	for _, h := range ports {
		port, emit, ok := portHandleMatches(h, name, proto)
		if !ok {
			continue
		}
		for c := range d.v4CIDRs() {
			buf = append(buf, ipsetmember.MakeIPPortProtoV4(c.AddrV4(), port, emit))
		}
		for c := range d.v6CIDRs() {
			buf = append(buf, ipsetmember.MakeIPPortProtoV6(c.AddrV6(), port, emit))
		}
	}
	return buf
}

// ---------------------------------------------------------------------
// IP-set membership cache (lives in d.cache, an Adaptive set).
// UserData[0] holds the shape byte; the set's payload is untouched.
// ---------------------------------------------------------------------

func (d *endpointData) AddMatchingIPSetID(id string)       { d.cache.Add(id) }
func (d *endpointData) RemoveMatchingIPSetID(id string)    { d.cache.Discard(id) }
func (d *endpointData) NumMatchingIPSetIDs() int           { return d.cache.Len() }
func (d *endpointData) MatchingIPSetIDs() iter.Seq[string] { return d.cache.All() }
func (d *endpointData) ClearMatchingIPSetIDs()             { d.cache.Clear() }
func (d *endpointData) MatchingIPSetIDsString() string     { return d.cache.String() }

// ---------------------------------------------------------------------
// Equality (ignores cache, which is derived state).
// ---------------------------------------------------------------------

// EqualTo reports whether d and other carry the same labels, CIDRs,
// ports, and parents. Endpoints with different shapes are never equal
// (the shape is deterministic from the inputs, so semantically equal
// endpoints must have the same shape).
//
// Implementation note: same-shape endpoints have identical layout, so
// the per-shape branches only differ in how they reach their CIDRs.
// Ports and parents come through the shape-agnostic slice helpers.
func (d *endpointData) EqualTo(other *endpointData) bool {
	s := d.shape()
	if s != other.shape() {
		return false
	}
	if !d.labels.Equals(other.labels) {
		return false
	}
	switch s {
	case shapeGeneral:
		g1 := (*epGeneral)(unsafe.Pointer(d))
		g2 := (*epGeneral)(unsafe.Pointer(other))
		if !slices.Equal(g1.v4CIDRsSlice(), g2.v4CIDRsSlice()) ||
			!slices.Equal(g1.v6CIDRsSlice(), g2.v6CIDRsSlice()) {
			return false
		}
	case shapeV4Multi:
		m1 := (*epV4Multi)(unsafe.Pointer(d))
		m2 := (*epV4Multi)(unsafe.Pointer(other))
		if !slices.Equal(m1.cidrsSlice(), m2.cidrsSlice()) {
			return false
		}
	case shapeV6Multi:
		m1 := (*epV6Multi)(unsafe.Pointer(d))
		m2 := (*epV6Multi)(unsafe.Pointer(other))
		if !slices.Equal(m1.cidrsSlice(), m2.cidrsSlice()) {
			return false
		}
	default:
		// Counted variant: compare the in-tail V4Addr / V6Addr.
		switch shapeTable[s].cidr {
		case cidrKindV4:
			if d.v4FromUserData() != other.v4FromUserData() {
				return false
			}
		case cidrKindV6:
			if *(*ip.V6Addr)(d.tailPtr(cidrFieldOffset)) != *(*ip.V6Addr)(other.tailPtr(cidrFieldOffset)) {
				return false
			}
		case cidrKindDual:
			if d.v4FromUserData() != other.v4FromUserData() {
				return false
			}
			if *(*ip.V6Addr)(d.tailPtr(cidrFieldOffset)) != *(*ip.V6Addr)(other.tailPtr(cidrFieldOffset)) {
				return false
			}
		}
	}
	return slices.Equal(d.ports(), other.ports()) &&
		slices.Equal(d.parents(), other.parents())
}
