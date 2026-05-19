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

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/lib/std/uniquestr"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// endpointData is a per-endpoint datum stored in the
// SelectorAndNamedPortIndex. There is one instance per workload/host
// endpoint/network set, so in large clusters there can be ~1M
// instances and the per-endpoint footprint dominates label-index
// memory. It is implemented as an interface with multiple concrete
// implementations chosen at construction time by newEndpointData; the
// counted variants pack the common shapes (1 v4 / 1 v6 / 1v4+1v6 CIDR,
// 0/1/2 ports, 0/1/2 parents) into fixed-size fields and avoid the
// per-endpoint slice header + backing-array allocations the general
// fallback uses.
type endpointData interface {
	// Selector evaluation ----------------------------------------------
	// GetHandle implements parser.Labels: combines own labels with
	// parent labels on the fly.
	GetHandle(labelName uniquestr.Handle) (uniquestr.Handle, bool)
	// OwnLabelHandles implements labelnamevalueindex.Labeled.
	OwnLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle]
	// AllOwnAndParentLabelHandles implements
	// labelrestrictionindex.Labeled.
	AllOwnAndParentLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle]

	// Per-endpoint data -------------------------------------------------
	// AppendCIDROrIPMembers appends a CIDROrIPOnly IP-set member per
	// CIDR to buf and returns the new slice. Variants emit typed
	// members directly to avoid the ip.CIDR boxing the hot
	// CalculateEndpointContribution path would otherwise incur.
	AppendCIDROrIPMembers(buf []ipsetmember.IPSetMember) []ipsetmember.IPSetMember
	// AppendIPPortMembers appends one IPSetMember per
	// (matching-named-port × address) pair to buf.
	AppendIPPortMembers(buf []ipsetmember.IPSetMember,
		name string, proto ipsetmember.Protocol) []ipsetmember.IPSetMember
	// EachParent calls yield once per parent pointer in stable order.
	EachParent(yield func(*npParentData) bool)
	// HasParent reports whether parent is one of this endpoint's
	// parents.
	HasParent(parent *npParentData) bool

	// IP-set membership cache ------------------------------------------
	AddMatchingIPSetID(id string)
	RemoveMatchingIPSetID(id string)
	NumMatchingIPSetIDs() int
	MatchingIPSetIDs() iter.Seq[string]
	ClearMatchingIPSetIDs()
	MatchingIPSetIDsString() string

	// Change detection --------------------------------------------------
	// EqualTo compares this endpointData to other ignoring the
	// matching-IP-set-IDs cache (which is derived state).
	EqualTo(other endpointData) bool
}

// portHandle is an interned, value-equal handle for a single
// model.EndpointPort. Endpoints that share port tuples share storage
// at the unique-package level, and equality on a portHandle is a
// single pointer compare.
type portHandle = unique.Handle[model.EndpointPort]

func internEndpointPort(p model.EndpointPort) portHandle {
	return unique.Make(p)
}

// portHandleMatches centralises the protocol+name match rule so every
// implementation agrees. It is the inverse of the previous inline
// match in LookupNamedPorts: name must match, then the original
// MatchesModelProtocol rule applies to the protocol.
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

// newEndpointData picks the most compact concrete implementation that
// can hold the given inputs. As soon as any axis exceeds its counted
// slot count the general fallback is used (and all three axes are
// stored as slices) to keep the variant set small.
func newEndpointData(
	labels uniquelabels.Map,
	nets []ip.CIDR,
	ports []model.EndpointPort,
	parents []*npParentData,
) endpointData {
	cidrShape, v4, v6 := classifyNets(nets)
	if cidrShape == cidrShapeGeneral || len(ports) > 2 || len(parents) > 2 {
		return newEndpointDataGeneral(labels, nets, ports, parents)
	}
	return newCountedEndpointData(labels, cidrShape, v4, v6, ports, parents)
}

type cidrShape uint8

const (
	cidrShapeV4 cidrShape = iota
	cidrShapeV6
	cidrShapeDual
	cidrShapeGeneral
)

// classifyNets inspects the (validated) nets slice and returns the
// shape plus the canonical v4/v6 addresses where present. Anything
// other than exactly one v4, exactly one v6, or one of each is
// classified as general.
func classifyNets(nets []ip.CIDR) (shape cidrShape, v4 ip.V4Addr, v6 ip.V6Addr) {
	var sawV4, sawV6 bool
	for _, cidr := range nets {
		switch a := cidr.Addr().(type) {
		case ip.V4Addr:
			if sawV4 {
				return cidrShapeGeneral, v4, v6
			}
			sawV4 = true
			v4 = a
		case ip.V6Addr:
			if sawV6 {
				return cidrShapeGeneral, v4, v6
			}
			sawV6 = true
			v6 = a
		default:
			return cidrShapeGeneral, v4, v6
		}
	}
	switch {
	case sawV4 && sawV6:
		return cidrShapeDual, v4, v6
	case sawV4:
		return cidrShapeV4, v4, v6
	case sawV6:
		return cidrShapeV6, v4, v6
	default:
		return cidrShapeGeneral, v4, v6
	}
}

// allOwnAndParentLabelHandles is shared by every endpointData
// implementation. It walks the endpoint's own labels first, recording
// keys it has emitted, then calls eachParent (a push-style iterator
// supplied by the concrete variant) to enumerate parents without the
// allocation that an iter.Seq closure would incur.
func allOwnAndParentLabelHandles(
	labels uniquelabels.Map,
	eachParent func(yield func(*npParentData) bool),
) iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return func(yield func(k, v uniquestr.Handle) bool) {
		seen := set.New[uniquestr.Handle]()
		defer seen.Clear()
		stopped := false
		for k, v := range labels.AllHandles() {
			if !yield(k, v) {
				return
			}
			seen.Add(k)
		}
		eachParent(func(parent *npParentData) bool {
			for k, v := range parent.labels.AllHandles() {
				if seen.Contains(k) {
					continue
				}
				if !yield(k, v) {
					stopped = true
					return false
				}
				seen.Add(k)
			}
			return true
		})
		_ = stopped
	}
}

// ---------------------------------------------------------------------
// General fallback implementation.
// ---------------------------------------------------------------------

// epGeneral is used whenever any axis (cidrs, ports, parents) exceeds
// its counted-slot count. It stores all three axes as slices.
type epGeneral struct {
	labels  uniquelabels.Map
	nets    []ip.CIDR
	ports   []portHandle
	parents []*npParentData

	cache set.Adaptive[string]
}

func newEndpointDataGeneral(
	labels uniquelabels.Map,
	nets []ip.CIDR,
	ports []model.EndpointPort,
	parents []*npParentData,
) *epGeneral {
	d := &epGeneral{labels: labels}
	if len(nets) > 0 {
		d.nets = nets
	}
	if len(parents) > 0 {
		d.parents = parents
	}
	if len(ports) > 0 {
		d.ports = make([]portHandle, len(ports))
		for i, p := range ports {
			d.ports[i] = internEndpointPort(p)
		}
	}
	return d
}

func (d *epGeneral) GetHandle(name uniquestr.Handle) (uniquestr.Handle, bool) {
	if h, ok := d.labels.GetHandle(name); ok {
		return h, true
	}
	for _, parent := range d.parents {
		if h, ok := parent.labels.GetHandle(name); ok {
			return h, true
		}
	}
	return uniquestr.Handle{}, false
}

func (d *epGeneral) OwnLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return d.labels.AllHandles()
}

func (d *epGeneral) AllOwnAndParentLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return allOwnAndParentLabelHandles(d.labels, d.EachParent)
}

func (d *epGeneral) AppendCIDROrIPMembers(buf []ipsetmember.IPSetMember) []ipsetmember.IPSetMember {
	for _, c := range d.nets {
		buf = append(buf, ipsetmember.MakeCIDROrIPOnly(c))
	}
	return buf
}

func (d *epGeneral) AppendIPPortMembers(
	buf []ipsetmember.IPSetMember,
	name string, proto ipsetmember.Protocol,
) []ipsetmember.IPSetMember {
	for _, h := range d.ports {
		port, emit, ok := portHandleMatches(h, name, proto)
		if !ok {
			continue
		}
		for _, c := range d.nets {
			buf = append(buf, ipsetmember.MakeIPPortProto(c.Addr(), port, emit))
		}
	}
	return buf
}

func (d *epGeneral) EachParent(yield func(*npParentData) bool) {
	for _, p := range d.parents {
		if !yield(p) {
			return
		}
	}
}

func (d *epGeneral) HasParent(parent *npParentData) bool {
	return slices.Contains(d.parents, parent)
}

func (d *epGeneral) AddMatchingIPSetID(id string)       { d.cache.Add(id) }
func (d *epGeneral) RemoveMatchingIPSetID(id string)    { d.cache.Discard(id) }
func (d *epGeneral) NumMatchingIPSetIDs() int           { return d.cache.Len() }
func (d *epGeneral) MatchingIPSetIDs() iter.Seq[string] { return d.cache.All() }
func (d *epGeneral) ClearMatchingIPSetIDs()             { d.cache.Clear() }
func (d *epGeneral) MatchingIPSetIDsString() string     { return d.cache.String() }

func (d *epGeneral) EqualTo(other endpointData) bool {
	o, ok := other.(*epGeneral)
	if !ok {
		return false
	}
	if !d.labels.Equals(o.labels) {
		return false
	}
	if len(d.ports) != len(o.ports) ||
		len(d.nets) != len(o.nets) ||
		len(d.parents) != len(o.parents) {
		return false
	}
	for i, p := range d.ports {
		if o.ports[i] != p {
			return false
		}
	}
	for i, c := range d.nets {
		if o.nets[i] != c {
			return false
		}
	}
	for i, p := range d.parents {
		if o.parents[i] != p {
			return false
		}
	}
	return true
}
