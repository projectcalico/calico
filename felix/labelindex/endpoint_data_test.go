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

package labelindex

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Fixtures.

var (
	v4A = ip.MustParseCIDROrIP("10.0.0.1/32") // single-addr V4
	v4B = ip.MustParseCIDROrIP("10.0.0.2/32")
	v6A = ip.MustParseCIDROrIP("fd00::1/128") // single-addr V6
	v6B = ip.MustParseCIDROrIP("fd00::2/128")

	// Multi-prefix CIDRs (network-set style).
	v4Net24A = ip.MustParseCIDROrIP("10.1.0.0/24")
	v4Net16  = ip.MustParseCIDROrIP("10.2.0.0/16")
	v6Net64A = ip.MustParseCIDROrIP("fd00:1::/64")

	tcpFoo  = model.EndpointPort{Name: "foo", Protocol: numorstring.ProtocolFromString("tcp"), Port: 8080}
	tcpBar  = model.EndpointPort{Name: "bar", Protocol: numorstring.ProtocolFromString("tcp"), Port: 8081}
	udpFoo  = model.EndpointPort{Name: "foo", Protocol: numorstring.ProtocolFromString("udp"), Port: 8082}
	sctpFoo = model.EndpointPort{Name: "foo", Protocol: numorstring.ProtocolFromString("sctp"), Port: 8083}

	parentA = &npParentData{id: "A", labels: uniquelabels.Make(map[string]string{"role": "A"})}
	parentB = &npParentData{id: "B", labels: uniquelabels.Make(map[string]string{"role": "B"})}
	parentC = &npParentData{id: "C", labels: uniquelabels.Make(map[string]string{"role": "C"})}

	emptyLabels = uniquelabels.Make(nil)
	someLabels  = uniquelabels.Make(map[string]string{"env": "prod"})
)

// TestVariantShapeSelection asserts that newEndpointData picks the
// most compact variant for every shape it can represent.
func TestVariantShapeSelection(t *testing.T) {
	cases := []struct {
		name    string
		nets    []ip.CIDR
		ports   []model.EndpointPort
		parents []*npParentData
		want    shape
	}{
		// V4 — single-address /32 nets.
		{"V4P0N0", []ip.CIDR{v4A}, nil, nil, shapeV4P0N0},
		{"V4P0N1", []ip.CIDR{v4A}, nil, []*npParentData{parentA}, shapeV4P0N1},
		{"V4P0N2", []ip.CIDR{v4A}, nil, []*npParentData{parentA, parentB}, shapeV4P0N2},
		{"V4P1N0", []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo}, nil, shapeV4P1N0},
		{"V4P1N1", []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo}, []*npParentData{parentA}, shapeV4P1N1},
		{"V4P1N2", []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo}, []*npParentData{parentA, parentB}, shapeV4P1N2},
		{"V4P2N0", []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo, udpFoo}, nil, shapeV4P2N0},
		{"V4P2N1", []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo, udpFoo}, []*npParentData{parentA}, shapeV4P2N1},
		{"V4P2N2", []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo, udpFoo}, []*npParentData{parentA, parentB}, shapeV4P2N2},

		// V6 — single-address /128 nets.
		{"V6P0N0", []ip.CIDR{v6A}, nil, nil, shapeV6P0N0},
		{"V6P0N1", []ip.CIDR{v6A}, nil, []*npParentData{parentA}, shapeV6P0N1},
		{"V6P0N2", []ip.CIDR{v6A}, nil, []*npParentData{parentA, parentB}, shapeV6P0N2},
		{"V6P1N0", []ip.CIDR{v6A}, []model.EndpointPort{tcpFoo}, nil, shapeV6P1N0},
		{"V6P1N1", []ip.CIDR{v6A}, []model.EndpointPort{tcpFoo}, []*npParentData{parentA}, shapeV6P1N1},
		{"V6P1N2", []ip.CIDR{v6A}, []model.EndpointPort{tcpFoo}, []*npParentData{parentA, parentB}, shapeV6P1N2},
		{"V6P2N0", []ip.CIDR{v6A}, []model.EndpointPort{tcpFoo, udpFoo}, nil, shapeV6P2N0},
		{"V6P2N1", []ip.CIDR{v6A}, []model.EndpointPort{tcpFoo, udpFoo}, []*npParentData{parentA}, shapeV6P2N1},
		{"V6P2N2", []ip.CIDR{v6A}, []model.EndpointPort{tcpFoo, udpFoo}, []*npParentData{parentA, parentB}, shapeV6P2N2},

		// Dual — 1 v4 + 1 v6.
		{"DualP0N0", []ip.CIDR{v4A, v6A}, nil, nil, shapeDualP0N0},
		{"DualP0N1", []ip.CIDR{v4A, v6A}, nil, []*npParentData{parentA}, shapeDualP0N1},
		{"DualP0N2", []ip.CIDR{v4A, v6A}, nil, []*npParentData{parentA, parentB}, shapeDualP0N2},
		{"DualP1N0", []ip.CIDR{v4A, v6A}, []model.EndpointPort{tcpFoo}, nil, shapeDualP1N0},
		{"DualP1N1", []ip.CIDR{v4A, v6A}, []model.EndpointPort{tcpFoo}, []*npParentData{parentA}, shapeDualP1N1},
		{"DualP1N2", []ip.CIDR{v4A, v6A}, []model.EndpointPort{tcpFoo}, []*npParentData{parentA, parentB}, shapeDualP1N2},
		{"DualP2N0", []ip.CIDR{v4A, v6A}, []model.EndpointPort{tcpFoo, udpFoo}, nil, shapeDualP2N0},
		{"DualP2N1", []ip.CIDR{v4A, v6A}, []model.EndpointPort{tcpFoo, udpFoo}, []*npParentData{parentA}, shapeDualP2N1},
		{"DualP2N2", []ip.CIDR{v4A, v6A}, []model.EndpointPort{tcpFoo, udpFoo}, []*npParentData{parentA, parentB}, shapeDualP2N2},

		// V4Multi — same-family multi-CIDR or non-single-address
		// v4 input, no ports. Network-set shape.
		{"V4Multi/2v4Hosts", []ip.CIDR{v4A, v4B}, nil, nil, shapeV4Multi},
		{"V4Multi/v4Net24", []ip.CIDR{v4Net24A}, nil, nil, shapeV4Multi},
		{"V4Multi/v4Net16", []ip.CIDR{v4Net16}, nil, nil, shapeV4Multi},
		{"V4Multi/2v4Nets", []ip.CIDR{v4Net24A, v4Net16}, nil, nil, shapeV4Multi},
		{"V4Multi/withParents", []ip.CIDR{v4Net24A}, nil, []*npParentData{parentA, parentB}, shapeV4Multi},

		// V6Multi — same-family multi-CIDR or non-single-address v6.
		{"V6Multi/2v6Hosts", []ip.CIDR{v6A, v6B}, nil, nil, shapeV6Multi},
		{"V6Multi/v6Net64", []ip.CIDR{v6Net64A}, nil, nil, shapeV6Multi},

		// General — empty, mixed v4+v6 multi-CIDR, or anything with
		// ports that overflows the counted axes.
		{"General/empty", nil, nil, nil, shapeGeneral},
		{"General/3parents", []ip.CIDR{v4A}, nil, []*npParentData{parentA, parentB, parentC}, shapeGeneral},
		{"General/3ports", []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo, udpFoo, sctpFoo}, nil, shapeGeneral},
		{"General/v4Net+v6", []ip.CIDR{v4Net24A, v6A}, nil, nil, shapeGeneral},
		{"General/v4Net+ports", []ip.CIDR{v4Net24A}, []model.EndpointPort{tcpFoo}, nil, shapeGeneral},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newEndpointData(emptyLabels, c.nets, c.ports, c.parents)
			if got := d.shape(); got != c.want {
				t.Fatalf("shape: got %d, want %d", got, c.want)
			}
		})
	}
}

// TestVariantAppendCIDROrIPMembers verifies that every variant emits
// the correct IP-set members for the no-named-port (CIDR-only) case.
// Particularly important for the network-set bug: a /24 must produce
// a CIDR member, not a single-IP member.
func TestVariantAppendCIDROrIPMembers(t *testing.T) {
	cases := []struct {
		name string
		nets []ip.CIDR
	}{
		{"V4", []ip.CIDR{v4A}},
		{"V6", []ip.CIDR{v6A}},
		{"Dual", []ip.CIDR{v4A, v6A}},
		{"General/empty", nil},
		{"General/v4Net24", []ip.CIDR{v4Net24A}},
		{"General/v4Net16", []ip.CIDR{v4Net16}},
		{"General/v6Net64", []ip.CIDR{v6Net64A}},
		{"General/mixed", []ip.CIDR{v4Net24A, v6A, v4Net16}},
		{"General/2v4Hosts", []ip.CIDR{v4A, v4B}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newEndpointData(emptyLabels, c.nets, nil, nil)
			got := d.AppendCIDROrIPMembers(nil)

			// Expected = one member per input CIDR. For
			// single-address CIDRs the member is the address; for
			// real CIDRs (/24, /16, /64...) the member is the
			// CIDR itself.
			want := make([]ipsetmember.IPSetMember, 0, len(c.nets))
			for _, cidr := range c.nets {
				want = append(want, ipsetmember.MakeCIDROrIPOnly(cidr))
			}
			if !memberSetsEqual(got, want) {
				t.Fatalf("members:\n  got  %s\n  want %s", fmtMembers(got), fmtMembers(want))
			}
		})
	}
}

// TestVariantAppendIPPortMembers exercises every variant that can carry
// ports and asserts that named-port lookups emit one member per
// (matching port × address) pair.
func TestVariantAppendIPPortMembers(t *testing.T) {
	cases := []struct {
		name   string
		nets   []ip.CIDR
		ports  []model.EndpointPort
		query  string
		queryP ipsetmember.Protocol
		// expected: one member per (matched port × address)
	}{
		{"V4/oneTCP", []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo}, "foo", ipsetmember.ProtocolTCP},
		{"V4/oneTCP_noMatch", []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo}, "bar", ipsetmember.ProtocolTCP},
		{"V4/twoMixed_TCPquery", []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo, udpFoo}, "foo", ipsetmember.ProtocolTCP},
		{"V4/twoMixed_UDPquery", []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo, udpFoo}, "foo", ipsetmember.ProtocolUDP},
		{"V6/oneTCP", []ip.CIDR{v6A}, []model.EndpointPort{tcpFoo}, "foo", ipsetmember.ProtocolTCP},
		{"Dual/oneTCP", []ip.CIDR{v4A, v6A}, []model.EndpointPort{tcpFoo}, "foo", ipsetmember.ProtocolTCP},
		{"Dual/twoMixed_UDPquery", []ip.CIDR{v4A, v6A}, []model.EndpointPort{tcpFoo, udpFoo}, "foo", ipsetmember.ProtocolUDP},
		{"General/3ports", []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo, udpFoo, sctpFoo}, "foo", ipsetmember.ProtocolSCTP},
		// Multi-prefix CIDR forces General; cross product is per-CIDR.
		{"General/v4Net24+tcp", []ip.CIDR{v4Net24A}, []model.EndpointPort{tcpFoo}, "foo", ipsetmember.ProtocolTCP},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newEndpointData(emptyLabels, c.nets, c.ports, nil)
			got := d.AppendIPPortMembers(nil, c.query, c.queryP)

			// Build the expected set by mimicking the original
			// inline loop: for every matching port, for every cidr,
			// emit MakeIPPortProto(addr, port, proto).
			var want []ipsetmember.IPSetMember
			for _, p := range c.ports {
				if p.Name != c.query {
					continue
				}
				if !c.queryP.MatchesModelProtocol(p.Protocol) {
					continue
				}
				emit := ipsetmember.ProtocolFrom(p.Protocol)
				for _, cidr := range c.nets {
					want = append(want, ipsetmember.MakeIPPortProto(cidr.Addr(), p.Port, emit))
				}
			}
			if !memberSetsEqual(got, want) {
				t.Fatalf("members:\n  got  %s\n  want %s", fmtMembers(got), fmtMembers(want))
			}
		})
	}
}

// TestVariantParents covers Parents() and HasParent() across the parent
// shapes (0, 1, 2, multi via General).
func TestVariantParents(t *testing.T) {
	cases := [][]*npParentData{
		nil,
		{parentA},
		{parentA, parentB},
		{parentA, parentB, parentC},
	}
	for _, parents := range cases {
		name := fmt.Sprintf("N=%d", len(parents))
		t.Run(name, func(t *testing.T) {
			d := newEndpointData(emptyLabels, []ip.CIDR{v4A}, nil, parents)

			// Iterator yields all parents in order.
			var got []*npParentData
			for p := range d.Parents() {
				got = append(got, p)
			}
			if len(got) != len(parents) {
				t.Fatalf("Parents len: got %d, want %d", len(got), len(parents))
			}
			for i, p := range parents {
				if got[i] != p {
					t.Fatalf("Parents[%d]: got %v, want %v", i, got[i], p)
				}
			}

			// HasParent: positive cases.
			for _, p := range parents {
				if !d.HasParent(p) {
					t.Fatalf("HasParent(%v) = false; want true", p)
				}
			}
			// HasParent: negative case (a parent not in the list).
			notIn := parentA
			if len(parents) > 0 && parents[0] == parentA {
				notIn = parentC
				for _, p := range parents {
					if p == parentC {
						notIn = nil // pick something we know isn't there
						break
					}
				}
			}
			if notIn != nil && d.HasParent(notIn) {
				t.Fatalf("HasParent(%v) = true; want false", notIn)
			}
		})
	}
}

// TestVariantEqualTo covers shape-aware equality.
func TestVariantEqualTo(t *testing.T) {
	a := newEndpointData(someLabels, []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo}, []*npParentData{parentA})
	aCopy := newEndpointData(someLabels, []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo}, []*npParentData{parentA})
	bDifferentV4 := newEndpointData(someLabels, []ip.CIDR{v4B}, []model.EndpointPort{tcpFoo}, []*npParentData{parentA})
	bDifferentParent := newEndpointData(someLabels, []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo}, []*npParentData{parentB})
	bDifferentPort := newEndpointData(someLabels, []ip.CIDR{v4A}, []model.EndpointPort{udpFoo}, []*npParentData{parentA})
	bDifferentShape := newEndpointData(someLabels, []ip.CIDR{v6A}, []model.EndpointPort{tcpFoo}, []*npParentData{parentA})
	bDifferentLabels := newEndpointData(emptyLabels, []ip.CIDR{v4A}, []model.EndpointPort{tcpFoo}, []*npParentData{parentA})

	// General-vs-General.
	gA := newEndpointData(someLabels, []ip.CIDR{v4Net24A, v4Net16}, nil, nil)
	gACopy := newEndpointData(someLabels, []ip.CIDR{v4Net24A, v4Net16}, nil, nil)
	gB := newEndpointData(someLabels, []ip.CIDR{v4Net24A, v6Net64A}, nil, nil)

	cases := []struct {
		name string
		a, b *endpointData
		want bool
	}{
		{"same content", a, aCopy, true},
		{"different v4", a, bDifferentV4, false},
		{"different parent", a, bDifferentParent, false},
		{"different port", a, bDifferentPort, false},
		{"different shape (v4 vs v6)", a, bDifferentShape, false},
		{"different labels", a, bDifferentLabels, false},
		{"general same", gA, gACopy, true},
		{"general different cidr", gA, gB, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.a.EqualTo(c.b); got != c.want {
				t.Fatalf("EqualTo: got %v, want %v", got, c.want)
			}
		})
	}
}

// Helpers.

func memberSetsEqual(a, b []ipsetmember.IPSetMember) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, m := range a {
		matched := false
		for j, n := range b {
			if !used[j] && reflect.DeepEqual(m, n) {
				used[j] = true
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func fmtMembers(ms []ipsetmember.IPSetMember) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, fmt.Sprintf("%v", m))
	}
	return fmt.Sprintf("%v", parts)
}
