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

package v4

import (
	"testing"

	. "github.com/onsi/gomega"
)

// The leg's flag bit layout is a contract with the C side
// (felix/bpf-gpl/conntrack_types.h: the calico_ct_leg bitfield members and the
// CALI_CT_LEG_* masks), but the Go side spells it out independently in the
// encoder (Leg.AsBytes via setBit), Leg.Flags, and the two decoders
// (readConntrackLeg, readConntrackLegV6). Nothing forces those four to agree -
// a transposed bit compiles fine - so this test pins them to each other and to
// the numeric layout. The Go<->C half of the contract is covered by the bpf/ut
// tests that read BPF-written legs through these decoders.

// legBitPatterns is every flag alone, plus none, plus all: enough to catch a
// transposed or dropped bit in any of the four spellings.
func legBitPatterns() []Leg {
	// Seqno stays zero: it is not part of the flag contract, and its byte
	// order is asymmetric today - AsBytes writes it little-endian while both
	// decoders read it big-endian (the datapath stores it raw in network
	// order) - which is a pre-existing quirk out of this test's scope.
	base := Leg{Bytes: 0x1122334455667788, Packets: 0x99aabbcc, Ifindex: 42}
	single := []func(*Leg){
		func(l *Leg) { l.SynSeen = true },
		func(l *Leg) { l.AckSeen = true },
		func(l *Leg) { l.FinSeen = true },
		func(l *Leg) { l.RstSeen = true },
		func(l *Leg) { l.Approved = true },
		func(l *Leg) { l.Opener = true },
		func(l *Leg) { l.Workload = true },
		func(l *Leg) { l.Tunnel = true },
		func(l *Leg) { l.Pinned = true },
		func(l *Leg) { l.Checked = true },
	}

	patterns := []Leg{base}
	for _, set := range single {
		l := base
		set(&l)
		patterns = append(patterns, l)
	}
	all := base
	for _, set := range single {
		set(&all)
	}
	return append(patterns, all)
}

// legExpectedFlags computes the flag word from the documented bit positions
// alone, independent of the code under test.
func legExpectedFlags(l Leg) uint32 {
	var f uint32
	for bit, set := range []bool{
		l.SynSeen, l.AckSeen, l.FinSeen, l.RstSeen,
		l.Approved, l.Opener, l.Workload,
		l.Tunnel, l.Pinned, l.Checked,
	} {
		if set {
			f |= 1 << bit
		}
	}
	return f
}

func TestLegFlagsRoundTripV4(t *testing.T) {
	RegisterTestingT(t)

	for _, leg := range legBitPatterns() {
		Expect(leg.Flags()).To(Equal(legExpectedFlags(leg)),
			"Leg.Flags disagrees with the documented bit layout for %+v", leg)

		v := NewValueNormal(0, 0, leg, Leg{})
		got := ValueFromBytes(v.AsBytes()).Data().A2B
		Expect(got).To(Equal(leg), "A2B encode/decode changed the leg")

		v = NewValueNormal(0, 0, Leg{}, leg)
		got = ValueFromBytes(v.AsBytes()).Data().B2A
		Expect(got).To(Equal(leg), "B2A encode/decode changed the leg")
	}
}

func TestLegFlagsRoundTripV6(t *testing.T) {
	RegisterTestingT(t)

	for _, leg := range legBitPatterns() {
		v := NewValueV6Normal(0, 0, leg, Leg{})
		got := ValueV6FromBytes(v.AsBytes()).Data().A2B
		Expect(got).To(Equal(leg), "A2B encode/decode changed the leg (v6)")

		v = NewValueV6Normal(0, 0, Leg{}, leg)
		got = ValueV6FromBytes(v.AsBytes()).Data().B2A
		Expect(got).To(Equal(leg), "B2A encode/decode changed the leg (v6)")
	}
}
