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
	"encoding/binary"
	"testing"

	. "github.com/onsi/gomega"
)

// legBits mirrors the CALI_CT_LEG_* bit positions in
// felix/bpf-gpl/conntrack_types.h. The bit numbers are written out here on
// purpose: naming LegFlag* instead would only compare the constants to
// themselves.
var legBits = []struct {
	name string
	bit  uint32
	flag uint32
	set  func(*Leg)
	get  func(Leg) bool
}{
	{"syn_seen", 0, LegFlagSynSeen, func(l *Leg) { l.SynSeen = true }, func(l Leg) bool { return l.SynSeen }},
	{"ack_seen", 1, LegFlagAckSeen, func(l *Leg) { l.AckSeen = true }, func(l Leg) bool { return l.AckSeen }},
	{"fin_seen", 2, LegFlagFinSeen, func(l *Leg) { l.FinSeen = true }, func(l Leg) bool { return l.FinSeen }},
	{"rst_seen", 3, LegFlagRstSeen, func(l *Leg) { l.RstSeen = true }, func(l Leg) bool { return l.RstSeen }},
	{"approved", 4, LegFlagApproved, func(l *Leg) { l.Approved = true }, func(l Leg) bool { return l.Approved }},
	{"opener", 5, LegFlagOpener, func(l *Leg) { l.Opener = true }, func(l Leg) bool { return l.Opener }},
	{"workload", 6, LegFlagWorkload, func(l *Leg) { l.Workload = true }, func(l Leg) bool { return l.Workload }},
	{"tunnel", 7, LegFlagTunnel, func(l *Leg) { l.Tunnel = true }, func(l Leg) bool { return l.Tunnel }},
	{"pinned", 8, LegFlagPinned, func(l *Leg) { l.Pinned = true }, func(l Leg) bool { return l.Pinned }},
	{"checked", 9, LegFlagChecked, func(l *Leg) { l.Checked = true }, func(l Leg) bool { return l.Checked }},
}

// TestLegFlagBitPositions pins each flag's bit across LegFlag*, Flags, AsBytes
// and the decoders.
func TestLegFlagBitPositions(t *testing.T) {
	for _, tc := range legBits {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)

			var leg Leg
			tc.set(&leg)

			Expect(tc.flag).To(Equal(uint32(1)<<tc.bit),
				"LegFlag constant for %s must be bit %d", tc.name, tc.bit)

			Expect(leg.Flags()).To(Equal(uint32(1)<<tc.bit),
				"Flags() must report %s as bit %d", tc.name, tc.bit)

			b := leg.AsBytes()
			Expect(len(b)).To(Equal(legSize))
			Expect(binary.LittleEndian.Uint32(b[legExtra+4:legExtra+8])).To(
				Equal(uint32(1)<<tc.bit),
				"AsBytes must set only bit %d of the flags word", tc.bit)

			for name, decode := range map[string]func([]byte) Leg{
				"v4": readConntrackLeg,
				"v6": readConntrackLegV6,
			} {
				got := decode(b)
				Expect(tc.get(got)).To(BeTrue(), "%s decoder lost %s", name, tc.name)
				Expect(got.Flags()).To(Equal(leg.Flags()), "%s decoder round trip", name)
			}
		})
	}
}

// TestLegRoundTrip checks that every field survives encode/decode, so a
// reshuffle of the struct cannot silently move the flags word.
func TestLegRoundTrip(t *testing.T) {
	RegisterTestingT(t)

	leg := Leg{
		Bytes:    0x1122334455667788,
		Packets:  0x99aabbcc,
		Seqno:    0xdeadbeef,
		SynSeen:  true,
		AckSeen:  false,
		FinSeen:  true,
		RstSeen:  false,
		Approved: true,
		Opener:   false,
		Workload: true,
		Tunnel:   true,
		Pinned:   false,
		Checked:  true,
		Ifindex:  0x0badf00d,
	}

	b := leg.AsBytes()
	Expect(readConntrackLeg(b)).To(Equal(leg))
	Expect(readConntrackLegV6(b)).To(Equal(leg))
}
