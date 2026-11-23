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

package events

import (
	"encoding/binary"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/calc"
)

var _ = Describe("CollectorPolicyListener", func() {
	var l *CollectorPolicyListener

	BeforeEach(func() {
		l = NewCollectorPolicyListener(calc.NewLookupsCache())
		Expect(l.Start()).To(Succeed())
	})

	AfterEach(func() {
		l.Stop()
	})

	// policyVerdict lays out a policy verdict event the way the BPF programs fill in their state.
	// For ICMP they write the type and code over the destination port, type first, and copy that
	// port to the post-NAT port when there is no NAT; the pre-NAT port stays zero.
	policyVerdict := func(v6 bool, src, dst string, ipProto uint8, dport [2]byte) Event {
		data := make([]byte, 112)
		typ := TypePolicyVerdict
		if v6 {
			typ = TypePolicyVerdictV6
			copy(data[0:16], net.ParseIP(src).To16())
			copy(data[32:48], net.ParseIP(dst).To16())
			copy(data[48:64], net.ParseIP(dst).To16())
		} else {
			copy(data[0:4], net.ParseIP(src).To4())
			copy(data[32:36], net.ParseIP(dst).To4())
			copy(data[48:52], net.ParseIP(dst).To4())
		}
		copy(data[90:92], dport[:])
		if ipProto != protoICMP && ipProto != protoICMPv6 {
			copy(data[92:94], dport[:])
		}
		copy(data[94:96], dport[:])
		data[96] = ipProto
		binary.LittleEndian.PutUint32(data[100:104], 1)
		return Event{typ: typ, data: data}
	}

	It("should report the ICMP type in the high byte of the destination port", func() {
		// Destination unreachable (3), host unreachable (1).
		l.EventHandler(policyVerdict(false, "10.0.0.1", "10.0.0.2", protoICMP, [2]byte{3, 1}))
		pktInfo := <-l.PacketInfoChan()
		Expect(pktInfo.Tuple.Proto).To(Equal(protoICMP))
		Expect(pktInfo.Tuple.L4Dst).To(Equal(3<<8 | 1))
	})

	It("should report the ICMPv6 type in the high byte of the destination port", func() {
		// Echo request (128).
		l.EventHandler(policyVerdict(true, "fd00::1", "fd00::2", protoICMPv6, [2]byte{128, 0}))
		pktInfo := <-l.PacketInfoChan()
		Expect(pktInfo.Tuple.Proto).To(Equal(protoICMPv6))
		Expect(pktInfo.Tuple.L4Dst).To(Equal(128 << 8))
	})

	It("should leave TCP ports alone", func() {
		var port [2]byte
		binary.LittleEndian.PutUint16(port[:], 8080)
		l.EventHandler(policyVerdict(false, "10.0.0.1", "10.0.0.2", 6, port))
		pktInfo := <-l.PacketInfoChan()
		Expect(pktInfo.Tuple.L4Dst).To(Equal(8080))
		Expect(pktInfo.IsDNAT).To(BeFalse())
	})
})
