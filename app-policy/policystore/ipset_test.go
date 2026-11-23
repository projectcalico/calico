// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policystore

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
)

func TestAddIp(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP)
	addr := "2.2.2.2"
	uut.AddString(addr)
	Expect(uut.Contains(addr)).To(BeTrue())

	addr = "2.2.2.3"
	uut.AddString(addr)
	Expect(uut.Contains(addr)).To(BeTrue())

	// Test idempotency
	uut.AddString(addr)
	Expect(uut.Contains(addr)).To(BeTrue())
}

func TestRemoveIp(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP)
	addr := "2.2.2.2"

	uut.RemoveString("2.2.2.2")
	Expect(uut.Contains(addr)).To(BeFalse())
	uut.AddString("2.2.2.2")
	Expect(uut.Contains(addr)).To(BeTrue())
	uut.RemoveString("2.2.2.2")
	Expect(uut.Contains(addr)).To(BeFalse())
	// Test idempotency
	uut.RemoveString("2.2.2.2")
	Expect(uut.Contains(addr)).To(BeFalse())

	// Adding a different address should not affect a removed one
	uut.AddString("2.2.2.3")
	Expect(uut.Contains(addr)).To(BeFalse())
}

func TestAddIpAndPort(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
	addr := "2.2.2.2,tcp:2222"

	uut.AddString("2.2.2.2,tcp:2222")
	Expect(uut.Contains(addr)).To(BeTrue())

	// Different port.
	addr = "2.2.2.2,tcp:33"
	Expect(uut.Contains(addr)).To(BeFalse())

	// Add other port
	uut.AddString("2.2.2.2,tcp:33")
	Expect(uut.Contains(addr)).To(BeTrue())
}

func TestRemoveIpAndPort(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
	addr := "2.2.2.2,tcp:2222"

	uut.RemoveString("2.2.2.2,tcp:2222")
	Expect(uut.Contains(addr)).To(BeFalse())
	uut.AddString("2.2.2.2,tcp:2222")
	Expect(uut.Contains(addr)).To(BeTrue())
	uut.RemoveString("2.2.2.2,tcp:2222")
	Expect(uut.Contains(addr)).To(BeFalse())
	// Test idempotency
	uut.RemoveString("2.2.2.2,tcp:2222")
	Expect(uut.Contains(addr)).To(BeFalse())

	// Adding a different address should not affect a removed one
	uut.AddString("2.2.2.3,tcp:2222")
	Expect(uut.Contains(addr)).To(BeFalse())
}

func TestIpPortContains(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
	addrTCP := "2.2.2.2,tcp:2222"
	addrUDP := "2.2.2.2,udp:2222"
	addrPort := "2.2.2.2,tcp:2223"
	addrIp := "2.2.2.3,tcp:2222"

	// Different protocol
	uut.AddString("2.2.2.2,udp:2222")
	Expect(uut.Contains(addrTCP)).To(BeFalse())

	Expect(uut.Contains(addrUDP)).To(BeTrue())

	// Different port
	uut.AddString("2.2.2.2,tcp:2223")
	Expect(uut.Contains(addrTCP)).To(BeFalse())
	Expect(uut.Contains(addrPort)).To(BeTrue())

	// Different IP
	uut.AddString("2.2.2.3,tcp:2222")
	Expect(uut.Contains(addrTCP)).To(BeFalse())
	Expect(uut.Contains(addrIp)).To(BeTrue())
}

func TestIPNet(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_NET)
	uut.AddString("192.168.8.0/24")
	addr192_168_8_1 := "192.168.8.1"
	Expect(uut.Contains(addr192_168_8_1)).To(BeTrue())

	uut.AddString("192.168.0.0/16")
	addr192_168_20_1 := "192.168.20.1"
	Expect(uut.Contains(addr192_168_20_1)).To(BeTrue())

	uut.RemoveString("192.168.0.0/16")
	Expect(uut.Contains(addr192_168_20_1)).To(BeFalse())

	// Idempotency
	uut.AddString("192.168.8.0/24")
	Expect(uut.Contains(addr192_168_8_1)).To(BeTrue())
	Expect(uut.Contains(addr192_168_20_1)).To(BeFalse())
}

func TestIPNetAddIP(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_NET)
	uut.AddString("192.168.8.8/32")
	addr192_168_8_1 := "192.168.8.1"
	addr192_168_8_8 := "192.168.8.8"
	addr10_10_4_1 := "10.10.4.1"
	Expect(uut.Contains(addr192_168_8_8)).To(BeTrue())
	Expect(uut.Contains(addr192_168_8_1)).To(BeFalse())
	Expect(uut.Contains(addr10_10_4_1)).To(BeFalse())

	// Idempotency
	uut.AddString("192.168.8.8/32")
	Expect(uut.Contains(addr192_168_8_8)).To(BeTrue())
	Expect(uut.Contains(addr192_168_8_1)).To(BeFalse())
	Expect(uut.Contains(addr10_10_4_1)).To(BeFalse())

	// Remove
	uut.RemoveString("192.168.8.8/32")
	Expect(uut.Contains(addr192_168_8_8)).To(BeFalse())
	Expect(uut.Contains(addr192_168_8_1)).To(BeFalse())
	Expect(uut.Contains(addr10_10_4_1)).To(BeFalse())

	// Check cleanup
	internals := uut.(ipNetSet)
	Expect(internals.v4.children).To(Equal([2]*trieNode{nil, nil}))
	Expect(internals.v6.children).To(Equal([2]*trieNode{nil, nil}))
}

func TestIPNetAddAboveBelowMax(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_NET)
	addr192_168_8_1 := "192.168.8.1"
	addr192_168_8_8 := "192.168.8.8"
	addr192_168_255_1 := "192.168.255.1"
	uut.AddString("192.168.0.0/16")
	Expect(uut.Contains(addr192_168_8_8)).To(BeTrue())
	Expect(uut.Contains(addr192_168_8_1)).To(BeTrue())
	Expect(uut.Contains(addr192_168_255_1)).To(BeTrue())

	uut.AddString("192.168.8.0/24")
	Expect(uut.Contains(addr192_168_8_8)).To(BeTrue())
	Expect(uut.Contains(addr192_168_8_1)).To(BeTrue())
	Expect(uut.Contains(addr192_168_255_1)).To(BeTrue())

	uut.AddString("192.168.8.8/30")
	Expect(uut.Contains(addr192_168_8_8)).To(BeTrue())
	Expect(uut.Contains(addr192_168_8_1)).To(BeTrue())
	Expect(uut.Contains(addr192_168_255_1)).To(BeTrue())

	uut.AddString("192.168.8.8/32")
	Expect(uut.Contains(addr192_168_8_8)).To(BeTrue())
	Expect(uut.Contains(addr192_168_8_1)).To(BeTrue())
	Expect(uut.Contains(addr192_168_255_1)).To(BeTrue())

	uut.RemoveString("192.168.0.0/16")
	Expect(uut.Contains(addr192_168_8_8)).To(BeTrue())
	Expect(uut.Contains(addr192_168_8_1)).To(BeTrue())
	Expect(uut.Contains(addr192_168_255_1)).To(BeFalse())

	uut.RemoveString("192.168.8.0/24")
	Expect(uut.Contains(addr192_168_8_8)).To(BeTrue())
	Expect(uut.Contains(addr192_168_8_1)).To(BeFalse())
	Expect(uut.Contains(addr192_168_255_1)).To(BeFalse())

	uut.RemoveString("192.168.8.8/30")
	Expect(uut.Contains(addr192_168_8_8)).To(BeTrue())
	Expect(uut.Contains(addr192_168_8_1)).To(BeFalse())
	Expect(uut.Contains(addr192_168_255_1)).To(BeFalse())

	uut.RemoveString("192.168.8.8/32")
	Expect(uut.Contains(addr192_168_8_8)).To(BeFalse())
	Expect(uut.Contains(addr192_168_8_1)).To(BeFalse())
	Expect(uut.Contains(addr192_168_255_1)).To(BeFalse())

	// Check cleanup
	internals := uut.(ipNetSet)
	Expect(internals.v4.children).To(Equal([2]*trieNode{nil, nil}))
	Expect(internals.v6.children).To(Equal([2]*trieNode{nil, nil}))
}

// Test that the trie uses most-significant bits first
func TestIPNetBitOrder(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_NET)
	addr128 := "129.0.0.1"
	addr1 := "1.0.0.1"
	uut.AddString("1.0.0.0/2")
	Expect(uut.Contains(addr128)).To(BeFalse())
	Expect(uut.Contains(addr1)).To(BeTrue())
}

func TestIPNetV6(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_NET)
	uut.AddString("fe80:23af:77bd::/49")
	addrfe80_23af_77bd_34 := "fe80:23af:77bd::34"
	addrfe81_23af_77bd_fe80 := "fe81:23af:77bd::fe80"
	Expect(uut.Contains(addrfe80_23af_77bd_34)).To(BeTrue())
	Expect(uut.Contains(addrfe81_23af_77bd_fe80)).To(BeFalse())

	uut.AddString("fe80:23af::/32")
	addrfe80_23af_22 := "fe80:23af::22"
	Expect(uut.Contains(addrfe80_23af_22)).To(BeTrue())
	Expect(uut.Contains(addrfe81_23af_77bd_fe80)).To(BeFalse())

	uut.RemoveString("fe80:23af::/32")
	Expect(uut.Contains(addrfe80_23af_22)).To(BeFalse())
	Expect(uut.Contains(addrfe81_23af_77bd_fe80)).To(BeFalse())

	// Idempotency
	uut.AddString("fe80:23af:77bd::/48")
	Expect(uut.Contains(addrfe80_23af_77bd_34)).To(BeTrue())
	Expect(uut.Contains(addrfe80_23af_22)).To(BeFalse())
	Expect(uut.Contains(addrfe81_23af_77bd_fe80)).To(BeFalse())
}

// A member with a longer prefix than the trie's bitmap node (/25 to /31 for IPv4, /121 to /127 for
// IPv6) hangs below that node, so a lookup must look past the node's bitmap of host addresses.
func TestIPNetLongPrefixMembers(t *testing.T) {
	for _, tc := range []struct {
		member string
		in     []string
		out    []string
	}{
		{"10.0.0.128/25", []string{"10.0.0.128", "10.0.0.200", "10.0.0.255"}, []string{"10.0.0.127", "10.0.1.200"}},
		{"10.0.0.128/28", []string{"10.0.0.128", "10.0.0.130", "10.0.0.143"}, []string{"10.0.0.127", "10.0.0.144"}},
		{"10.0.0.130/31", []string{"10.0.0.130", "10.0.0.131"}, []string{"10.0.0.129", "10.0.0.132"}},
		{"fd00::80/121", []string{"fd00::80", "fd00::c8", "fd00::ff"}, []string{"fd00::7f", "fd00::1:c8"}},
		{"fd00::82/127", []string{"fd00::82", "fd00::83"}, []string{"fd00::81", "fd00::84"}},
	} {
		t.Run(tc.member, func(t *testing.T) {
			RegisterTestingT(t)
			uut := NewIPSet(proto.IPSetUpdate_NET)
			uut.AddString(tc.member)
			for _, addr := range tc.in {
				Expect(uut.Contains(addr)).To(BeTrue(), "%s should be in %s", addr, tc.member)
			}
			for _, addr := range tc.out {
				Expect(uut.Contains(addr)).To(BeFalse(), "%s should not be in %s", addr, tc.member)
			}

			uut.RemoveString(tc.member)
			for _, addr := range tc.in {
				Expect(uut.Contains(addr)).To(BeFalse(), "%s after removing %s", addr, tc.member)
			}
			internals := uut.(ipNetSet)
			Expect(internals.v4.children).To(Equal([2]*trieNode{nil, nil}))
			Expect(internals.v6.children).To(Equal([2]*trieNode{nil, nil}))
		})
	}
}

// Host addresses and a longer prefix can share the bitmap node. Removing one kind of member must
// leave the other's addresses in the set.
func TestIPNetLongPrefixAndHostMembersOverlap(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_NET)
	uut.AddString("10.0.0.0/24")
	uut.AddString("10.0.0.128/28")
	uut.AddString("10.0.0.130/32")
	uut.AddString("10.0.0.5/32")

	uut.RemoveString("10.0.0.0/24")
	Expect(uut.Contains("10.0.0.130")).To(BeTrue())
	Expect(uut.Contains("10.0.0.135")).To(BeTrue())
	Expect(uut.Contains("10.0.0.5")).To(BeTrue())
	Expect(uut.Contains("10.0.0.6")).To(BeFalse())
	Expect(uut.Contains("10.0.0.200")).To(BeFalse())

	// The /28 still covers the host address taken out of the bitmap.
	uut.RemoveString("10.0.0.130/32")
	Expect(uut.Contains("10.0.0.130")).To(BeTrue())
	Expect(uut.Contains("10.0.0.5")).To(BeTrue())

	uut.AddString("10.0.0.130/32")
	uut.RemoveString("10.0.0.128/28")
	Expect(uut.Contains("10.0.0.130")).To(BeTrue())
	Expect(uut.Contains("10.0.0.135")).To(BeFalse())
	Expect(uut.Contains("10.0.0.5")).To(BeTrue())

	uut.RemoveString("10.0.0.130/32")
	uut.RemoveString("10.0.0.5/32")
	Expect(uut.Contains("10.0.0.130")).To(BeFalse())
	Expect(uut.Contains("10.0.0.5")).To(BeFalse())
	internals := uut.(ipNetSet)
	Expect(internals.v4.children).To(Equal([2]*trieNode{nil, nil}))
}

func BenchmarkIPNetSetContains(b *testing.B) {
	for _, tc := range []struct {
		name    string
		members []string
		addr    string
	}{
		{"HostMembers/Hit", []string{"10.0.0.5/32", "10.0.0.6/32", "10.0.1.7/32"}, "10.0.0.6"},
		{"HostMembers/Miss", []string{"10.0.0.5/32", "10.0.0.6/32", "10.0.1.7/32"}, "10.0.0.9"},
		{"ShortPrefix/Hit", []string{"10.0.0.0/16"}, "10.0.200.9"},
		{"LongPrefix/Hit", []string{"10.0.0.128/28", "10.0.0.5/32"}, "10.0.0.130"},
		{"LongPrefix/Miss", []string{"10.0.0.128/28", "10.0.0.5/32"}, "10.0.0.200"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			s := NewIPSet(proto.IPSetUpdate_NET)
			for _, m := range tc.members {
				s.AddString(m)
			}
			b.ReportAllocs()
			for b.Loop() {
				s.Contains(tc.addr)
			}
		})
	}
}
