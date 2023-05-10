// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/calico/app-policy/proto"

	envoyapi "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

func makeAddr(ip string, protocol envoyapi.SocketAddress_Protocol, port uint32) envoyapi.Address {
	return envoyapi.Address{Address: &envoyapi.Address_SocketAddress{
		SocketAddress: &envoyapi.SocketAddress{
			Address:       ip,
			Protocol:      protocol,
			PortSpecifier: &envoyapi.SocketAddress_PortValue{PortValue: port},
		},
	}}
}

func makeIpAddr(ip string) envoyapi.Address {
	return envoyapi.Address{Address: &envoyapi.Address_SocketAddress{
		SocketAddress: &envoyapi.SocketAddress{
			Address: ip,
		},
	}}
}

func TestAddIp(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP)
	uut.AddString("2.2.2.2")
	addr := makeIpAddr("2.2.2.2")
	Expect(uut.ContainsAddress(&addr)).To(BeTrue())

	uut.AddString("2.2.2.3")
	addr.GetSocketAddress().Address = "2.2.2.3"
	Expect(uut.ContainsAddress(&addr)).To(BeTrue())

	// Test idempotency
	uut.AddString("2.2.2.3")
	addr.GetSocketAddress().Address = "2.2.2.3"
	Expect(uut.ContainsAddress(&addr)).To(BeTrue())
}

func TestRemoveIp(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP)
	addr := makeIpAddr("2.2.2.2")

	uut.RemoveString("2.2.2.2")
	Expect(uut.ContainsAddress(&addr)).To(BeFalse())
	uut.AddString("2.2.2.2")
	Expect(uut.ContainsAddress(&addr)).To(BeTrue())
	uut.RemoveString("2.2.2.2")
	Expect(uut.ContainsAddress(&addr)).To(BeFalse())
	// Test idempotency
	uut.RemoveString("2.2.2.2")
	Expect(uut.ContainsAddress(&addr)).To(BeFalse())

	// Adding a different address should not affect a removed one
	uut.AddString("2.2.2.3")
	Expect(uut.ContainsAddress(&addr)).To(BeFalse())
}

func TestAddIpAndPort(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
	addr := makeAddr("2.2.2.2", envoyapi.SocketAddress_TCP, 2222)

	uut.AddString("2.2.2.2,tcp:2222")
	Expect(uut.ContainsAddress(&addr)).To(BeTrue())

	// Different port.
	addr.GetSocketAddress().GetPortSpecifier().(*envoyapi.SocketAddress_PortValue).PortValue = 33
	Expect(uut.ContainsAddress(&addr)).To(BeFalse())

	// Add other port
	uut.AddString("2.2.2.2,tcp:33")
	Expect(uut.ContainsAddress(&addr)).To(BeTrue())
}

func TestRemoveIpAndPort(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
	addr := makeAddr("2.2.2.2", envoyapi.SocketAddress_TCP, 2222)

	uut.RemoveString("2.2.2.2,tcp:2222")
	Expect(uut.ContainsAddress(&addr)).To(BeFalse())
	uut.AddString("2.2.2.2,tcp:2222")
	Expect(uut.ContainsAddress(&addr)).To(BeTrue())
	uut.RemoveString("2.2.2.2,tcp:2222")
	Expect(uut.ContainsAddress(&addr)).To(BeFalse())
	// Test idempotency
	uut.RemoveString("2.2.2.2,tcp:2222")
	Expect(uut.ContainsAddress(&addr)).To(BeFalse())

	// Adding a different address should not affect a removed one
	uut.AddString("2.2.2.3,tcp:2222")
	Expect(uut.ContainsAddress(&addr)).To(BeFalse())
}

func TestIpPortContainsAddress(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
	addrTCP := makeAddr("2.2.2.2", envoyapi.SocketAddress_TCP, 2222)
	addrUDP := makeAddr("2.2.2.2", envoyapi.SocketAddress_UDP, 2222)
	addrPort := makeAddr("2.2.2.2", envoyapi.SocketAddress_TCP, 2223)
	addrIp := makeAddr("2.2.2.3", envoyapi.SocketAddress_TCP, 2222)

	// Different protocol
	uut.AddString("2.2.2.2,udp:2222")
	Expect(uut.ContainsAddress(&addrTCP)).To(BeFalse())

	Expect(uut.ContainsAddress(&addrUDP)).To(BeTrue())

	// Different port
	uut.AddString("2.2.2.2,tcp:2223")
	Expect(uut.ContainsAddress(&addrTCP)).To(BeFalse())
	Expect(uut.ContainsAddress(&addrPort)).To(BeTrue())

	// Different IP
	uut.AddString("2.2.2.3,tcp:2222")
	Expect(uut.ContainsAddress(&addrTCP)).To(BeFalse())
	Expect(uut.ContainsAddress(&addrIp)).To(BeTrue())
}

func TestIPNet(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_NET)
	uut.AddString("192.168.8.0/24")
	addr192_168_8_1 := makeIpAddr("192.168.8.1")
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeTrue())

	uut.AddString("192.168.0.0/16")
	addr192_168_20_1 := makeIpAddr("192.168.20.1")
	Expect(uut.ContainsAddress(&addr192_168_20_1)).To(BeTrue())

	uut.RemoveString("192.168.0.0/16")
	Expect(uut.ContainsAddress(&addr192_168_20_1)).To(BeFalse())

	// Idempotency
	uut.AddString("192.168.8.0/24")
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_20_1)).To(BeFalse())
}

func TestIPNetAddIP(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_NET)
	uut.AddString("192.168.8.8/32")
	addr192_168_8_1 := makeIpAddr("192.168.8.1")
	addr192_168_8_8 := makeIpAddr("192.168.8.8")
	addr10_10_4_1 := makeIpAddr("10.10.4.1")
	Expect(uut.ContainsAddress(&addr192_168_8_8)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeFalse())
	Expect(uut.ContainsAddress(&addr10_10_4_1)).To(BeFalse())

	// Idempotency
	uut.AddString("192.168.8.8/32")
	Expect(uut.ContainsAddress(&addr192_168_8_8)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeFalse())
	Expect(uut.ContainsAddress(&addr10_10_4_1)).To(BeFalse())

	// Remove
	uut.RemoveString("192.168.8.8/32")
	Expect(uut.ContainsAddress(&addr192_168_8_8)).To(BeFalse())
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeFalse())
	Expect(uut.ContainsAddress(&addr10_10_4_1)).To(BeFalse())

	// Check cleanup
	internals := uut.(ipNetSet)
	Expect(internals.v4.children).To(Equal([2]*trieNode{nil, nil}))
	Expect(internals.v6.children).To(Equal([2]*trieNode{nil, nil}))
}

func TestIPNetAddAboveBelowMax(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_NET)
	addr192_168_8_1 := makeIpAddr("192.168.8.1")
	addr192_168_8_8 := makeIpAddr("192.168.8.8")
	addr192_168_255_1 := makeIpAddr("192.168.255.1")
	uut.AddString("192.168.0.0/16")
	Expect(uut.ContainsAddress(&addr192_168_8_8)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_255_1)).To(BeTrue())

	uut.AddString("192.168.8.0/24")
	Expect(uut.ContainsAddress(&addr192_168_8_8)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_255_1)).To(BeTrue())

	uut.AddString("192.168.8.8/30")
	Expect(uut.ContainsAddress(&addr192_168_8_8)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_255_1)).To(BeTrue())

	uut.AddString("192.168.8.8/32")
	Expect(uut.ContainsAddress(&addr192_168_8_8)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_255_1)).To(BeTrue())

	uut.RemoveString("192.168.0.0/16")
	Expect(uut.ContainsAddress(&addr192_168_8_8)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_255_1)).To(BeFalse())

	uut.RemoveString("192.168.8.0/24")
	Expect(uut.ContainsAddress(&addr192_168_8_8)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeFalse())
	Expect(uut.ContainsAddress(&addr192_168_255_1)).To(BeFalse())

	uut.RemoveString("192.168.8.8/30")
	Expect(uut.ContainsAddress(&addr192_168_8_8)).To(BeTrue())
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeFalse())
	Expect(uut.ContainsAddress(&addr192_168_255_1)).To(BeFalse())

	uut.RemoveString("192.168.8.8/32")
	Expect(uut.ContainsAddress(&addr192_168_8_8)).To(BeFalse())
	Expect(uut.ContainsAddress(&addr192_168_8_1)).To(BeFalse())
	Expect(uut.ContainsAddress(&addr192_168_255_1)).To(BeFalse())

	// Check cleanup
	internals := uut.(ipNetSet)
	Expect(internals.v4.children).To(Equal([2]*trieNode{nil, nil}))
	Expect(internals.v6.children).To(Equal([2]*trieNode{nil, nil}))
}

// Test that the trie uses most-significant bits first
func TestIPNetBitOrder(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_NET)
	addr128 := makeIpAddr("129.0.0.1")
	addr1 := makeIpAddr("1.0.0.1")
	uut.AddString("1.0.0.0/2")
	Expect(uut.ContainsAddress(&addr128)).To(BeFalse())
	Expect(uut.ContainsAddress(&addr1)).To(BeTrue())
}

func TestIPNetV6(t *testing.T) {
	RegisterTestingT(t)

	uut := NewIPSet(proto.IPSetUpdate_NET)
	uut.AddString("fe80:23af:77bd::/49")
	addrfe80_23af_77bd_34 := makeIpAddr("fe80:23af:77bd::34")
	addrfe81_23af_77bd_fe80 := makeIpAddr("fe81:23af:77bd::fe80")
	Expect(uut.ContainsAddress(&addrfe80_23af_77bd_34)).To(BeTrue())
	Expect(uut.ContainsAddress(&addrfe81_23af_77bd_fe80)).To(BeFalse())

	uut.AddString("fe80:23af::/32")
	addrfe80_23af_22 := makeIpAddr("fe80:23af::22")
	Expect(uut.ContainsAddress(&addrfe80_23af_22)).To(BeTrue())
	Expect(uut.ContainsAddress(&addrfe81_23af_77bd_fe80)).To(BeFalse())

	uut.RemoveString("fe80:23af::/32")
	Expect(uut.ContainsAddress(&addrfe80_23af_22)).To(BeFalse())
	Expect(uut.ContainsAddress(&addrfe81_23af_77bd_fe80)).To(BeFalse())

	// Idempotency
	uut.AddString("fe80:23af:77bd::/48")
	Expect(uut.ContainsAddress(&addrfe80_23af_77bd_34)).To(BeTrue())
	Expect(uut.ContainsAddress(&addrfe80_23af_22)).To(BeFalse())
	Expect(uut.ContainsAddress(&addrfe81_23af_77bd_fe80)).To(BeFalse())
}
