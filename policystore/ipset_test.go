// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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
package policystore

import (
	. "github.com/onsi/gomega"
	"testing"

	"github.com/projectcalico/app-policy/proto"

	envoyapi "github.com/envoyproxy/data-plane-api/api"
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
	g := NewGomegaWithT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP)
	uut.AddString("2.2.2.2")
	addr := makeIpAddr("2.2.2.2")
	g.Expect(uut.ContainsAddress(&addr)).To(BeTrue())

	uut.AddString("2.2.2.3")
	addr.GetSocketAddress().Address = "2.2.2.3"
	g.Expect(uut.ContainsAddress(&addr)).To(BeTrue())

	// Test idempotency
	uut.AddString("2.2.2.3")
	addr.GetSocketAddress().Address = "2.2.2.3"
	g.Expect(uut.ContainsAddress(&addr)).To(BeTrue())
}

func TestRemoveIp(t *testing.T) {
	g := NewGomegaWithT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP)
	addr := makeIpAddr("2.2.2.2")

	uut.RemoveString("2.2.2.2")
	g.Expect(uut.ContainsAddress(&addr)).To(BeFalse())
	uut.AddString("2.2.2.2")
	g.Expect(uut.ContainsAddress(&addr)).To(BeTrue())
	uut.RemoveString("2.2.2.2")
	g.Expect(uut.ContainsAddress(&addr)).To(BeFalse())
	// Test idempotency
	uut.RemoveString("2.2.2.2")
	g.Expect(uut.ContainsAddress(&addr)).To(BeFalse())

	// Adding a different address should not affect a removed one
	uut.AddString("2.2.2.3")
	g.Expect(uut.ContainsAddress(&addr)).To(BeFalse())
}

func TestAddIpAndPort(t *testing.T) {
	g := NewGomegaWithT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
	addr := makeAddr("2.2.2.2", envoyapi.SocketAddress_TCP, 2222)

	uut.AddString("2.2.2.2,tcp:2222")
	g.Expect(uut.ContainsAddress(&addr)).To(BeTrue())

	// Different port.
	addr.GetSocketAddress().GetPortSpecifier().(*envoyapi.SocketAddress_PortValue).PortValue = 33
	g.Expect(uut.ContainsAddress(&addr)).To(BeFalse())

	// Add other port
	uut.AddString("2.2.2.2,tcp:33")
	g.Expect(uut.ContainsAddress(&addr)).To(BeTrue())
}

func TestRemoveIpAndPort(t *testing.T) {
	g := NewGomegaWithT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
	addr := makeAddr("2.2.2.2", envoyapi.SocketAddress_TCP, 2222)

	uut.RemoveString("2.2.2.2,tcp:2222")
	g.Expect(uut.ContainsAddress(&addr)).To(BeFalse())
	uut.AddString("2.2.2.2,tcp:2222")
	g.Expect(uut.ContainsAddress(&addr)).To(BeTrue())
	uut.RemoveString("2.2.2.2,tcp:2222")
	g.Expect(uut.ContainsAddress(&addr)).To(BeFalse())
	// Test idempotency
	uut.RemoveString("2.2.2.2,tcp:2222")
	g.Expect(uut.ContainsAddress(&addr)).To(BeFalse())

	// Adding a different address should not affect a removed one
	uut.AddString("2.2.2.3,tcp:2222")
	g.Expect(uut.ContainsAddress(&addr)).To(BeFalse())
}

func TestIpPortContainsAddress(t *testing.T) {
	g := NewGomegaWithT(t)

	uut := NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
	addrTCP := makeAddr("2.2.2.2", envoyapi.SocketAddress_TCP, 2222)
	addrUDP := makeAddr("2.2.2.2", envoyapi.SocketAddress_UDP, 2222)
	addrPort := makeAddr("2.2.2.2", envoyapi.SocketAddress_TCP, 2223)
	addrIp := makeAddr("2.2.2.3", envoyapi.SocketAddress_TCP, 2222)

	// Different protocol
	uut.AddString("2.2.2.2,udp:2222")
	g.Expect(uut.ContainsAddress(&addrTCP)).To(BeFalse())

	g.Expect(uut.ContainsAddress(&addrUDP)).To(BeTrue())

	// Different port
	uut.AddString("2.2.2.2,tcp:2223")
	g.Expect(uut.ContainsAddress(&addrTCP)).To(BeFalse())
	g.Expect(uut.ContainsAddress(&addrPort)).To(BeTrue())

	// Different IP
	uut.AddString("2.2.2.3,tcp:2222")
	g.Expect(uut.ContainsAddress(&addrTCP)).To(BeFalse())
	g.Expect(uut.ContainsAddress(&addrIp)).To(BeTrue())
}
