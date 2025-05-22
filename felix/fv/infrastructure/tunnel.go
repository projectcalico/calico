// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
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

package infrastructure

import (
	"fmt"
	"net"

	. "github.com/onsi/gomega"
)

// TunnelStrategy is a strategy for assigning tunnel configuration to a topology.
type TunnelStrategy interface {
	// Returns the tunnel address to use for the Felix with the given index.
	TunnelAddress(i int) string
	TunnelAddressV6(i int) string
}

// defaultTunnelStrategy implements TunnelStrategy, assigning a block to each Felix.
type defaultTunnelStrategy struct {
	v4Pool *net.IPNet
	v6Pool *net.IPNet
}

func NewDefaultTunnelStrategy(v4Pool, v6Pool string) TunnelStrategy {
	_, v4cidr, err := net.ParseCIDR(v4Pool)
	Expect(err).To(BeNil())
	_, v6cidr, err := net.ParseCIDR(v6Pool)
	Expect(err).To(BeNil())

	return &defaultTunnelStrategy{
		v4Pool: v4cidr,
		v6Pool: v6cidr,
	}
}

func (s *defaultTunnelStrategy) TunnelAddress(i int) string {
	return fmt.Sprintf("%d.%d.%d.0", s.v4Pool.IP[0], s.v4Pool.IP[1], i)
}

func (s *defaultTunnelStrategy) TunnelAddressV6(i int) string {
	cidr := s.v6Pool
	return net.ParseIP(fmt.Sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%d:0",
		cidr.IP[0], cidr.IP[1], cidr.IP[2], cidr.IP[3], cidr.IP[4], cidr.IP[5], cidr.IP[6],
		cidr.IP[7], cidr.IP[8], cidr.IP[9], cidr.IP[10], cidr.IP[11], i)).String()
}

// borrowedTunnelStrategy is a strategy for assigning tunnel configuration to a topology
// where one node borrows its tunnel address from the IPAM block of another.
type borrowedIPTunnelStrategy struct {
	v4Pool     *net.IPNet
	v6Pool     *net.IPNet
	numFelixes int
}

func NewBorrowedIPTunnelStrategy(v4Pool, v6Pool string, numFelixes int) TunnelStrategy {
	_, v4cidr, err := net.ParseCIDR(v4Pool)
	Expect(err).To(BeNil())
	_, v6cidr, err := net.ParseCIDR(v6Pool)
	Expect(err).To(BeNil())

	return &borrowedIPTunnelStrategy{
		v4Pool:     v4cidr,
		v6Pool:     v6cidr,
		numFelixes: numFelixes,
	}
}

func (s *borrowedIPTunnelStrategy) TunnelAddress(i int) string {
	if i == s.numFelixes-1 {
		// For most nodes, use the first IP of the block. However, for the last node,
		// we borrow its IP from the first node's block.
		return fmt.Sprintf("%d.%d.%d.1", s.v4Pool.IP[0], s.v4Pool.IP[1], 0)
	}
	return fmt.Sprintf("%d.%d.%d.0", s.v4Pool.IP[0], s.v4Pool.IP[1], i)
}

func (s *borrowedIPTunnelStrategy) TunnelAddressV6(i int) string {
	cidr := s.v6Pool
	if i == s.numFelixes-1 {
		// For most nodes, use the first IP of the block. However, for the last node,
		// we borrow its IP from the first node's block.
		return net.ParseIP(fmt.Sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%d:1",
			cidr.IP[0], cidr.IP[1], cidr.IP[2], cidr.IP[3], cidr.IP[4], cidr.IP[5], cidr.IP[6],
			cidr.IP[7], cidr.IP[8], cidr.IP[9], cidr.IP[10], cidr.IP[11], 0)).String()
	}
	return net.ParseIP(fmt.Sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%d:0",
		cidr.IP[0], cidr.IP[1], cidr.IP[2], cidr.IP[3], cidr.IP[4], cidr.IP[5], cidr.IP[6],
		cidr.IP[7], cidr.IP[8], cidr.IP[9], cidr.IP[10], cidr.IP[11], i)).String()
}
