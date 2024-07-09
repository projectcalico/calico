// Copyright (c) 2016-2023 Tigera, Inc. All rights reserved.
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

// The ip package contains yet another IP address (and CIDR) type :-).   The
// types differ from the ones in the net package in that they are backed by
// fixed-sized arrays of the appropriate size.  The key advantage of
// using a fixed-size array is that it makes the types hashable so they can
// be used as map keys.  In addition, they can be converted to net.IP by
// slicing.
package ip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"

	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	IPv4SizeDword = 1
	IPv6SizeDword = 4
)

var ErrInvalidIP = errors.New("Failed to parse IP address")

// Addr represents either an IPv4 or IPv6 IP address.
type Addr interface {
	// Version returns the IP version; 4 or 6.
	Version() uint8
	// AsNetIP returns a net.IP, which is backed by/shares storage with
	// this object.
	AsNetIP() net.IP
	AsCalicoNetIP() calinet.IP
	AsCIDR() CIDR
	String() string
	AsBinary() string
	Add(int) Addr
	NthBit(uint) int
}

type V4Addr [4]byte

func (a V4Addr) Version() uint8 {
	return 4
}

func (a V4Addr) AsNetIP() net.IP {
	return net.IP(a[0:net.IPv4len])
}

func (a V4Addr) AsCalicoNetIP() calinet.IP {
	return calinet.IP{IP: a.AsNetIP()}
}

func (a V4Addr) AsCIDR() CIDR {
	return V4CIDR{
		addr:   a,
		prefix: 32,
	}
}

func (a V4Addr) AsUint32() uint32 {
	return binary.BigEndian.Uint32(a[:])
}

func (a V4Addr) NthBit(n uint) int {
	return int(a.AsUint32() >> (32 - n) & 1)
}

func (a V4Addr) String() string {
	return a.AsNetIP().String()
}

func (a V4Addr) AsBinary() string {
	ipInBinary := fmt.Sprintf("%04b", 4)
	for ii := 0; ii < net.IPv4len; ii++ {
		temp := fmt.Sprintf("%08b", a[ii])
		ipInBinary += temp
	}

	return ipInBinary
}

func (a V4Addr) Add(n int) Addr {
	myValue := int(binary.BigEndian.Uint32(a[:]))
	offsetValue := (uint32)(myValue + n)
	var newAddr V4Addr
	binary.BigEndian.PutUint32(newAddr[:], offsetValue)
	return newAddr
}

func Int2NetIP(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, addr)
	return ip
}

type V6Addr [16]byte

func (a V6Addr) Version() uint8 {
	return 6
}

func (a V6Addr) AsNetIP() net.IP {
	return net.IP(a[0:net.IPv6len])
}

func (a V6Addr) AsCalicoNetIP() calinet.IP {
	return calinet.IP{IP: a.AsNetIP()}
}

func (a V6Addr) AsCIDR() CIDR {
	return V6CIDR{
		addr:   a,
		prefix: 128,
	}
}

// AsUint64Pair returns a pair of uint64 representing a V6Addr as there is
// no native 128 bit uint type in go.
func (a V6Addr) AsUint64Pair() (uint64, uint64) {
	return binary.BigEndian.Uint64(a[:8]), binary.BigEndian.Uint64(a[8:])
}

func (a V6Addr) NthBit(n uint) int {
	h, l := a.AsUint64Pair()
	if n <= 64 {
		return int(h >> (64 - n) & 1)
	}

	return int(l >> (128 - n) & 1)
}

func (a V6Addr) String() string {
	return a.AsNetIP().String()
}

func (a V6Addr) AsBinary() string {
	ipInBinary := fmt.Sprintf("%04b", 6)
	for ii := 0; ii < net.IPv6len; ii++ {
		temp := fmt.Sprintf("%08b", a[ii])
		ipInBinary += temp
	}

	return ipInBinary
}

func (a V6Addr) Add(n int) Addr {
	var myVal, nVal, newVal big.Int

	myVal.SetBytes(a[:])
	nVal.SetInt64(int64(n))
	newVal.Add(&myVal, &nVal)

	var newAddr V6Addr
	b := newVal.Bytes()
	bLen := len(b)
	offset := len(a) - bLen
	copy(newAddr[offset:], b)

	return newAddr
}

type CIDR interface {
	Version() uint8
	Addr() Addr
	Prefix() uint8
	String() string
	ToIPNet() net.IPNet
	AsBinary() string
	Contains(addr Addr) bool
	// IsSingleAddress returns true if the CIDR represents a single address.
	// I.e. a /32 for IPv4 or a /128 for IPv6.
	IsSingleAddress() bool
}

type V4CIDR struct {
	addr   V4Addr
	prefix uint8
}

func (c V4CIDR) Version() uint8 {
	return 4
}

func (c V4CIDR) Addr() Addr {
	return c.addr
}

func (c V4CIDR) Prefix() uint8 {
	return c.prefix
}

func (c V4CIDR) ToIPNet() net.IPNet {
	return net.IPNet{
		IP:   c.Addr().AsNetIP(),
		Mask: net.CIDRMask(int(c.Prefix()), 32),
	}
}

func (c V4CIDR) Contains(addr Addr) bool {
	v4Addr, ok := addr.(V4Addr)
	if !ok {
		return false
	}

	return c.ContainsV4(v4Addr)
}

func (c V4CIDR) ContainsV4(addr V4Addr) bool {
	a32 := c.addr.AsUint32()
	b32 := addr.AsUint32()
	xored := a32 ^ b32 // Has a zero bit wherever the two values are the same.
	commonPrefixLen := uint8(bits.LeadingZeros32(xored))
	return commonPrefixLen >= c.prefix
}

func (c V4CIDR) String() string {
	return fmt.Sprintf("%s/%v", c.addr.String(), c.prefix)
}

func (c V4CIDR) AsBinary() string {
	ipInBinary := fmt.Sprintf("%04b", 4)
	for ii := 0; ii < net.IPv4len; ii++ {
		temp := fmt.Sprintf("%08b", c.addr[ii])
		ipInBinary += temp
	}

	return ipInBinary[0 : c.prefix+4]
}

func (c V4CIDR) IsSingleAddress() bool {
	return c.prefix == 32
}

type V6CIDR struct {
	addr   V6Addr
	prefix uint8
}

func (c V6CIDR) Version() uint8 {
	return 6
}

func (c V6CIDR) Addr() Addr {
	return c.addr
}

func (c V6CIDR) Prefix() uint8 {
	return c.prefix
}

func (c V6CIDR) ToIPNet() net.IPNet {
	return net.IPNet{
		IP:   c.Addr().AsNetIP(),
		Mask: net.CIDRMask(int(c.Prefix()), 128),
	}
}

func (c V6CIDR) Contains(addr Addr) bool {
	v6Addr, ok := addr.(V6Addr)
	if !ok {
		return false
	}

	return c.ContainsV6(v6Addr)
}

func (c V6CIDR) ContainsV6(addr V6Addr) bool {
	a64_h, a64_l := c.addr.AsUint64Pair()
	b64_h, b64_l := addr.AsUint64Pair()
	xored_h := a64_h ^ b64_h // Has a zero bit wherever the two values are the same.
	xored_l := a64_l ^ b64_l

	commonPrefixLen := uint8(bits.LeadingZeros64(xored_h))
	if xored_h == 0 {
		commonPrefixLen = 64 + uint8(bits.LeadingZeros64(xored_l))
	}

	return commonPrefixLen >= c.prefix
}

func (c V6CIDR) String() string {
	return fmt.Sprintf("%s/%v", c.addr.String(), c.prefix)
}

func (c V6CIDR) AsBinary() string {
	ipInBinary := fmt.Sprintf("%04b", 6)
	for ii := 0; ii < net.IPv6len; ii++ {
		temp := fmt.Sprintf("%08b", c.addr[ii])
		ipInBinary += temp
	}
	return ipInBinary[0 : c.prefix+4]
}

func (c V6CIDR) IsSingleAddress() bool {
	return c.prefix == 128
}

func FromString(s string) Addr {
	return FromNetIP(net.ParseIP(s))
}

// Parses an IP or CIDR string and returns the IP.
func FromIPOrCIDRString(s string) Addr {
	parts := strings.Split(s, "/")
	return FromNetIP(net.ParseIP(parts[0]))
}

func FromNetIP(netIP net.IP) Addr {
	// Note: we have to use To4() here because the net package often represents an IPv4 address
	// using 16 bytes.  The only way to distinguish an IPv4 address using that API is To4(),
	// which returns nil if the IP is a v6 address or nil.
	if v4NetIP := netIP.To4(); v4NetIP != nil {
		ip := V4Addr{}
		copy(ip[:], v4NetIP)
		return ip
	}
	if v6NetIP := netIP.To16(); v6NetIP != nil {
		ip := V6Addr{}
		copy(ip[:], v6NetIP)
		return ip
	}
	return nil
}

func CIDRFromString(cidrStr string) (CIDR, error) {
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}
	return CIDRFromIPNet(cidr), nil
}

func CIDRFromCalicoNet(ipNet calinet.IPNet) CIDR {
	return CIDRFromIPNet(&ipNet.IPNet)
}

func CIDRsFromCalicoNets(ipNets []calinet.IPNet) []CIDR {
	cidrs := make([]CIDR, 0, len(ipNets))
	for _, ipNet := range ipNets {
		cidrs = append(cidrs, CIDRFromCalicoNet(ipNet))
	}
	return cidrs
}

func FromCalicoIP(ip calinet.IP) Addr {
	return FromNetIP(ip.IP)
}

// CIDRFromIPNet converts a *net.IPNet to a CIDR; if passed nil,
// returns nil.
func CIDRFromIPNet(ipNet *net.IPNet) CIDR {
	if ipNet == nil {
		return nil
	}
	ones, _ := ipNet.Mask.Size()
	// Mask the IP before creating the CIDR so that we have it in canonical format.
	ip := FromNetIP(ipNet.IP.Mask(ipNet.Mask))
	if ip.Version() == 4 {
		return V4CIDR{
			addr:   ip.(V4Addr),
			prefix: uint8(ones),
		}
	} else {
		return V6CIDR{
			addr:   ip.(V6Addr),
			prefix: uint8(ones),
		}
	}
}

// CIDRFromAddrAndPrefix.
func CIDRFromAddrAndPrefix(addr Addr, prefixLen int) CIDR {
	netIP := addr.AsNetIP()
	ipNet := net.IPNet{
		IP:   netIP,
		Mask: net.CIDRMask(prefixLen, len(netIP)*8),
	}
	return CIDRFromIPNet(&ipNet)
}

// CIDRFromNetIP converts the given IP into our CIDR representation as a /32 or /128.
func CIDRFromNetIP(netIP net.IP) CIDR {
	return FromNetIP(netIP).AsCIDR()
}

// MustParseCIDROrIP parses the given IP address or CIDR, treating IP addresses as "full length"
// CIDRs.  For example, "10.0.0.1" is treated as "10.0.0.1/32".  It panics on failure.
func MustParseCIDROrIP(s string) CIDR {
	cidr, err := ParseCIDROrIP(s)
	if err != nil {
		log.WithError(err).WithField("cidr", s).Panic("Failed to parse CIDR")
	}
	return cidr
}

// ParseCIDROrIP parses the given IP address or CIDR, treating IP addresses as "full length"
// CIDRs.  For example, "10.0.0.1" is treated as "10.0.0.1/32".
func ParseCIDROrIP(s string) (CIDR, error) {
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, ErrInvalidIP
		}
		return CIDRFromNetIP(ip), nil
	}
	_, netCIDR, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return CIDRFromIPNet(netCIDR), nil
}

func IPNetsEqual(net1, net2 *net.IPNet) bool {
	if net1 == nil && net2 == nil {
		// Both are nil, therefore equal.
		return true
	}
	if net1 == nil || net2 == nil {
		// Only one is nil, therefore not equal.
		return false
	}
	return CIDRFromIPNet(net1) == CIDRFromIPNet(net2)
}

func ParseIPAs16Byte(ip string) (ipb [16]byte, ok bool) {
	ipn := net.ParseIP(ip)
	if ipn != nil {
		ok = true
		copy(ipb[:], ipn.To16())
	}
	return
}
