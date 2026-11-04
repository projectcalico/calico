// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package accounting

import (
	"fmt"
	"math"
	"math/big"
	"net"
	"net/netip"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"go4.org/netipx"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// NumReservedIPsInCIDR returns how many addresses in cidr the reservations cover, allocated or not, counting overlaps
// once. It is for callers such as kube-controllers that already hold the reservations and list no blocks.
func NumReservedIPsInCIDR(cidr cnet.IPNet, reservations []*v3.IPReservation) (int, error) {
	n, err := NumReservedIPsInCIDRBig(cidr, reservations)
	if err != nil {
		return 0, err
	}
	return ClampToInt(n), nil
}

// NumReservedIPsInCIDRBig is NumReservedIPsInCIDR without the clamp, for comparing against an IPv6 CIDR's size.
func NumReservedIPsInCIDRBig(cidr cnet.IPNet, reservations []*v3.IPReservation) (*big.Int, error) {
	return countReserved(cidr, ReservationCIDRs(reservations))
}

// ReservedIPs is the reserved address set, built once for repeated lookups. A nil one reserves nothing.
type ReservedIPs struct {
	set *netipx.IPSet
}

// NewReservedIPs builds the set the given reservations cover.
func NewReservedIPs(reservations []*v3.IPReservation) (*ReservedIPs, error) {
	return newReservedIPs(ReservationCIDRs(reservations))
}

// Contains is whether no allocation can use ip.
func (r *ReservedIPs) Contains(ip net.IP) bool {
	addr, ok := netipx.FromStdIP(ip)
	return ok && r.containsAddr(addr)
}

func newReservedIPs(reserved []cnet.IPNet) (*ReservedIPs, error) {
	var b netipx.IPSetBuilder
	for _, r := range reserved {
		if p, ok := toPrefix(r.IPNet); ok {
			b.AddPrefix(p)
		} else {
			logrus.WithField("cidr", r.String()).Warn("Ignoring reservation that cannot be represented as a prefix.")
		}
	}
	s, err := b.IPSet()
	if err != nil {
		return nil, err
	}
	return &ReservedIPs{set: s}, nil
}

func (r *ReservedIPs) containsAddr(addr netip.Addr) bool {
	return r != nil && r.set != nil && r.set.Contains(addr)
}

// changedSince returns the addresses reserved in exactly one of r and old.
func (r *ReservedIPs) changedSince(old *ReservedIPs) (*netipx.IPSet, error) {
	var added, removed netipx.IPSetBuilder
	added.AddSet(r.ipSet())
	added.RemoveSet(old.ipSet())
	removed.AddSet(old.ipSet())
	removed.RemoveSet(r.ipSet())
	addedSet, err := added.IPSet()
	if err != nil {
		return nil, err
	}
	removed.AddSet(addedSet)
	return removed.IPSet()
}

// overlaps is whether any address in n is reserved.
func (r *ReservedIPs) overlaps(n net.IPNet) bool {
	p, ok := toPrefix(n)
	return ok && r.ipSet().OverlapsPrefix(p)
}

// countIn is how many addresses in cidr are reserved.
func (r *ReservedIPs) countIn(cidr net.IPNet) (*big.Int, error) {
	p, err := prefixFromCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var b netipx.IPSetBuilder
	b.AddPrefix(p)
	b.Intersect(r.ipSet())
	s, err := b.IPSet()
	if err != nil {
		return nil, err
	}
	return numIPsInSet(s), nil
}

func (r *ReservedIPs) ipSet() *netipx.IPSet {
	if r == nil || r.set == nil {
		return &netipx.IPSet{}
	}
	return r.set
}

// countReserved is NumReservedIPsInCIDRBig over CIDRs already resolved from the reservations.
func countReserved(cidr cnet.IPNet, reserved []cnet.IPNet) (*big.Int, error) {
	prefix, err := prefixFromCIDR(cidr.IPNet)
	if err != nil {
		return nil, err
	}
	assignable, err := subtractReserved(prefix, reserved).IPSet()
	if err != nil {
		return nil, err
	}
	return new(big.Int).Sub(numIPsInPrefix(prefix), numIPsInSet(assignable)), nil
}

// ReservationCIDRs returns the CIDRs that the given IPReservations cover.  Malformed
// entries are logged and skipped; validation should prevent them.
func ReservationCIDRs(reservations []*v3.IPReservation) []cnet.IPNet {
	var cidrs []cnet.IPNet
	for _, r := range reservations {
		for _, cidrStr := range r.Spec.ReservedCIDRs {
			cidrStr = strings.TrimSpace(cidrStr)
			if cidrStr == "" {
				continue
			}
			_, cidr, err := cnet.ParseCIDROrIP(cidrStr)
			if err != nil {
				logrus.WithError(err).WithFields(logrus.Fields{
					"reservation": r.Name,
					"cidr":        cidrStr,
				}).Error("Ignoring malformed CIDR in IPReservation.")
				continue
			}
			cidrs = append(cidrs, *cidr)
		}
	}
	return cidrs
}

// subtractReserved returns the part of prefix that no reservation covers. Reservations can overlap and nest, so this is
// a set subtraction rather than a sum over the CIDRs.
func subtractReserved(prefix netip.Prefix, reserved []cnet.IPNet) *netipx.IPSetBuilder {
	var assignable netipx.IPSetBuilder
	assignable.AddPrefix(prefix)
	for _, r := range reserved {
		if p, ok := toPrefix(r.IPNet); ok {
			assignable.RemovePrefix(p)
		} else {
			logrus.WithField("cidr", r.String()).Warn("Ignoring reservation that cannot be represented as a prefix.")
		}
	}
	return &assignable
}

// prefixFromCIDR converts a CIDR to a netip.Prefix, failing when it has no prefix form.
func prefixFromCIDR(cidr net.IPNet) (netip.Prefix, error) {
	p, ok := toPrefix(cidr)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("CIDR %s cannot be represented as a prefix", cidr.String())
	}
	return p, nil
}

// numIPsInSet counts the addresses in s, as a big.Int because an IPv6 set overflows an int.
func numIPsInSet(s *netipx.IPSet) *big.Int {
	total := big.NewInt(0)
	for _, p := range s.Prefixes() {
		total.Add(total, numIPsInPrefix(p))
	}
	return total
}

// numIPsInPrefix counts the addresses in p.
func numIPsInPrefix(p netip.Prefix) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
}

// ClampToInt converts n to an int, saturating at math.MaxInt rather than wrapping negative. Real pools are far smaller,
// so this is purely defensive.
func ClampToInt(n *big.Int) int {
	if !n.IsInt64() || n.Int64() > math.MaxInt {
		return math.MaxInt
	}
	return int(n.Int64())
}

// toPrefix converts n to a prefix. An IPv4-mapped IPv6 CIDR becomes the IPv4 prefix, which is how the allocator matches it.
func toPrefix(n net.IPNet) (netip.Prefix, bool) {
	if p, ok := netipx.FromStdIPNet(&n); ok && p.IsValid() {
		return p, true
	}
	ones, bits := n.Mask.Size()
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok || bits != 128 || ones < 96 || !addr.Is4In6() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr.Unmap(), ones-96).Masked(), true
}
