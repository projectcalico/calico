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

// NumReservedIPsInCIDR returns how many of the addresses in cidr the given
// IPReservations cover, whether or not they are also allocated.  An address
// covered twice is counted once.
//
// GetUtilization reports this alongside the allocated and free counts, but doing so
// costs a list of every allocation block.  This is for callers that already hold the
// resources — kube-controllers gets them from its syncer — and need only this
// number.
func NumReservedIPsInCIDR(cidr cnet.IPNet, reservations []*v3.IPReservation) (int, error) {
	n, err := NumReservedIPsInCIDRBig(cidr, reservations)
	if err != nil {
		return 0, err
	}
	return ClampToInt(n), nil
}

// NumReservedIPsInCIDRBig is NumReservedIPsInCIDR without the saturation. A
// caller comparing the count against the size of the CIDR needs it: an IPv6
// pool holds more addresses than an int, so a reservation covering all of one
// clamps to a number smaller than the pool and reads as partial cover.
func NumReservedIPsInCIDRBig(cidr cnet.IPNet, reservations []*v3.IPReservation) (*big.Int, error) {
	return countReserved(cidr, ReservationCIDRs(reservations))
}

// ReservedIPs answers whether one address is reserved, over the same set
// NumReservedIPsInCIDR counts. A caller holding both the allocations and the
// reservations needs this to tell an allocated address that is also reserved
// from one that is not: the two counts overlap, so they cannot be added.
type ReservedIPs struct {
	set *netipx.IPSet
}

// NewReservedIPs builds the reserved set once, for repeated Contains calls.
func NewReservedIPs(reservations []*v3.IPReservation) (*ReservedIPs, error) {
	return newReservedIPs(ReservationCIDRs(reservations))
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

// Contains is whether no allocation can use ip. A nil ReservedIPs reserves
// nothing, so a caller that could not read the reservations is not told an
// address is free when it may not be.
func (r *ReservedIPs) Contains(ip net.IP) bool {
	if r == nil || r.set == nil {
		return false
	}
	addr, ok := netipx.FromStdIP(ip)
	if !ok {
		return false
	}
	return r.set.Contains(addr)
}

// containsAddr is Contains for an address the caller already holds as a netip.Addr.
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

func (r *ReservedIPs) ipSet() *netipx.IPSet {
	if r == nil || r.set == nil {
		return &netipx.IPSet{}
	}
	return r.set
}

// countReserved is NumReservedIPsInCIDRBig over CIDRs already resolved from the reservations.
func countReserved(cidr cnet.IPNet, reserved []cnet.IPNet) (*big.Int, error) {
	prefix, err := PrefixFromCIDR(cidr.IPNet)
	if err != nil {
		return nil, err
	}
	assignable, err := SubtractReserved(prefix, reserved).IPSet()
	if err != nil {
		return nil, err
	}
	return new(big.Int).Sub(NumIPsInPrefix(prefix), NumIPsInSet(assignable)), nil
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

// SubtractReserved returns the part of prefix that no reservation covers.
//
// Reservations may overlap and nest arbitrarily — one IPReservation can cover a /24
// while another names a single address inside it — so this has to be a set operation
// rather than a sum over the CIDRs.  Subtracting a prefix splits whatever it partly
// overlaps and repeats are no-ops, so the set needs no deduplication of our own.
func SubtractReserved(prefix netip.Prefix, reserved []cnet.IPNet) *netipx.IPSetBuilder {
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

// PrefixFromCIDR converts a CIDR to a netip.Prefix, failing when it has no prefix form.
func PrefixFromCIDR(cidr net.IPNet) (netip.Prefix, error) {
	p, ok := toPrefix(cidr)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("CIDR %s cannot be represented as a prefix", cidr.String())
	}
	return p, nil
}

// NumIPsInSet counts the addresses in s, as a big.Int because an IPv6 set overflows an int.
func NumIPsInSet(s *netipx.IPSet) *big.Int {
	total := big.NewInt(0)
	for _, p := range s.Prefixes() {
		total.Add(total, NumIPsInPrefix(p))
	}
	return total
}

// NumIPsInPrefix counts the addresses in p.
func NumIPsInPrefix(p netip.Prefix) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
}

// ClampToInt saturates rather than wrapping.  Real pools are far smaller than
// this — IPv6 pools are /96 or longer — so it is purely defensive: it keeps the
// conversion to the int fields of BlockUtilization and PoolUtilization total,
// instead of turning an oversized count negative.
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
