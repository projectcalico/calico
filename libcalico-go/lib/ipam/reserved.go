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

package ipam

import (
	"fmt"
	"math"
	"math/big"
	"net"
	"net/netip"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	"go4.org/netipx"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// NumReservedIPsInCIDR returns how many of the addresses in cidr the given
// IPReservations cover, whether or not they are also allocated.
//
// GetUtilization reports this alongside the allocated and free counts, but doing so
// costs a list of every allocation block.  This is for callers that already hold the
// IPReservations — kube-controllers gets them from its syncer — and need only this
// number.
func NumReservedIPsInCIDR(cidr cnet.IPNet, reservations []*v3.IPReservation) (int, error) {
	prefix, err := prefixFromCIDR(cidr.IPNet)
	if err != nil {
		return 0, err
	}

	assignable, err := subtractReservations(prefix, reservedCIDRs(reservations)).IPSet()
	if err != nil {
		return 0, err
	}
	return clampToInt(new(big.Int).Sub(numIPsInPrefix(prefix), numIPsInSet(assignable))), nil
}

// countPoolSpace reports address counts for a whole IP pool CIDR, including the
// parts of it that no allocation block covers yet:
//
//   - capacity: how many IPs the pool CIDR holds;
//   - reserved: how many of those a reservation covers, whether or not they are
//     also allocated;
//   - availableOutsideBlocks: how many are neither reserved nor inside one of
//     the given blocks.  IPs inside a block are left to the caller, which has
//     the block's allocations and so can tell free from in-use.
func countPoolSpace(poolCIDR net.IPNet, reserved cidrSliceFilter, blocks []BlockUtilization) (capacity, reservedCount, availableOutsideBlocks int, err error) {
	poolPrefix, err := prefixFromCIDR(poolCIDR)
	if err != nil {
		return 0, 0, 0, err
	}
	assignable := subtractReservations(poolPrefix, reserved)

	// Clone before subtracting the blocks so we can measure the pool both with
	// and without them.  Clone drops errors accumulated so far, but they stay on
	// the original, which we check below.
	outsideBlocks := assignable.Clone()
	for _, b := range blocks {
		if p, ok := netipx.FromStdIPNet(&b.CIDR); ok {
			outsideBlocks.RemovePrefix(p)
		}
	}

	assignableSet, err := assignable.IPSet()
	if err != nil {
		return 0, 0, 0, err
	}
	outsideBlocksSet, err := outsideBlocks.IPSet()
	if err != nil {
		return 0, 0, 0, err
	}

	poolSize := numIPsInPrefix(poolPrefix)
	return clampToInt(poolSize),
		clampToInt(new(big.Int).Sub(poolSize, numIPsInSet(assignableSet))),
		clampToInt(numIPsInSet(outsideBlocksSet)),
		nil
}

// reservedCIDRs returns the CIDRs that the given IPReservations cover.  Malformed
// entries are logged and skipped; validation should prevent them.
func reservedCIDRs(reservations []*v3.IPReservation) cidrSliceFilter {
	var cidrs cidrSliceFilter
	for _, r := range reservations {
		for _, cidrStr := range r.Spec.ReservedCIDRs {
			cidrStr = strings.TrimSpace(cidrStr)
			if cidrStr == "" {
				continue
			}
			_, cidr, err := cnet.ParseCIDROrIP(cidrStr)
			if err != nil {
				log.WithError(err).WithFields(log.Fields{
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

// subtractReservations returns the part of prefix that no reservation covers.
//
// Reservations may overlap and nest arbitrarily — one IPReservation can cover a /24
// while another names a single address inside it — so this has to be a set operation
// rather than a sum over the CIDRs.  Subtracting a prefix splits whatever it partly
// overlaps and repeats are no-ops, so the set needs no deduplication of our own.
func subtractReservations(prefix netip.Prefix, reserved cidrSliceFilter) *netipx.IPSetBuilder {
	var assignable netipx.IPSetBuilder
	assignable.AddPrefix(prefix)
	for _, r := range reserved {
		if p, ok := netipx.FromStdIPNet(&r.IPNet); ok {
			assignable.RemovePrefix(p)
		} else {
			log.WithField("cidr", r.String()).Warn("Ignoring reservation that cannot be represented as a prefix.")
		}
	}
	return &assignable
}

func prefixFromCIDR(cidr net.IPNet) (netip.Prefix, error) {
	p, ok := netipx.FromStdIPNet(&cidr)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("CIDR %s cannot be represented as a prefix", cidr.String())
	}
	return p, nil
}

func numIPsInSet(s *netipx.IPSet) *big.Int {
	total := big.NewInt(0)
	for _, p := range s.Prefixes() {
		total.Add(total, numIPsInPrefix(p))
	}
	return total
}

func numIPsInPrefix(p netip.Prefix) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
}

// clampToInt saturates rather than wrapping.  Real pools are far smaller than
// this — IPv6 pools are /96 or longer — so it is purely defensive: it keeps the
// conversion to the int fields of BlockUtilization and PoolUtilization total,
// instead of turning an oversized count negative.
func clampToInt(n *big.Int) int {
	if !n.IsInt64() || n.Int64() > math.MaxInt {
		return math.MaxInt
	}
	return int(n.Int64())
}
