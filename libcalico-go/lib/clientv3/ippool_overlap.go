// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package clientv3

import (
	"bytes"
	"slices"
	"sort"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// cidrRange is a CIDR flattened to an inclusive address range. Addresses are left-aligned and
// zero-padded, so a set of ranges must hold a single IP version.
type cidrRange struct {
	lo [16]byte
	hi [16]byte

	// maxHi is the greatest hi among this range and all earlier ones. One lookup then covers
	// every range starting before a candidate.
	maxHi [16]byte
}

func newCIDRRange(n cnet.IPNet) cidrRange {
	ip := n.IP.To4()
	if ip == nil {
		ip = n.IP.To16()
	}

	// A v4 address can carry a 16-byte mask, so trim the mask to the address width.
	mask := n.Mask
	if len(mask) > len(ip) {
		mask = mask[len(mask)-len(ip):]
	}

	var r cidrRange
	for i := range ip {
		r.lo[i] = ip[i] & mask[i]
		r.hi[i] = r.lo[i] | ^mask[i]
	}
	return r
}

// maskingRanges holds the CIDRs of pools that suppress overlapping pools, sorted by start address.
type maskingRanges []cidrRange

// overlaps reports whether any masking range intersects c. Prefixes are aligned blocks, so only
// the first range starting at or after c matters, plus anything earlier via maxHi.
func (m maskingRanges) overlaps(c cidrRange) bool {
	i := sort.Search(len(m), func(k int) bool {
		return bytes.Compare(m[k].lo[:], c.lo[:]) >= 0
	})
	if i < len(m) && bytes.Compare(m[i].lo[:], c.hi[:]) <= 0 {
		return true
	}
	return i > 0 && bytes.Compare(m[i-1].maxHi[:], c.lo[:]) >= 0
}

// index sorts the ranges and records the running prefix maximum used by overlaps.
func (m maskingRanges) index() {
	slices.SortFunc(m, func(a, b cidrRange) int {
		return bytes.Compare(a.lo[:], b.lo[:])
	})

	var maxHi [16]byte
	for i := range m {
		if bytes.Compare(m[i].hi[:], maxHi[:]) > 0 {
			maxHi = m[i].hi
		}
		m[i].maxHi = maxHi
	}
}

func isAllocatable(pool *v3.IPPool) bool {
	if pool.Status == nil {
		return false
	}
	for _, condition := range pool.Status.Conditions {
		if condition.Type == v3.IPPoolConditionAllocatable {
			return condition.Status == metav1.ConditionTrue
		}
	}
	return false
}

// selectable reports whether IPAM may allocate from the pool, before overlap is considered.
func selectable(pool *v3.IPPool) bool {
	if !pool.DeletionTimestamp.IsZero() {
		logrus.Debugf("Skipping deleting IP pool (%s)", pool.Name)
		return false
	}
	if pool.Spec.Disabled {
		logrus.Debugf("Skipping disabled IP pool (%s)", pool.Name)
		return false
	}
	if pool.Status == nil {
		return true
	}
	for _, condition := range pool.Status.Conditions {
		if condition.Type == v3.IPPoolConditionAllocatable && condition.Status == metav1.ConditionFalse {
			logrus.Debugf("Skipping IP pool (%s) with condition Allocatable=false", pool.Name)
			return false
		}
	}
	return true
}

type poolCandidate struct {
	pool        *v3.IPPool
	rng         cidrRange
	allocatable bool
}

// selectAllocatablePools returns the pools IPAM may allocate from. The IP pool controller resolves
// overlap asynchronously, so a pool it has not marked is usable only while nothing covers its CIDR.
func selectAllocatablePools(pools []v3.IPPool, ipVersion int) []v3.IPPool {
	candidates := make([]poolCandidate, 0, len(pools))
	maskers := make(maskingRanges, 0, len(pools))

	// One parse per pool feeds both the masking set and the candidate list.
	for i := range pools {
		pool := &pools[i]
		_, cidr, err := cnet.ParseCIDR(pool.Spec.CIDR)
		if err != nil {
			logrus.Warnf("Failed to parse the IPPool: %s. Ignoring that IPPool", pool.Spec.CIDR)
			continue
		}
		if cidr.Version() != ipVersion {
			logrus.Debugf("Ignoring IPPool: %s. IP version is different.", pool.Spec.CIDR)
			continue
		}
		rng := newCIDRRange(*cidr)
		allocatable := isAllocatable(pool)

		// A pool masks overlaps once marked allocatable, and while it is being deleted, since it
		// holds blocks until they are released. Administratively disabled pools do not mask.
		if allocatable || !pool.DeletionTimestamp.IsZero() {
			maskers = append(maskers, rng)
		}
		if selectable(pool) {
			candidates = append(candidates, poolCandidate{pool: pool, rng: rng, allocatable: allocatable})
		}
	}
	maskers.index()

	filtered := make([]v3.IPPool, 0, len(candidates))
	for _, c := range candidates {
		// The controller's verdict is taken as-is, so a marked pool never tests itself.
		if !c.allocatable && maskers.overlaps(c.rng) {
			logrus.Debugf("Skipping IP pool (%s) overlapped by an allocatable pool", c.pool.Name)
			continue
		}
		filtered = append(filtered, *c.pool)
	}
	return filtered
}
