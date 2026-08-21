// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package clientv3

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/ip"
)

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

// masks reports whether the pool suppresses pools that overlap it, matching the trie the IP pool
// controller builds. A terminating pool masks because it holds blocks until they are released; a
// disabled one does not.
func masks(pool *v3.IPPool) bool {
	if pool.Spec.Disabled {
		return false
	}
	return isAllocatable(pool) || !pool.DeletionTimestamp.IsZero()
}

type poolCandidate struct {
	pool        *v3.IPPool
	cidr        ip.CIDR
	allocatable bool
}

// selectAllocatablePools returns the pools IPAM may allocate from. The IP pool controller resolves
// overlap asynchronously, so a pool it has not marked is usable only while nothing covers its CIDR.
func selectAllocatablePools(pools []v3.IPPool, ipVersion int) []v3.IPPool {
	candidates := make([]poolCandidate, 0, len(pools))
	maskers := ip.NewCIDRTrie()

	for i := range pools {
		pool := &pools[i]
		cidr, err := ip.CIDRFromString(pool.Spec.CIDR)
		if err != nil {
			logrus.Warnf("Failed to parse the IPPool: %s. Ignoring that IPPool", pool.Spec.CIDR)
			continue
		}
		if int(cidr.Version()) != ipVersion {
			logrus.Debugf("Ignoring IPPool: %s. IP version is different.", pool.Spec.CIDR)
			continue
		}
		if masks(pool) {
			maskers.Update(cidr, pool)
		}
		if selectable(pool) {
			candidates = append(candidates, poolCandidate{pool: pool, cidr: cidr, allocatable: isAllocatable(pool)})
		}
	}

	filtered := make([]v3.IPPool, 0, len(candidates))
	for _, c := range candidates {
		// The controller's verdict is taken as-is, so a marked pool never tests itself.
		if !c.allocatable && maskers.Overlaps(c.cidr) {
			logrus.Debugf("Skipping IP pool (%s) overlapped by an allocatable pool", c.pool.Name)
			continue
		}
		filtered = append(filtered, *c.pool)
	}
	return filtered
}
