// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package clientv3

import (
	"fmt"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// benchPools builds a non-overlapping set of pools, the first marked count of them allocatable and
// the rest left unmarked, which is the shape that decides how much work selectAllocatablePools does.
func benchPools(total, marked int) []v3.IPPool {
	pools := make([]v3.IPPool, 0, total)
	for i := 0; i < total; i++ {
		cidr := fmt.Sprintf("10.%d.%d.0/26", i/256, i%256)
		status := metav1.ConditionStatus("")
		if i < marked {
			status = metav1.ConditionTrue
		}
		pools = append(pools, poolWithCondition(fmt.Sprintf("pool-%d", i), cidr, status))
	}
	return pools
}

// filterOnly is the selection this change replaces: a per-pool filter with no overlap handling.
func filterOnly(pools []v3.IPPool, ipVersion int) []v3.IPPool {
	var filtered []v3.IPPool
	for i := range pools {
		pool := &pools[i]
		if !pool.DeletionTimestamp.IsZero() || pool.Spec.Disabled {
			continue
		}
		skip := false
		if pool.Status != nil {
			for _, condition := range pool.Status.Conditions {
				if condition.Type == v3.IPPoolConditionAllocatable && condition.Status == metav1.ConditionFalse {
					skip = true
				}
			}
		}
		if skip {
			continue
		}
		if _, cidr, err := cnet.ParseCIDR(pool.Spec.CIDR); err != nil || cidr.Version() != ipVersion {
			continue
		}
		filtered = append(filtered, *pool)
	}
	return filtered
}

func benchmarkSelect(b *testing.B, total, marked int) {
	pools := benchPools(total, marked)
	b.Run("after", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			selectAllocatablePools(pools, 4)
		}
	})
	b.Run("before", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			filterOnly(pools, 4)
		}
	})
}

func BenchmarkSelectAllocatablePools_2500_AllMarked(b *testing.B) {
	benchmarkSelect(b, 2500, 2500)
}

func BenchmarkSelectAllocatablePools_2500_TenUnmarked(b *testing.B) {
	benchmarkSelect(b, 2500, 2490)
}

func BenchmarkSelectAllocatablePools_2500_HalfUnmarked(b *testing.B) {
	benchmarkSelect(b, 2500, 1250)
}
