// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package clientv3

import (
	"fmt"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// benchPools builds a non-overlapping set of pools, the first count of them marked allocatable and
// the rest left unmarked, which is the shape that decides how many overlap lookups run.
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

func benchmarkSelect(b *testing.B, total, marked int) {
	pools := benchPools(total, marked)
	for i := 0; i < b.N; i++ {
		selectAllocatablePools(pools, 4)
	}
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
