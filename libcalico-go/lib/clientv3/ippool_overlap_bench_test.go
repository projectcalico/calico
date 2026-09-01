// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package clientv3

import (
	"fmt"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// benchPools builds a non-overlapping set of pools, the first marked of them carrying the
// Allocatable condition, which is the shape that decides how many overlap lookups run.
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

var benchResult []v3.IPPool

func benchmarkSelect(b *testing.B, total, marked int) {
	pools := benchPools(total, marked)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchResult = selectAllocatablePools(pools, 4)
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
