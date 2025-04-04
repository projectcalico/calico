// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package old

import (
	"github.com/projectcalico/calico/goldmane/pkg/types"
)

// BucketRing is a ring buffer of aggregation buckets for efficient rollover.
type BucketRing struct {
	*FlowRing
}

func NewBucketRing(size, interval int, now int64, cleanupFunc func(*DiachronicFlow)) *BucketRing {
	ring := &BucketRing{
		FlowRing: NewRing[*FlowBucketMeta, *types.FlowKey, types.FlowMeta, *types.FlowMeta](
			size, interval, now,
			cleanupFunc,
			func() *FlowBucketMeta {
				return &FlowBucketMeta{
					stats: newStatisticsIndex(),
				}
			},
		),
	}

	return ring
}
