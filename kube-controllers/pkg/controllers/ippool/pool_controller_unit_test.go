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

package ippool

import (
	"slices"
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPoolSortFunc(t *testing.T) {
	now := time.Now()

	makePool := func(name string, createdAt time.Time, condition *metav1.Condition, deleting bool) *v3.IPPool {
		p := &v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name:              name,
				CreationTimestamp: metav1.NewTime(createdAt),
			},
		}
		if deleting {
			ts := metav1.NewTime(now)
			p.DeletionTimestamp = &ts
		}
		if condition != nil {
			p.Status = &v3.IPPoolStatus{
				Conditions: []metav1.Condition{*condition},
			}
		}
		return p
	}

	allocatable := &metav1.Condition{
		Type:   v3.IPPoolConditionAllocatable,
		Status: metav1.ConditionTrue,
		Reason: v3.IPPoolReasonOK,
	}
	disabled := &metav1.Condition{
		Type:   v3.IPPoolConditionAllocatable,
		Status: metav1.ConditionFalse,
		Reason: v3.IPPoolReasonCIDROverlap,
	}

	tests := []struct {
		name     string
		pools    []*v3.IPPool
		expected []string // expected order of pool names after sorting
	}{
		{
			name: "active pools sort before disabled pools",
			pools: []*v3.IPPool{
				makePool("disabled-pool", now.Add(-1*time.Minute), disabled, false),
				makePool("active-pool", now, allocatable, false),
			},
			expected: []string{"active-pool", "disabled-pool"},
		},
		{
			name: "active pools sort before terminating pools",
			pools: []*v3.IPPool{
				makePool("terminating-pool", now.Add(-1*time.Minute), allocatable, true),
				makePool("active-pool", now, allocatable, false),
			},
			expected: []string{"active-pool", "terminating-pool"},
		},
		{
			name: "terminating pools sort before disabled pools",
			pools: []*v3.IPPool{
				makePool("disabled-pool", now.Add(-2*time.Minute), disabled, false),
				makePool("terminating-pool", now.Add(-1*time.Minute), allocatable, true),
			},
			expected: []string{"terminating-pool", "disabled-pool"},
		},
		{
			name: "terminating pool with Allocatable=False still sorts before disabled pools",
			pools: []*v3.IPPool{
				makePool("disabled-pool", now.Add(-2*time.Minute), disabled, false),
				makePool("terminating-pool", now.Add(-1*time.Minute), disabled, true),
			},
			expected: []string{"terminating-pool", "disabled-pool"},
		},
		{
			name: "within same category, older pools sort first",
			pools: []*v3.IPPool{
				makePool("newer-pool", now, allocatable, false),
				makePool("older-pool", now.Add(-1*time.Minute), allocatable, false),
			},
			expected: []string{"older-pool", "newer-pool"},
		},
		{
			name: "same category and timestamp sorts by name",
			pools: []*v3.IPPool{
				makePool("pool-b", now, allocatable, false),
				makePool("pool-a", now, allocatable, false),
			},
			expected: []string{"pool-a", "pool-b"},
		},
		{
			name: "new pool with no condition sorts as active",
			pools: []*v3.IPPool{
				makePool("disabled-pool", now.Add(-1*time.Minute), disabled, false),
				makePool("new-pool", now, nil, false),
			},
			expected: []string{"new-pool", "disabled-pool"},
		},
		{
			name: "full scenario: active, terminating, and disabled pools",
			pools: []*v3.IPPool{
				makePool("disabled-2", now.Add(-1*time.Minute), disabled, false),
				makePool("active-pool", now.Add(-4*time.Minute), allocatable, false),
				makePool("disabled-1", now.Add(-2*time.Minute), disabled, false),
				makePool("terminating-pool", now.Add(-3*time.Minute), allocatable, true),
			},
			expected: []string{"active-pool", "terminating-pool", "disabled-1", "disabled-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to []any for the sort function.
			items := make([]any, len(tt.pools))
			for i, p := range tt.pools {
				items[i] = p
			}

			slices.SortFunc(items, poolSortFunc)

			got := make([]string, len(items))
			for i, item := range items {
				got[i] = item.(*v3.IPPool).Name
			}

			if len(got) != len(tt.expected) {
				t.Fatalf("expected %v, got %v", tt.expected, got)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Fatalf("expected %v, got %v", tt.expected, got)
				}
			}
		})
	}
}
