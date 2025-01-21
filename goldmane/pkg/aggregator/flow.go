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

package aggregator

import (
	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// flowMatches returns true if the flow matches the request.
func flowMatches(f *types.Flow, req *proto.FlowRequest) bool {
	// Check if the time range matches the flow's start time.
	if req.StartTimeGt > 0 && f.StartTime < req.StartTimeGt {
		return false
	}
	if req.StartTimeLt > 0 && f.StartTime > req.StartTimeLt {
		return false
	}
	return true
}

// mergeFlowInto merges flow b into flow a.
func mergeFlowInto(a, b *types.Flow) {
	// Merge in statistics.
	a.PacketsIn += b.PacketsIn
	a.PacketsOut += b.PacketsOut
	a.BytesIn += b.BytesIn
	a.BytesOut += b.BytesOut
	a.NumConnectionsStarted += b.NumConnectionsStarted
	a.NumConnectionsCompleted += b.NumConnectionsCompleted
	a.NumConnectionsLive += b.NumConnectionsLive

	// Update Start/End times, to indicate the full duration across all of the
	// component flows that have been merged into this aggregated one.
	if a.StartTime > b.StartTime {
		// The existing flow was present in a later (chronologically) bucket, we need to update the start time
		// of the flow to the start time of this (earlier chronologically) bucket.
		a.StartTime = b.StartTime
	}
	if a.EndTime < b.EndTime {
		// The existing flow was present in an earlier (chronologically) bucket, we need to update the end time
		// of the flow to the end time of this (later chronologically) bucket.
		a.EndTime = b.EndTime
	}

	// To merge labels, we include the intersection of the labels from both flows.
	// This means the resulting aggregated flow will have all the labels common to
	// its component flows.
	a.SourceLabels = intersection(a.SourceLabels, b.SourceLabels)
	a.DestLabels = intersection(a.DestLabels, b.DestLabels)
}

// intersection returns the intersection of two slices of strings. i.e., all the values that
// exist in both input slices.
func intersection(a, b []string) []string {
	labelsA := set.New[string]()
	labelsB := set.New[string]()
	intersection := set.New[string]()
	for _, v := range a {
		labelsA.Add(v)
	}
	for _, v := range b {
		labelsB.Add(v)
	}
	labelsA.Iter(func(l string) error {
		if labelsB.Contains(l) {
			intersection.Add(l)
		}
		return nil
	})
	return intersection.Slice()
}
