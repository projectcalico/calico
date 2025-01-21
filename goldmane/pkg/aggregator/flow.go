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
	if req.StartTimeGt == 0 && req.StartTimeLt == 0 {
		return true
	}

	for _, stat := range f.DiscreteStatistics {
		if (req.StartTimeGt > 0 && stat.StartTime > req.StartTimeGt) && (req.StartTimeLt > 0 && stat.StartTime < req.StartTimeLt) {
			return true
		}
	}

	return true
}

// mergeFlowInto merges flow b into flow a.
func mergeFlowInto(a, b *types.Flow) {
	// Merge in statistics.
	var existing *types.Statistics
	for _, stat := range a.DiscreteStatistics {
		if stat.StartTime == b.DiscreteStatistics[0].StartTime {
			existing = stat
			break
		}
	}

	if existing != nil {
		existing.PacketsIn += b.DiscreteStatistics[0].PacketsIn
		existing.PacketsOut += b.DiscreteStatistics[0].PacketsOut
		existing.BytesIn += b.DiscreteStatistics[0].BytesIn
		existing.BytesOut += b.DiscreteStatistics[0].BytesOut
		existing.NumConnectionsStarted += b.DiscreteStatistics[0].NumConnectionsStarted
		existing.NumConnectionsCompleted += b.DiscreteStatistics[0].NumConnectionsCompleted
		existing.NumConnectionsLive += b.DiscreteStatistics[0].NumConnectionsLive
	} else {
		a.DiscreteStatistics = append(a.DiscreteStatistics, b.DiscreteStatistics[0])
	}

	// TODO handle merging labels when we want to grab them.
	//// To merge labels, we include the intersection of the labels from both flows.
	//// This means the resulting aggregated flow will have all the labels common to
	//// its component flows.
	//a.SourceLabels = intersection(a.SourceLabels, b.SourceLabels)
	//a.DestLabels = intersection(a.DestLabels, b.DestLabels)
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
