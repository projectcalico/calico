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
	"github.com/projectcalico/calico/goldmane/proto"
)

// flowMatches returns true if the flow matches the request.
func flowMatches(f *proto.Flow, req *proto.FlowRequest) bool {
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
func mergeFlowInto(a, b *proto.Flow) {
	// Merge in statistics.
	a.PacketsIn += b.PacketsIn
	a.PacketsOut += b.PacketsOut
	a.BytesIn += b.BytesIn
	a.BytesOut += b.BytesOut
	a.NumConnectionsStarted += b.NumConnectionsStarted
	a.NumConnectionsCompleted += b.NumConnectionsCompleted
	a.NumConnectionsLive += b.NumConnectionsLive

	// TODO: Update Start/End times.

	// TODO: Merge labels.
}
