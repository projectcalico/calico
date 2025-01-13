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
