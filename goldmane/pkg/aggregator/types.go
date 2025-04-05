package aggregator

import (
	"github.com/projectcalico/calico/goldmane/pkg/aggregator/bucketing"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

type FlowRing = bucketing.BucketRing[*FlowBucketMeta, *types.FlowKey, *types.Flow, types.FlowKey, types.Flow]
type FlowBucket = bucketing.Bucket[*FlowBucketMeta, *types.FlowKey, *types.Flow, types.FlowKey, types.Flow]
type DiachronicFlow = bucketing.Diachronic[types.FlowKey, *types.Flow, types.Flow]

// listRequest is an internal helper used to synchronously request matching flows from the aggregator.
type listRequest struct {
	respCh chan *listResponse
	req    *proto.FlowListRequest
}

type filterHintsRequest struct {
	respCh chan *filterHintsResponse
	req    *proto.FilterHintsRequest
}

type listResponse struct {
	results *proto.FlowListResult
	err     error
}

type filterHintsResponse struct {
	results *proto.FilterHintsResult
	err     error
}

type streamRequest struct {
	respCh chan *Stream
	req    *proto.FlowStreamRequest
}

type sinkRequest struct {
	sink Sink
	done chan struct{}
}
