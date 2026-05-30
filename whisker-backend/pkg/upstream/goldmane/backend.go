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

package goldmane

import (
	"context"
	"io"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/goldmane/proto"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

var _ whiskerv1.FlowsBackend = &Backend{}

type Backend struct {
	cli client.FlowsClient
}

func NewBackend(cli client.FlowsClient) *Backend {
	return &Backend{cli: cli}
}

func (b *Backend) List(ctx context.Context, params whiskerv1.ListFlowsParams) (int, []whiskerv1.FlowResponse, error) {
	flowReq := &proto.FlowListRequest{
		SortBy:       toProtoSortByOptions(params.SortBy),
		Filter:       toProtoFilter(params.Filters),
		StartTimeGte: params.StartTimeGte,
		StartTimeLt:  params.StartTimeLt,
	}

	meta, flows, err := b.cli.List(ctx, flowReq)
	if err != nil {
		return 0, nil, err
	}

	var rspFlows []whiskerv1.FlowResponse
	for _, flow := range flows {
		rspFlows = append(rspFlows, protoToFlow(flow.Flow))
	}

	totalPages := 0
	if meta != nil {
		totalPages = int(meta.TotalPages)
	}
	return totalPages, rspFlows, nil
}

func (b *Backend) Stream(ctx context.Context, params whiskerv1.ListFlowsParams) (whiskerv1.FlowStream, error) {
	flowReq := &proto.FlowStreamRequest{
		Filter:       toProtoFilter(params.Filters),
		StartTimeGte: params.StartTimeGte,
	}

	stream, err := b.cli.Stream(ctx, flowReq)
	if err != nil {
		return nil, err
	}

	return &goldmaneFlowStream{stream: stream}, nil
}

func (b *Backend) FilterHints(ctx context.Context, params whiskerv1.FlowFilterHintsRequest) (int, []whiskerv1.FlowFilterHintResponse, error) {
	req := &proto.FilterHintsRequest{
		PageSize: int64(params.PageSize),
		Page:     int64(params.Page),
		Type:     params.Type.AsProto(),
		Filter:   toProtoFilter(params.Filters),
	}

	meta, gmhints, err := b.cli.FilterHints(ctx, req)
	if err != nil {
		return 0, nil, err
	}

	hints := make([]whiskerv1.FlowFilterHintResponse, len(gmhints))
	for i, hint := range gmhints {
		switch params.Type.AsProto() {
		case proto.FilterType_FilterTypeSourceNamespace, proto.FilterType_FilterTypeDestNamespace:
			hint.Value = protoToNamespace(hint.Value)
		case proto.FilterType_FilterTypeSourceName, proto.FilterType_FilterTypeDestName:
			hint.Value = protoToName(hint.Value)
		}
		hints[i] = whiskerv1.FlowFilterHintResponse{Value: hint.Value}
	}

	totalPages := 0
	if meta != nil {
		totalPages = int(meta.TotalPages)
	}
	return totalPages, hints, nil
}

type goldmaneFlowStream struct {
	stream proto.Flows_StreamClient
}

func (s *goldmaneFlowStream) Recv() (*whiskerv1.FlowResponse, error) {
	result, err := s.stream.Recv()
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, err
	}
	flow := protoToFlow(result.Flow)
	return &flow, nil
}
