// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package v1

import (
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	"net/http"
	"strings"
	"time"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/goldmane/proto"
	apictx "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

type flowsHdlr struct {
	flowCli client.FlowRetrieverClient
}

func NewFlows(cli client.FlowRetrieverClient) *flowsHdlr {
	return &flowsHdlr{cli}
}

func (hdlr *flowsHdlr) APIs() []apiutil.Endpoint {
	return []apiutil.Endpoint{
		{
			Method:  http.MethodGet,
			Path:    whiskerv1.FlowsPath,
			Handler: apiutil.NewJSONListResponseHandler(hdlr.List),
		},
		{
			Method:  http.MethodGet,
			Path:    whiskerv1.FlowsStreamPath,
			Handler: apiutil.NewJSONEventStreamHandler(hdlr.Stream),
		},
	}
}

func (hdlr *flowsHdlr) List(ctx apictx.Context, params whiskerv1.ListFlowsParams) apiutil.ListResponse[whiskerv1.FlowResponse] {
	logger := ctx.Logger()
	logger.Debug("List flows called.")

	flowReq := &proto.FlowRequest{}
	if !params.StartTimeGt.IsZero() {
		flowReq.StartTimeGt = params.StartTimeGt.Unix()
	}

	if !params.StartTimeLt.IsZero() {
		flowReq.StartTimeLt = params.StartTimeLt.Unix()
	}

	flows, err := hdlr.flowCli.List(ctx, flowReq)
	if err != nil {
		logger.WithError(err).Error("failed to list flows")
		return apiutil.NewListResponse[whiskerv1.FlowResponse](500).SetErrorMsg("Internal Server Error")
	}

	var rspFlows []whiskerv1.FlowResponse
	for _, flow := range flows {
		rspFlows = append(rspFlows, protoToFlow(flow))
	}

	return apiutil.NewListResponse[whiskerv1.FlowResponse](http.StatusOK).SetItems(rspFlows)
}

func (hdlr *flowsHdlr) Stream(ctx apictx.Context, params whiskerv1.StreamFlowsParams, rspStream apiutil.EventStream[whiskerv1.FlowResponse]) {
	logger := ctx.Logger()
	logger.Debug("Stream flows called.")

	// TODO figure out how we're going to handle errors.
	flowStream, err := hdlr.flowCli.Stream(ctx, &proto.FlowRequest{})
	if err != nil {
		logger.WithError(err).Error("failed to stream flows")
		return
	}

	for {
		flow, err := flowStream.Recv()
		if err != nil {
			logger.WithError(err).Error("failed to stream flows")
			break
		}

		if err := rspStream.Data(protoToFlow(flow)); err != nil {
			logger.WithError(err).Error("failed to write flow response")
			return
		}
	}

	return
}

func protoToFlow(flow *proto.Flow) whiskerv1.FlowResponse {
	return whiskerv1.FlowResponse{
		StartTime: time.Unix(flow.StartTime, 0),
		EndTime:   time.Unix(flow.EndTime, 0),
		Action:    flow.Key.Action,

		SourceName:      flow.Key.SourceName,
		SourceNamespace: flow.Key.SourceNamespace,
		SourceLabels:    strings.Join(flow.SourceLabels, " | "),

		DestName:      flow.Key.DestName,
		DestNamespace: flow.Key.DestNamespace,
		DestLabels:    strings.Join(flow.DestLabels, " | "),

		Protocol:   flow.Key.Proto,
		DestPort:   flow.Key.DestPort,
		Reporter:   flow.Key.Reporter,
		PacketsIn:  flow.PacketsIn,
		PacketsOut: flow.PacketsOut,
		BytesIn:    flow.BytesIn,
		BytesOut:   flow.PacketsIn,
	}
}
