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
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	apictx "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

type flowsHdlr struct {
	flowCli client.FlowServiceClient
}

func NewFlows(cli client.FlowServiceClient) *flowsHdlr {
	return &flowsHdlr{cli}
}

func (hdlr *flowsHdlr) APIs() []apiutil.Endpoint {
	return []apiutil.Endpoint{
		{
			Method:  http.MethodGet,
			Path:    whiskerv1.FlowsPath,
			Handler: apiutil.NewJSONListOrEventStreamHandler(hdlr.ListOrStream),
		},
	}
}

// ListOrStream sends back a list of flows or a stream, depending on whether the "Watch" flag is sent in the parameters.
func (hdlr *flowsHdlr) ListOrStream(ctx apictx.Context, params whiskerv1.ListFlowsParams) apiutil.ListOrStreamResponse[whiskerv1.FlowResponse] {
	logger := ctx.Logger()
	logger.Debug("List flows called.")

	// TODO Apply filters.
	if params.Watch {
		logger.Debug("Watch is set, streaming flows...")
		// TODO figure out how we're going to handle errors.
		flowStream, err := hdlr.flowCli.Stream(ctx, &proto.FlowStreamRequest{})
		if err != nil {
			logger.WithError(err).Error("failed to stream flows")
			return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse](http.StatusInternalServerError).SetError("Internal Server Error")
		}

		return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse](http.StatusOK).
			SendStream(func(yield func(flow whiskerv1.FlowResponse) bool) {
				for {
					flow, err := flowStream.Recv()
					if err == io.EOF {
						logger.Debug("EOF received, breaking stream.")
						return
					} else if err != nil {
						logger.WithError(err).Error("Failed to stream flows.")
						break
					}

					logrus.WithField("flow", flow).Debug("Received flow from stream.")
					if !yield(protoToFlow(flow.Flow)) {
						return
					}
				}
			})
	} else {
		logger.Debug("Watch not set, will return a list of flows.")
		flowReq := &proto.FlowListRequest{}
		if !params.StartTimeGt.IsZero() {
			flowReq.StartTimeGt = params.StartTimeGt.Unix()
		}

		if !params.StartTimeLt.IsZero() {
			flowReq.StartTimeLt = params.StartTimeLt.Unix()
		}

		if params.SortBy != whiskerv1.ListFlowsSortByDefault {
			// TODO figure out if we should panic or something if there's a mismatch between the sort by types.
			// TODO This wouldn't be a bad thing to do, since the params.SortBy value can't contain invalid values (the request
			// TODO fails if it does).
			switch params.SortBy {
			case whiskerv1.ListFlowsSortByDest:
				flowReq.SortBy = []*proto.SortOption{{SortBy: proto.SortBy_DestName}}
			}
		}
		flows, err := hdlr.flowCli.List(ctx, flowReq)
		if err != nil {
			logger.WithError(err).Error("failed to list flows")
			return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse](http.StatusInternalServerError).SetError("Internal Server Error")
		}

		var rspFlows []whiskerv1.FlowResponse
		for _, flow := range flows {
			rspFlows = append(rspFlows, protoToFlow(flow.Flow))
		}

		// TODO Use the total in the goldmane response when goldmane starts sending the number of items back.
		return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse](http.StatusOK).SendList(len(rspFlows), rspFlows)
	}
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
