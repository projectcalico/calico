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
	flowCli client.FlowsClient
}

func NewFlows(cli client.FlowsClient) *flowsHdlr {
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

	logrus.WithField("filter", params.Filters).Debug("Applying filters.")
	filter := proto.Filter{
		SourceNames:      toProtoStringMatches(params.Filters.SourceNames),
		SourceNamespaces: toProtoStringMatches(params.Filters.SourceNamespaces),
		DestNames:        toProtoStringMatches(params.Filters.DestNames),
		DestNamespaces:   toProtoStringMatches(params.Filters.DestNamespaces),
		Protocols:        toProtoStringMatches(params.Filters.Protocols),
		DestPorts:        toProtoPorts(params.Filters.DestPorts),
		Actions:          toProtoActions(params.Filters.Actions),
	}

	if params.Watch {
		logger.Debug("Watch is set, streaming flows...")
		// TODO figure out how we're going to handle errors.
		flowReq := &proto.FlowStreamRequest{
			Filter:       &filter,
			StartTimeGte: params.StartTimeGte,
		}

		flowStream, err := hdlr.flowCli.Stream(ctx, flowReq)
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

		flowReq := &proto.FlowListRequest{
			SortBy:       toProtoSortBy(params.SortBy),
			Filter:       &filter,
			StartTimeGte: params.StartTimeGte,
			StartTimeLt:  params.StartTimeLt,
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

func toProtoStringMatches(matches []whiskerv1.FilterMatch[string]) []*proto.StringMatch {
	var protos []*proto.StringMatch
	for _, match := range matches {
		protos = append(protos, &proto.StringMatch{
			Value: match.V,
			Type:  toProtoMatchType(match.Type),
		})
	}

	return protos
}

func toProtoActions(actions []whiskerv1.Action) []proto.Action {
	var protos []proto.Action
	for _, action := range actions {
		protos = append(protos, toProtoAction(action))
	}

	return protos
}

func toProtoPorts(matches []whiskerv1.FilterMatch[int64]) []*proto.PortMatch {
	var protos []*proto.PortMatch
	for _, match := range matches {
		protos = append(protos, &proto.PortMatch{
			Port: match.V,
		})
	}

	return protos
}

func toProtoAction(action whiskerv1.Action) proto.Action {
	switch action {
	case whiskerv1.ActionAllow:
		return proto.Action_Allow
	case whiskerv1.ActionDeny:
		return proto.Action_Deny
	case whiskerv1.ActionPass:
		return proto.Action_Pass
	default:
		panic("Unknown action")
	}
}

func toProtoMatchType(t whiskerv1.MatchType) proto.MatchType {
	switch t {
	case whiskerv1.MatchTypeExact:
		return proto.MatchType_Exact
	case whiskerv1.MatchTypeFuzzy:
		return proto.MatchType_Fuzzy
	default:
		panic("Unknown match type")
	}
}

func toProtoSortBy(sortBys []whiskerv1.ListFlowsSortBy) []*proto.SortOption {
	var opts []*proto.SortOption
	for _, sortBy := range sortBys {
		switch sortBy {
		case whiskerv1.ListFlowsSortByDestName:
			opts = append(opts, &proto.SortOption{SortBy: proto.SortBy_DestName})
		case whiskerv1.ListFlowsSortBySrcName:
			opts = append(opts, &proto.SortOption{SortBy: proto.SortBy_SourceName})
		}
	}

	return opts
}

func protoToFlow(flow *proto.Flow) whiskerv1.FlowResponse {
	action := ""
	switch flow.Key.Action {
	case proto.Action_ActionUnspecified:
		// This shouldn't happen, but strictly is part of the API.
	default:
		action = strings.ToLower(flow.Key.Action.String())
	}

	reporter := ""
	switch flow.Key.Reporter {
	case proto.Reporter_ReporterUnspecified:
		// This shouldn't happen, but strictly is part of the API.
	default:
		reporter = strings.ToLower(flow.Key.Reporter.String())
	}
	return whiskerv1.FlowResponse{
		StartTime: time.Unix(flow.StartTime, 0),
		EndTime:   time.Unix(flow.EndTime, 0),
		Action:    whiskerv1.Action(action),

		SourceName:      flow.Key.SourceName,
		SourceNamespace: flow.Key.SourceNamespace,
		SourceLabels:    strings.Join(flow.SourceLabels, " | "),

		DestName:      flow.Key.DestName,
		DestNamespace: flow.Key.DestNamespace,
		DestLabels:    strings.Join(flow.DestLabels, " | "),

		Protocol:   flow.Key.Proto,
		DestPort:   flow.Key.DestPort,
		Reporter:   reporter,
		PacketsIn:  flow.PacketsIn,
		PacketsOut: flow.PacketsOut,
		BytesIn:    flow.BytesIn,
		BytesOut:   flow.PacketsIn,
	}
}
