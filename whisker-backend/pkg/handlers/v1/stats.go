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
	"net/http"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	apictx "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

type statsHandler struct {
	statsCli client.StatisticsClient
}

func NewStats(cli client.StatisticsClient) *statsHandler {
	return &statsHandler{cli}
}

func (hdlr *statsHandler) APIs() []apiutil.Endpoint {
	return []apiutil.Endpoint{
		{
			Method:  http.MethodGet,
			Path:    whiskerv1.StatsPath,
			Handler: apiutil.NewJSONListOrEventStreamHandler(hdlr.ListOrStream),
		},
	}
}

func paramsToRequest(params whiskerv1.StatisticsParams) *proto.StatisticsRequest {
	req := &proto.StatisticsRequest{}

	req.StartTimeGt = params.StartTimeGt
	req.StartTimeLt = params.StartTimeLt

	if params.Type != "" {
		req.Type = proto.StatisticType(proto.StatisticType_value[params.Type])
	}
	if params.GroupBy != "" {
		req.GroupBy = proto.GroupBy(proto.GroupBy_value[params.GroupBy])
	}
	req.TimeSeries = params.TimeSeries

	// Filtering.
	if params.Namespace != "" ||
		params.Tier != "" ||
		params.Name != "" ||
		params.Action != "" ||
		params.Kind != "" {
		// If any of the above fields are set, we need to set the PolicyMatch field.
		req.PolicyMatch = &proto.PolicyMatch{}
	}
	if params.Namespace != "" {
		req.PolicyMatch.Namespace = params.Namespace
	}
	if params.Tier != "" {
		req.PolicyMatch.Tier = params.Tier
	}
	if params.Name != "" {
		req.PolicyMatch.Name = params.Name
	}
	if params.Action != "" {
		req.PolicyMatch.Action = params.Action
	}
	if params.Kind != "" {
		req.PolicyMatch.Kind = proto.PolicyKind(proto.PolicyKind_value[params.Kind])
	}
	return req
}

func (hdlr *statsHandler) ListOrStream(ctx apictx.Context, params whiskerv1.StatisticsParams) apiutil.ListOrStreamResponse[whiskerv1.StatisticsResponse] {
	logger := ctx.Logger()
	logger.Debug("List statistics called.")

	req := paramsToRequest(params)

	stats, err := hdlr.statsCli.List(ctx, req)
	if err != nil {
		logger.WithError(err).Error("failed to list statistics")
		return apiutil.NewListOrStreamResponse[whiskerv1.StatisticsResponse](http.StatusInternalServerError).SetError(err.Error())
	}

	var resps []whiskerv1.StatisticsResponse
	for _, stat := range stats {
		resps = append(resps, protoToStats(stat))
	}

	// TODO Use the total in the goldmane response when goldmane starts sending the number of items back.
	return apiutil.NewListOrStreamResponse[whiskerv1.StatisticsResponse](http.StatusOK).SendList(len(resps), resps)
}

func protoToStats(s *proto.StatisticsResult) whiskerv1.StatisticsResponse {
	return whiskerv1.StatisticsResponse{
		Policy:     protoToPolicyHit(s.Policy),
		GroupBy:    s.GroupBy.String(),
		Type:       s.Type.String(),
		Direction:  s.Direction.String(),
		AllowedIn:  s.AllowedIn,
		AllowedOut: s.AllowedOut,
		DeniedIn:   s.DeniedIn,
		DeniedOut:  s.DeniedOut,
		PassedIn:   s.PassedIn,
		PassedOut:  s.PassedOut,
		X:          s.X,
	}
}

func protoToPolicyHit(p *proto.PolicyHit) *whiskerv1.PolicyHit {
	if p == nil {
		return nil
	}

	return &whiskerv1.PolicyHit{
		Kind:        p.Kind.String(),
		Namespace:   p.Namespace,
		Name:        p.Name,
		Tier:        p.Tier,
		Action:      p.Action,
		PolicyIndex: p.PolicyIndex,
		RuleIndex:   p.RuleIndex,
		Trigger:     protoToPolicyHit(p.Trigger),
	}
}
