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
	statsCli client.StatisticsServiceClient
}

func NewStats(cli client.StatisticsServiceClient) *statsHandler {
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

func (hdlr *statsHandler) ListOrStream(ctx apictx.Context, params whiskerv1.StatisticsParams) apiutil.ListOrStreamResponse[whiskerv1.StatisticsResponse] {
	logger := ctx.Logger()
	logger.Debug("List statistics called.")

	// TODO Apply filters.
	req := &proto.StatisticsRequest{}
	if !params.StartTimeGt.IsZero() {
		req.StartTimeGt = params.StartTimeGt.Unix()
	}

	if !params.StartTimeLt.IsZero() {
		req.StartTimeLt = params.StartTimeLt.Unix()
	}

	stats, err := hdlr.statsCli.List(ctx, req)
	if err != nil {
		logger.WithError(err).Error("failed to list flows")
		return apiutil.NewListOrStreamResponse[whiskerv1.StatisticsResponse](http.StatusInternalServerError).SetError("Internal Server Error")
	}

	var resps []whiskerv1.StatisticsResponse
	for _, stat := range stats {
		resps = append(resps, protoToStats(stat))
	}

	// TODO Use the total in the goldmane response when goldmane starts sending the number of items back.
	return apiutil.NewListOrStreamResponse[whiskerv1.StatisticsResponse](http.StatusOK).SendList(len(resps), resps)
}

func protoToStats(s *proto.StatisticsResult) whiskerv1.StatisticsResponse {
	return whiskerv1.StatisticsResponse{}
}
