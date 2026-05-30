// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	apictx "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

type flowsHdlr struct {
	backend whiskerv1.FlowsBackend
}

func NewFlows(backend whiskerv1.FlowsBackend) *flowsHdlr {
	return &flowsHdlr{backend: backend}
}

func (hdlr *flowsHdlr) APIs() []apiutil.Endpoint {
	return []apiutil.Endpoint{
		{
			Method:  http.MethodGet,
			Path:    whiskerv1.FlowsPath,
			Handler: apiutil.NewJSONListOrEventStreamHandler(hdlr.ListOrStream),
		},
		{
			Method:  http.MethodGet,
			Path:    whiskerv1.FlowsFilterHintsPath,
			Handler: apiutil.NewJSONListHandler(hdlr.ListFilterHints),
		},
	}
}

func (hdlr *flowsHdlr) ListOrStream(ctx apictx.Context, params whiskerv1.ListFlowsParams) apiutil.ListOrStreamResponse[whiskerv1.FlowResponse] {
	logger := ctx.Logger()
	logger.Debug("List flows called.")

	logger.Debug("Applying filters.")

	if params.Watch {
		logger.Debug("Watch is set, streaming flows...")

		flowStream, err := hdlr.backend.Stream(ctx, params)
		if err != nil {
			logger.WithError(err).Error("failed to stream flows")
			return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse]().SetStatus(http.StatusInternalServerError).SetError("Internal Server Error")
		}

		return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse]().SetStatus(http.StatusOK).
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

					logger.Debug("Received flow from stream.")
					if !yield(*flow) {
						return
					}
				}
			})
	}

	logger.Debug("Watch not set, will return a list of flows.")

	totalPages, flows, err := hdlr.backend.List(ctx, params)
	if err != nil {
		logger.WithError(err).Error("failed to list flows")
		return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse]().SetStatus(http.StatusInternalServerError).SetError("Internal Server Error")
	}

	return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse]().SetStatus(http.StatusOK).
		SendList(apiutil.ListMeta{TotalPages: totalPages}, flows)
}

func (hdlr *flowsHdlr) ListFilterHints(ctx apictx.Context, params whiskerv1.FlowFilterHintsRequest) apiutil.ListResponse[whiskerv1.FlowFilterHintResponse] {
	logger := ctx.Logger()
	logger.Debug("ListFilterHints called.")

	totalPages, hints, err := hdlr.backend.FilterHints(ctx, params)
	if err != nil {
		logger.WithError(err).Error("failed to list filter hints")
		return apiutil.NewListResponse[whiskerv1.FlowFilterHintResponse]().
			SetStatus(http.StatusInternalServerError).
			SetError("Internal Server Error")
	}

	return apiutil.NewListResponse[whiskerv1.FlowFilterHintResponse]().
		SetStatus(http.StatusOK).
		SetMeta(apiutil.ListMeta{TotalPages: totalPages}).
		SetItems(hints)
}
