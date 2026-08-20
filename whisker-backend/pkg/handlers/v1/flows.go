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
	"github.com/projectcalico/calico/whisker-backend/pkg/auth"
)

type flowsHdlr struct {
	backend       whiskerv1.FlowsBackend
	filterFactory auth.FlowFilterFactory
}

func NewFlows(backend whiskerv1.FlowsBackend, opts ...FlowsOption) *flowsHdlr {
	h := &flowsHdlr{backend: backend}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

type FlowsOption func(*flowsHdlr)

func WithFlowFilterFactory(f auth.FlowFilterFactory) FlowsOption {
	return func(h *flowsHdlr) {
		h.filterFactory = f
	}
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

// ListOrStream sends back a list of flows or a stream, depending on whether the "Watch" flag is sent in the parameters.
func (hdlr *flowsHdlr) ListOrStream(ctx apictx.Context, params whiskerv1.ListFlowsParams) apiutil.ListOrStreamResponse[whiskerv1.FlowResponse] {
	logger := ctx.Logger()
	logger.Debug("List flows called.")

	// Do not log filter objects or flow objects — they may contain user identifiers and
	// flow metadata that could be a bulk-exfil vector.
	logger.Debug("Applying filters.")

	if params.Watch {
		logger.Debug("Watch is set, streaming flows...")
		// TODO figure out how we're going to handle errors.

		// Streaming is optional. Backends that cannot stream (e.g. Linseed)
		// implement only FlowsBackend; reject the watch request with a clear
		// error instead of a generic 500.
		streamer, ok := hdlr.backend.(whiskerv1.StreamingFlowsBackend)
		if !ok {
			logger.Debug("Watch requested but the configured upstream does not support streaming.")
			return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse]().SetStatus(http.StatusBadRequest).SetError("Streaming is not supported by the configured flow upstream")
		}

		flowStream, err := streamer.Stream(ctx, params)
		if err != nil {
			logger.Error("failed to stream flows", "error", err)
			return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse]().SetStatus(http.StatusInternalServerError).SetError("Internal Server Error")
		}

		flowStream, err = auth.FilterStreamFromUser(ctx, flowStream, hdlr.filterFactory)
		if err != nil {
			logger.Error("failed to create RBAC flow filter", "error", err)
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
						logger.Error("Failed to stream flows.", "error", err)
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
		logger.Error("failed to list flows", "error", err)
		return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse]().SetStatus(http.StatusInternalServerError).SetError("Internal Server Error")
	}

	flows, err = auth.FilterFlowsFromUser(ctx, flows, hdlr.filterFactory)
	if err != nil {
		logger.Error("failed to filter flows by RBAC", "error", err)
		return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse]().SetStatus(http.StatusInternalServerError).SetError("Internal Server Error")
	}

	// A single-page result the RBAC filter emptied is no pages at all —
	// backends already report 0 for an empty result, and the UI must not be
	// told there is a page to render with nothing in it. Multi-page counts are
	// left alone: they are real pagination state from the backend.
	if len(flows) == 0 && totalPages == 1 {
		totalPages = 0
	}

	return apiutil.NewListOrStreamResponse[whiskerv1.FlowResponse]().SetStatus(http.StatusOK).
		SendList(apiutil.ListMeta{TotalPages: totalPages}, flows)
}

// ListFilterHints returns a list of filter hints. This provides filter values for various filters that will produce
// results (i.e. there are actually flows the match a filter with the returned values).
func (hdlr *flowsHdlr) ListFilterHints(ctx apictx.Context, params whiskerv1.FlowFilterHintsRequest) apiutil.ListResponse[whiskerv1.FlowFilterHintResponse] {
	logger := ctx.Logger()
	logger.Debug("ListFilterHints called.")

	// Hints are derived from an unscoped, cluster-wide query. Gate the source
	// flows by the same RBAC check used for List, so a namespace-scoped user
	// can't read back names / namespaces / policies from namespaces they cannot
	// list.
	includeFlow, err := auth.FilterFuncFromUser(ctx, hdlr.filterFactory)
	if err != nil {
		logger.Error("failed to create RBAC flow filter", "error", err)
		return apiutil.NewListResponse[whiskerv1.FlowFilterHintResponse]().
			SetStatus(http.StatusInternalServerError).
			SetError("Internal Server Error")
	}

	totalPages, hints, err := hdlr.backend.FilterHints(ctx, params, includeFlow)
	if err != nil {
		logger.Error("failed to list filter hints", "error", err)
		return apiutil.NewListResponse[whiskerv1.FlowFilterHintResponse]().
			SetStatus(http.StatusInternalServerError).
			SetError("Internal Server Error")
	}

	return apiutil.NewListResponse[whiskerv1.FlowFilterHintResponse]().
		SetStatus(http.StatusOK).
		SetMeta(apiutil.ListMeta{TotalPages: totalPages}).
		SetItems(hints)
}
