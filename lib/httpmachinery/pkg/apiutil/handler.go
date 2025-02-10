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

package apiutil

import (
	"encoding/json"
	"iter"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/codec"
	apicontext "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/header"
)

// listOrStreamHandler is a handler that responds with either a json list or a server side event stream.
type genericHandler[RequestParams any, Body any] struct {
	f func(apicontext.Context, RequestParams) responseType
}

type responseType interface {
	Status() int
	ResponseWriter() ResponseWriter
}

// NewListOrEventStreamHandler creates a handler that response with a json list or a server side event stream.
func NewListOrEventStreamHandler[RequestParams any, ResponseBody any](f func(apicontext.Context, RequestParams) ListOrStreamResponse[ResponseBody]) handler {
	return genericHandler[RequestParams, ResponseBody]{
		f: func(ctx apicontext.Context, params RequestParams) responseType {
			return f(ctx, params)
		},
	}
}

func (l genericHandler[RequestParams, Body]) ServeHTTP(cfg RouterConfig, w http.ResponseWriter, req *http.Request) {
	ctx := apicontext.NewRequestContext(req)

	params := parseRequestParams[RequestParams](ctx, cfg, w, req)
	if params == nil {
		return
	}

	rsp := l.f(ctx, *params)
	w.WriteHeader(rsp.Status())
	if err := rsp.ResponseWriter().WriteResponse(ctx, w); err != nil {
		logrus.WithError(err).Error("failed to write response")
		writeJSONError(w, http.StatusInternalServerError, "Internal Server Error")
	}
}

func parseRequestParams[RequestParams any](ctx apicontext.Context, cfg RouterConfig, w http.ResponseWriter, req *http.Request) *RequestParams {
	params, err := codec.DecodeAndValidateRequestParams[RequestParams](ctx, cfg.URLVars, req)
	if err != nil {
		ctx.Logger().WithError(err).Debug("Failed to decode request params.")
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return nil
	}

	return params
}

func writeJSONResponse(w http.ResponseWriter, src any) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	if err := json.NewEncoder(w).Encode(src); err != nil {
		logrus.WithError(err).Error("Failed to encode response.")
	}
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	writeJSONResponse(w, ErrorResponse{Error: message})
}

type ResponseWriter interface {
	WriteResponse(apicontext.Context, http.ResponseWriter) error
}

// eventStreamResponseWriter is used to respond with a server side event stream.
type eventStreamResponseWriter[Body any] struct {
	items iter.Seq[Body]
}

func (rs *eventStreamResponseWriter[Body]) WriteResponse(ctx apicontext.Context, w http.ResponseWriter) error {
	w.Header().Set(header.ContentType, header.TextEventStream)
	w.Header().Set(header.CacheControl, header.NoCache)
	w.Header().Set(header.Connection, header.KeepAlive)
	w.Header().Set(header.AccessControlAllowOrigin, "localhost")

	jStream := newJSONEventStreamWriter[Body](w)
	for item := range rs.items {
		if err := jStream.writeData(item); err != nil {
			ctx.Logger().WithError(err).Debug("Failed to write flow to stream.")
			return err
		}
	}

	return nil
}

// jsonListResponseWriter is used to write by a json list that contains the total.
type jsonListResponseWriter[Body any] struct {
	items List[Body]
}

func (rs *jsonListResponseWriter[Body]) WriteResponse(ctx apicontext.Context, w http.ResponseWriter) error {
	writeJSONResponse(w, rs.items)
	return nil
}

// jsonErrorResponseWriter is used to respond with a json error.
type jsonErrorResponseWriter struct {
	error string
}

func (rs *jsonErrorResponseWriter) WriteResponse(ctx apicontext.Context, w http.ResponseWriter) error {
	writeJSONResponse(w, ErrorResponse{Error: rs.error})
	return nil
}
