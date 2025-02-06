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
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/codec"
	apicontext "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/header"
)

func NewBasicJSONHandler[RequestParams any, Body any](f func(apicontext.Context, RequestParams) ResponseType[Body]) handler {
	return genericJSONHandler[RequestParams, Body]{f: f}
}

// genericJSONHandler is a handler that accepts either no body or a json body in the request and response with a json
// object. If the api needs to accept lists of objects or respond with them then this is not suitable, use something like
// ndJSONReqRespHandler or ndJSONRespHandler.
type genericJSONHandler[RequestParams any, Body any] struct {
	f func(apicontext.Context, RequestParams) ResponseType[Body]
}

func (g genericJSONHandler[RequestParams, Response]) ServeHTTP(cfg RouterConfig, w http.ResponseWriter, req *http.Request) {
	ctx := apicontext.NewRequestContext(req)

	params := parseRequestParams[RequestParams](ctx, cfg, w, req)
	if params == nil {
		return
	}

	rsp := g.f(ctx, *params)
	if len(rsp.error) > 0 {
		writeJSONError(w, rsp.status, rsp.error)
	} else {
		w.WriteHeader(rsp.status)
		writeJSONResponse(w, rsp.body)
	}
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

type listOrStreamHandler[RequestParams any, Body any] struct {
	f func(apicontext.Context, RequestParams) ListOrStreamResponse[Body]
}

func (l listOrStreamHandler[RequestParams, Body]) ServeHTTP(cfg RouterConfig, w http.ResponseWriter, req *http.Request) {
	ctx := apicontext.NewRequestContext(req)

	params := parseRequestParams[RequestParams](ctx, cfg, w, req)
	if params == nil {
		return
	}

	rsp := l.f(ctx, *params)
	if len(rsp.error) > 0 {
		writeJSONError(w, rsp.status, rsp.error)
	} else {
		if rsp.body.Streamer != nil {
			w.Header().Set(header.ContentType, header.TextEventStream)
			w.Header().Set(header.CacheControl, header.NoCache)
			w.Header().Set(header.Connection, header.KeepAlive)

			// TODO Remove this.
			w.Header().Set(header.AccessControlAllowOrigin, "*")

			jStream := newJSONStreamWriter[Body](w)
			for flow := range rsp.body.Streamer.Stream {
				if err := jStream.WriteData(flow); err != nil {
					ctx.Logger().WithError(err).Debug("Failed to write flow to stream.")
					return
				}
			}
		} else {
			w.WriteHeader(rsp.status)
			writeJSONResponse(w, rsp.body.Lister)
		}
	}
}

func NewListOrStreamResponseHandler[RequestParams any, Body any](f func(apicontext.Context, RequestParams) ListOrStreamResponse[Body]) handler {
	return listOrStreamHandler[RequestParams, Body]{
		f: f,
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
