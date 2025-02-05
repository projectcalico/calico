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

	apicontext "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/header"
	"github.com/sirupsen/logrus"
)

func NewBasicJSONHandler[RequestParams any, Body any](f func(apicontext.Context, RequestParams) ResponseType[Body]) handler {
	return genericJSONHandler[RequestParams, Body]{f: f}
}

func NewJSONListResponseHandler[RequestParams any, Body any](f func(apicontext.Context, RequestParams) ListResponse[Body]) handler {
	return genericJSONHandler[RequestParams, List[Body]]{
		f: func(ctx apicontext.Context, r RequestParams) ResponseType[List[Body]] {
			return ResponseType[List[Body]](f(ctx, r))
		},
	}
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
	if len(rsp.errMsg) > 0 {
		writeJSONError(w, rsp.status, rsp.errMsg)
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
