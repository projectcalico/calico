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

// This files contains handler implementations to decode requests and encode responses. They provide easier to use interfaces
// to developers creating APIs. For instance, if you get a handler from the NewJSONListOrEventStreamHandler you can
// stream the objects with a server side event stream just by returning ListOrStreamResponse with an iterator set, i.e.
//
// 	return apiutil.NewListOrStreamResponse[ResponseType](http.StatusOK).
//		SendStream(func(yield func(flow ResponseType) bool) {
//			for _, obj := range responseList {
//				if !yield(obj) {
//					return
//				}
//			}
//		})
//
// You don't need to worry about handling the http response code or even knowing anything about the Server Side Event
// stream syntax.
//
// Similarly, you don't need to decode any requests, you just provide the object type with the appropriate takes, i.e.
//	type ParameterType struct {
//		// ID is a parameter in the path, like /resources/{id}/subresources. The `urlPath` tag tells the decoder that this
//		// is a path parameter.
//		ID string `urlPath:"id" validate:"required"`
//		// Watch is a query parameter, like /resources/{id}/subresources?watch. The `urlQuery` tag tells the decoder that
//		// this is a query parameter
//		Watch bool `urlQuery:"watch"`
// 		// XCustomerHeader is a header in the request. The `header` tag tells the decoder that the value for this field
//		// is in the headers, under the name 'X-Customer-Header'.
//		XCustomerHeader bool `header:"X-Customer-Header"`
//	}

package apiutil

import (
	"encoding/json"
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

// NewJSONListOrEventStreamHandler creates a handler that response with a json list or a server side event stream.
func NewJSONListOrEventStreamHandler[RequestParams any, ResponseBody any](f func(apicontext.Context, RequestParams) ListOrStreamResponse[ResponseBody]) handler {
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
	if err := rsp.ResponseWriter().WriteResponse(ctx, rsp.Status(), w); err != nil {
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
