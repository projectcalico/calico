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

// Package apiutil provides types and utilities for creating http APIs. It helps abstract out encoding and decoding request
// responses so that API creators can focus solely on the business logic and not the http logic. This is done mainly through
// the `Endpoint` and `handler` types.
//
// The `handler` types provide a generic type http handler for decoding requests and encoding the responses in various
// ways. The use of a handler passes it a function that accepts a struct type representing the request, and returns
// a struct type representing the response. The handle will decode the http request into the struct type the given
// function accepts, and will encode the returned struct into a http response.
//
// As an example, the `NewListOrEventStreamHandler` accepts a function with the definition
// `f func(apicontext.Context, RequestParams) ListOrStreamResponse[ResponseBody]`, where `RequestParams` and `ResponseBody`
// are generic types of `any`. The following example illustrates how to create a handler function for this handler type:
//
//		// API returns a list of Endpoint objects that define the API paths / methods and the handlers that implement
//		// the business logic.
//		func API() []apiutil.Endpoint {
//			return []apiutil.Endpoint{
//				{
//					Method:  http.MethodGet,
//					Path:    "/resources/{id}/subresources",
//					Handler: apiutil.NewListOrEventStreamHandler(ListOrStream),
//				},
//			}
//		}
//
//		type ParameterType struct {
//			// ID is a parameter in the path, like /resources/{id}/subresources. The `urlPath` tag tells the decoder that this
//			// is a path parameter.
//			ID string `urlPath:"id" validate:"required"`
//			// Watch is a query parameter, like /resources/{id}/subresources?watch. The `urlQuery` tag tells the decoder that
//			// this is a query parameter
//			Watch bool `urlQuery:"watch"`
//		}
//
//		type ResponseType struct {
//			ID    string `json:"requestID"`
//			Value string `json:"value"`
//		}
//
//		func (hdlr *ExampleHandler) ListOrStream(ctx apictx.Context, params ParameterType) apiutil.ListOrStreamResponse[ResponseType] {
//			logger := ctx.Logger()
//			logger.Debug("ListOrStream called.")
//			responseList := []ResponseType{
//				{ID: params.ID, Value: "value1"},
//				{ID: params.ID, Value: "value2"},
//				{ID: params.ID, Value: "value3"},
//			}
//
//			if params.Watch {
//				return apiutil.NewListOrStreamResponse[ResponseType](http.StatusOK).
//					SendStream(func(yield func(flow ResponseType) bool) {
//						for _, obj := range responseList {
//							if !yield(obj) {
//								return
//							}
//						}
//					})
//			} else {
//				return apiutil.NewListOrStreamResponse[ResponseType](http.StatusOK).SendList(len(responseList), responseList)
//			}
//		}
//
//	The tags on the ParameterType type tell the parameter decoder where to fine the values for the fields in the http
//	request. The apicontext.Context type provides extra context information about the request that's guaranteed to be
//	there if you have an instance of this object.
package apiutil
