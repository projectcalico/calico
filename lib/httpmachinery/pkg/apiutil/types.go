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

import "net/http"

// handler is an unexported http.Handler, used to force APIs to get the handler implementations from this package and
// implement missing handlers here. These handlers are responsible for reading the request, decoding them into concreate
// objects to pass to some "backend" handler, retrieves the response from the backend handlers and encodes the response
// properly. This abstracts out all http request / response handling logic from the backend implementation.
type handler http.Handler

// Endpoint represents a single endpoint in a http API. It contains the method and path to define the
// location for the of the endpoint, and a handler to handle the request.
//
// The Handler provide must be one from this package, which allows you to specific a backend.
//
// Optional middleware can be configured for the endpoint, and it will run after any middleware defined for the API.
type Endpoint struct {
	Method     string
	Path       string
	Handler    handler
	Middleware []Middleware
}

type MiddlewareFunc func(http.Handler) http.Handler

func (mw MiddlewareFunc) Middleware(handler http.Handler) http.Handler {
	return mw(handler)
}

type Middleware interface {
	Middleware(handler http.Handler) http.Handler
}
