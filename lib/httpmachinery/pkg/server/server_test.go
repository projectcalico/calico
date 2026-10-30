// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package server_test

import (
	"net/http"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/server"
)

// recordingRouter captures what NewHTTPServer hands its router.
type recordingRouter struct {
	apis       []apiutil.Endpoint
	middleware []apiutil.MiddlewareFunc
}

func (r *recordingRouter) RegisterAPIs(apis []apiutil.Endpoint, middleware ...apiutil.MiddlewareFunc) http.Handler {
	r.apis = apis
	r.middleware = middleware
	return http.NotFoundHandler()
}

// Server-wide middleware is useless unless the server passes it to the router,
// which is the whole path between WithMiddleware and a wrapped endpoint.
func TestWithMiddlewareReachesTheRouter(t *testing.T) {
	RegisterTestingT(t)

	first := apiutil.MiddlewareFunc(func(next http.Handler) http.Handler { return next })
	second := apiutil.MiddlewareFunc(func(next http.Handler) http.Handler { return next })

	router := &recordingRouter{}
	_, err := server.NewHTTPServer(router, nil,
		server.WithAddr("127.0.0.1:0"),
		server.WithMiddleware(first),
		server.WithMiddleware(second),
	)
	Expect(err).NotTo(HaveOccurred())

	// Both calls contribute, in the order given, so a caller can add middleware
	// from more than one place.
	Expect(router.middleware).To(HaveLen(2))
}

func TestNoMiddlewareByDefault(t *testing.T) {
	RegisterTestingT(t)

	router := &recordingRouter{}
	_, err := server.NewHTTPServer(router, nil, server.WithAddr("127.0.0.1:0"))
	Expect(err).NotTo(HaveOccurred())
	Expect(router.middleware).To(BeEmpty())
}
