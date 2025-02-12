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

package gorilla

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/server"
)

type registrar struct {
	router *mux.Router
}

func (g *registrar) RegisterAPIs(apis []apiutil.Endpoint, middlewares ...apiutil.MiddlewareFunc) http.Handler {
	config := apiutil.NewRouterConfig(mux.Vars)

	midFuncs := make([]mux.MiddlewareFunc, len(middlewares))
	for i, m := range middlewares {
		midFuncs[i] = m.Middleware
	}
	for _, api := range apis {
		subRouter := g.router.Methods(api.Method).Subrouter()
		subRouter.Handle(api.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.Handler.ServeHTTP(config, w, r)
		}))

		subRouter.Use(midFuncs...)

		for _, m := range api.Middleware {
			subRouter.Use(m.Middleware)
		}
	}

	return g.router
}

func NewRouter() server.Router {
	return &registrar{router: mux.NewRouter()}
}
