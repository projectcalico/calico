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

package server

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

// Health is for liveness and readiness probes
type Health struct {
	http         *http.Server
	httpServeMux *http.ServeMux
}

// NewHealth returns a new health and instantiates the handlers.
func NewHealth() (*Health, error) {
	health := &Health{
		http:         new(http.Server),
		httpServeMux: http.NewServeMux(),
	}
	health.http.Addr = ":9080"
	health.http.Handler = health.httpServeMux

	// Both readiness and liveness should both be healthy. In other words, if the endpoints
	// are accessible, the service is live and ready.
	health.httpServeMux.HandleFunc("/health", func(resp http.ResponseWriter, req *http.Request) {
		log.Trace("GET /health")

		if _, err := resp.Write([]byte("OK")); err != nil {
			log.WithError(err).Error("failed to write /health response")
		}
	})

	return health, nil
}

// ListenAndServeHTTP starts to listen and serve HTTP requests
func (h *Health) ListenAndServeHTTP() error {
	log.Infof("Starting Health server at %s", h.http.Addr)
	return h.http.ListenAndServe()
}
