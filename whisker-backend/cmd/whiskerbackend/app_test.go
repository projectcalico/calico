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

package whiskerbackend

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/klauspost/compress/zstd"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/compression"
	gorillaadpt "github.com/projectcalico/calico/lib/httpmachinery/pkg/server/adaptors/gorilla"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	v1mocks "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1/mocks"
	v1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

func TestWithMiddleware_AppliesToEveryEndpoint(t *testing.T) {
	RegisterTestingT(t)

	endpoints := v1.NewFlows(new(v1mocks.FlowsBackend)).APIs()
	Expect(endpoints).NotTo(BeEmpty())
	before := make([]int, len(endpoints))
	for i, ep := range endpoints {
		before[i] = len(ep.Middleware)
	}

	// Two markers stand in for authentication and cluster resolution; each
	// endpoint must gain both, after whatever it already declared.
	marker := apiutil.MiddlewareFunc(func(next http.Handler) http.Handler { return next })
	got := withMiddleware(endpoints, marker, marker)

	Expect(got).To(HaveLen(len(endpoints)))
	for i, ep := range got {
		Expect(ep.Middleware).To(HaveLen(before[i]+2), ep.Path)
	}
}

// TestFlowsResponseIsCompressed covers the whole path the compression
// middleware takes: through the router, over a real flows response. A page of
// flows repeats its field names on every record, which is why it is worth
// compressing at all.
func TestFlowsResponseIsCompressed(t *testing.T) {
	RegisterTestingT(t)

	flows := make([]whiskerv1.FlowResponse, 200)
	for i := range flows {
		flows[i] = whiskerv1.FlowResponse{SourceName: "client", DestName: "server", Protocol: "tcp"}
	}

	endpoints := v1.NewFlows(&staticFlowsBackend{flows: flows}).APIs()
	handler := gorillaadpt.NewRouter().RegisterAPIs(endpoints, compression.NewResponseCompressor())

	r := httptest.NewRequest(http.MethodGet, "/flows", nil)
	r.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	rsp := w.Result()
	Expect(rsp.StatusCode).To(Equal(http.StatusOK))
	Expect(rsp.Header.Get("Content-Encoding")).To(Equal("zstd"),
		"a browser offering zstd should be served zstd")

	compressed, err := io.ReadAll(rsp.Body)
	Expect(err).NotTo(HaveOccurred())

	zr, err := zstd.NewReader(bytes.NewReader(compressed))
	Expect(err).NotTo(HaveOccurred())
	defer zr.Close()
	decoded, err := io.ReadAll(zr)
	Expect(err).NotTo(HaveOccurred())

	Expect(len(compressed)).To(BeNumerically("<", len(decoded)/10),
		"a page of flows should shrink by more than 10x")
	Expect(string(decoded)).To(ContainSubstring(`"source_name":"client"`))
}

// staticFlowsBackend serves a fixed page of flows.
type staticFlowsBackend struct {
	whiskerv1.FlowsBackend

	flows []whiskerv1.FlowResponse
}

func (b *staticFlowsBackend) List(context.Context, whiskerv1.ListFlowsParams) (int, []whiskerv1.FlowResponse, error) {
	return 1, b.flows, nil
}
