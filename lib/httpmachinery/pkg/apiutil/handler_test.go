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

package apiutil_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	apicontext "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/testutil"
)

func TestJSONListResponse(t *testing.T) {
	setupTest(t)

	type Request struct {
		ReqField string `urlQuery:"reqField"`
	}
	type Response struct {
		RespField string `json:"rspField"`
	}

	hdlr := apiutil.NewJSONListOrEventStreamHandler(func(ctx apicontext.Context, params Request) apiutil.ListOrStreamResponse[Response] {
		Expect(params.ReqField).To(Equal("value"))
		return apiutil.NewListOrStreamResponse[Response](http.StatusOK).SendList(20, []Response{
			{RespField: "foo"},
			{RespField: "bar"},
		})
	})

	w := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "foobar", nil)
	Expect(err).NotTo(HaveOccurred())

	values := r.URL.Query()
	values.Set("reqField", "value")
	r.URL.RawQuery = values.Encode()

	hdlr.ServeHTTP(apiutil.NewNOOPRouterConfig(), w, r)

	type ListResponse struct {
		Items []Response `json:"items"`
		Total int        `json:"total"`
	}

	Expect(testutil.MustUnmarshal[ListResponse](t, w.Body.Bytes())).To(Equal(&ListResponse{
		Items: []Response{
			{RespField: "foo"},
			{RespField: "bar"},
		},
		Total: 20,
	}))
}

func TestJSONStreamResponse(t *testing.T) {
	setupTest(t)

	type Request struct {
		ReqField string `urlQuery:"reqField"`
	}
	type Response struct {
		RespField string `json:"rspField"`
	}

	hdlr := apiutil.NewJSONListOrEventStreamHandler(func(ctx apicontext.Context, params Request) apiutil.ListOrStreamResponse[Response] {
		Expect(params.ReqField).To(Equal("value"))
		return apiutil.NewListOrStreamResponse[Response](http.StatusOK).SendStream(func(yield func(r Response) bool) {
			items := []Response{{RespField: "foo"}, {RespField: "bar"}}
			for _, item := range items {
				if !yield(item) {
					return
				}
			}
		})
	})

	w := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "foobar", nil)
	Expect(err).NotTo(HaveOccurred())

	values := r.URL.Query()
	values.Set("reqField", "value")
	r.URL.RawQuery = values.Encode()

	hdlr.ServeHTTP(apiutil.NewNOOPRouterConfig(), w, r)
	Expect(w.Body.String()).To(Equal("data: {\"rspField\":\"foo\"}\n\ndata: {\"rspField\":\"bar\"}\n\n"))
}
