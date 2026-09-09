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
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/header"
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
		return apiutil.NewListOrStreamResponse[Response]().SetStatus(http.StatusOK).SendList(apiutil.ListMeta{TotalPages: 20}, []Response{
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

	type ListMetadata struct {
		TotalPages int `json:"totalPages"`
	}

	type ListResponse struct {
		Items []Response   `json:"items"`
		Total ListMetadata `json:"total"`
	}

	Expect(testutil.MustUnmarshal[ListResponse](t, w.Body.Bytes())).To(Equal(&ListResponse{
		Items: []Response{
			{RespField: "foo"},
			{RespField: "bar"},
		},
		Total: ListMetadata{
			TotalPages: 20,
		},
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
		return apiutil.NewListOrStreamResponse[Response]().SetStatus(http.StatusOK).SendStream(func(yield func(r Response) bool) {
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

func TestJSONErrorResponse(t *testing.T) {
	setupTest(t)

	type Request struct {
		ReqField string `urlQuery:"reqField"`
	}
	type Response struct {
		RespField string `json:"rspField"`
	}

	hdlr := apiutil.NewJSONListOrEventStreamHandler(func(ctx apicontext.Context, params Request) apiutil.ListOrStreamResponse[Response] {
		return apiutil.NewListOrStreamResponse[Response]().
			SetStatus(http.StatusInternalServerError).
			SetError("Internal Server Error")
	})

	w := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "foobar", nil)
	Expect(err).NotTo(HaveOccurred())

	values := r.URL.Query()
	values.Set("reqField", "value")
	r.URL.RawQuery = values.Encode()

	hdlr.ServeHTTP(apiutil.NewNOOPRouterConfig(), w, r)

	Expect(w.Code).To(Equal(http.StatusInternalServerError))
	Expect(testutil.MustUnmarshal[apiutil.ErrorResponse](t, w.Body.Bytes())).To(Equal(&apiutil.ErrorResponse{
		Error: "Internal Server Error",
	}))
}

func TestJSONListErrorResponse(t *testing.T) {
	setupTest(t)

	type Request struct {
		ReqField string `urlQuery:"reqField"`
	}
	type Response struct {
		RespField string `json:"rspField"`
	}

	hdlr := apiutil.NewJSONListHandler(func(ctx apicontext.Context, params Request) apiutil.ListResponse[Response] {
		return apiutil.NewListResponse[Response]().
			SetStatus(http.StatusInternalServerError).
			SetError("Internal Server Error")
	})

	w := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "foobar", nil)
	Expect(err).NotTo(HaveOccurred())

	values := r.URL.Query()
	values.Set("reqField", "value")
	r.URL.RawQuery = values.Encode()

	hdlr.ServeHTTP(apiutil.NewNOOPRouterConfig(), w, r)

	Expect(w.Code).To(Equal(http.StatusInternalServerError))
	Expect(testutil.MustUnmarshal[apiutil.ErrorResponse](t, w.Body.Bytes())).To(Equal(&apiutil.ErrorResponse{
		Error: "Internal Server Error",
	}))
}

// TestResponseContentType covers every response declaring its content type. The
// header has to be set before the status is written: once WriteHeader has run,
// net/http ignores later header changes and sniffs the body instead, labelling
// a large JSON body text/plain. Reading it back off Result rather than Header is
// what makes the ordering observable.
func TestResponseContentType(t *testing.T) {
	setupTest(t)

	type Request struct {
		ReqField string `urlQuery:"reqField"`
		Page     int    `urlQuery:"page"`
	}
	type Response struct {
		RespField string `json:"rspField"`
	}

	list := apiutil.NewJSONListOrEventStreamHandler(func(ctx apicontext.Context, params Request) apiutil.ListOrStreamResponse[Response] {
		return apiutil.NewListOrStreamResponse[Response]().SetStatus(http.StatusOK).
			SendList(apiutil.ListMeta{TotalPages: 1}, []Response{{RespField: "foo"}})
	})
	stream := apiutil.NewJSONListOrEventStreamHandler(func(ctx apicontext.Context, params Request) apiutil.ListOrStreamResponse[Response] {
		return apiutil.NewListOrStreamResponse[Response]().SetStatus(http.StatusOK).
			SendStream(func(yield func(r Response) bool) { yield(Response{RespField: "foo"}) })
	})
	streamErr := apiutil.NewJSONListOrEventStreamHandler(func(ctx apicontext.Context, params Request) apiutil.ListOrStreamResponse[Response] {
		return apiutil.NewListOrStreamResponse[Response]().SetStatus(http.StatusBadRequest).SetError("bad request")
	})
	listErr := apiutil.NewJSONListHandler(func(ctx apicontext.Context, params Request) apiutil.ListResponse[Response] {
		return apiutil.NewListResponse[Response]().SetStatus(http.StatusInternalServerError).SetError("internal server error")
	})

	for _, tc := range []struct {
		name        string
		serve       func(cfg apiutil.RouterConfig, w http.ResponseWriter, r *http.Request)
		query       string
		contentType string
	}{
		{"json list", list.ServeHTTP, "reqField=value", header.ApplicationJSON},
		{"json error", streamErr.ServeHTTP, "reqField=value", header.ApplicationJSON},
		{"json list handler error", listErr.ServeHTTP, "reqField=value", header.ApplicationJSON},
		// A request the handler never sees, answered by the decoder.
		{"request decoding error", list.ServeHTTP, "page=notanumber", header.ApplicationJSON},
		{"event stream", stream.ServeHTTP, "reqField=value", header.TextEventStream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r, err := http.NewRequest(http.MethodGet, "foobar?"+tc.query, nil)
			Expect(err).NotTo(HaveOccurred())

			tc.serve(apiutil.NewNOOPRouterConfig(), w, r)

			Expect(w.Result().Header.Get(header.ContentType)).To(Equal(tc.contentType),
				"the content type must be set before the status is written")
		})
	}
}
