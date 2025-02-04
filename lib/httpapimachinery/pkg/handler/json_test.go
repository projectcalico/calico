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

package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"

	_ctx "github.com/projectcalico/calico/lib/httpapimachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/handler"
)

func TestJSONListResponse(t *testing.T) {
	setupTest(t)

	type Request struct {
		ReqField string `urlQuery:"reqField"`
	}
	type Response struct {
		RespField string `json:"rspField"`
	}

	hdlr := handler.NewJSONListResponseHandler(func(ctx _ctx.Context, params Request) handler.ListResponse[Response] {
		Expect(params.ReqField).To(Equal("value"))
		return handler.NewListResponse[Response](http.StatusOK).SetTotal(20).SetItems([]Response{
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

	hdlr.ServeHTTP(w, r)

	type ListResponse struct {
		Items []Response `json:"items"`
		Total int        `json:"total"`
	}

	Expect(mustUnmarshal[ListResponse](w.Body.Bytes())).To(Equal(&ListResponse{
		Items: []Response{
			{RespField: "foo"},
			{RespField: "bar"},
		},
		Total: 20,
	}))
}
