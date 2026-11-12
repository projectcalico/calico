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

package gorilla_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	apicontext "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/header"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/server/adaptors/gorilla"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/testutil"
)

type emptyParams struct{}

type item struct {
	Name string `json:"name"`
}

func newTestHandler() http.Handler {
	endpoint := apiutil.Endpoint{
		Method: http.MethodGet,
		Path:   "/things",
		Handler: apiutil.NewJSONListHandler(func(_ apicontext.Context, _ emptyParams) apiutil.ListResponse[item] {
			return apiutil.NewListResponse[item]().SetStatus(http.StatusOK).SetItems([]item{{Name: "a"}})
		}),
	}
	return gorilla.NewRouter().RegisterAPIs([]apiutil.Endpoint{endpoint})
}

func TestMethodNotAllowedWritesCodedErrorBody(t *testing.T) {
	RegisterTestingT(t)

	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodPost, "/things", nil)
	Expect(err).NotTo(HaveOccurred())
	newTestHandler().ServeHTTP(w, r)

	Expect(w.Code).To(Equal(http.StatusMethodNotAllowed))
	Expect(w.Result().Header.Get(header.ContentType)).To(Equal(header.ApplicationJSON))
	Expect(testutil.MustUnmarshal[apiutil.ErrorResponse](t, w.Body.Bytes()).Code).To(Equal("MethodNotAllowed"))
}

// The supported method must still reach its handler, so the 405 body is not
// produced by a handler that answers everything.
func TestSupportedMethodIsNotRejected(t *testing.T) {
	RegisterTestingT(t)

	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, "/things", nil)
	Expect(err).NotTo(HaveOccurred())
	newTestHandler().ServeHTTP(w, r)

	Expect(w.Code).To(Equal(http.StatusOK))
	Expect(w.Body.String()).NotTo(ContainSubstring("MethodNotAllowed"))
}
