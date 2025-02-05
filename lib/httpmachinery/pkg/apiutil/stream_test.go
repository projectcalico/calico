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
	"bytes"
	"fmt"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/testutil"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	apicontext "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
)

func TestFlowLogsEventStream(t *testing.T) {
	setupTest(t)

	type request struct{}
	type response struct {
		Field string `json:"foo"`
	}

	hdlr := apiutil.NewJSONEventStreamHandler(func(ctx apicontext.Context, params request, stream apiutil.EventStream[response]) {
		Expect(stream.Data(response{Field: "bar"})).ShouldNot(HaveOccurred())
		Expect(stream.Data(response{Field: "baz"})).ShouldNot(HaveOccurred())

		return
	})

	w := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "foobar", bytes.NewBufferString(testutil.MustMarshal(t, request{})))
	Expect(err).NotTo(HaveOccurred())

	hdlr.ServeHTTP(apiutil.NewNOOPRouterConfig(), w, r)

	Expect(w.Code).To(Equal(http.StatusOK))
	Expect(w.Body.String()).To(Equal(fmt.Sprintf("data: %s\n\ndata: %s\n\n",
		testutil.MustMarshal(t, response{Field: "bar"}), testutil.MustMarshal(t, response{Field: "baz"}))))
}
