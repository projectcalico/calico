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

package v1_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/testutil"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	hdlrv1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

func TestGetConfig_StreamingEnabled(t *testing.T) {
	sc := setupTest(t)

	hdlr := hdlrv1.NewConfig(true)
	rsp := hdlr.GetConfig(sc.apiCtx, whiskerv1.ConfigRequest{})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))

	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())

	result := testutil.MustUnmarshal[apiutil.List[whiskerv1.ConfigResponse]](t, recorder.Body.Bytes())
	Expect(result.Items).To(HaveLen(1))
	Expect(result.Items[0].Streaming).To(BeTrue())
}

func TestGetConfig_StreamingDisabled(t *testing.T) {
	sc := setupTest(t)

	hdlr := hdlrv1.NewConfig(false)
	rsp := hdlr.GetConfig(sc.apiCtx, whiskerv1.ConfigRequest{})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))

	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())

	result := testutil.MustUnmarshal[apiutil.List[whiskerv1.ConfigResponse]](t, recorder.Body.Bytes())
	Expect(result.Items).To(HaveLen(1))
	Expect(result.Items[0].Streaming).To(BeFalse())
}
