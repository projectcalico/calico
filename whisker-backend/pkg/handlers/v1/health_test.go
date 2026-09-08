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

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/testutil"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	hdlrv1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

func TestHealth(t *testing.T) {
	sc := setupTest(t)

	hdlr := hdlrv1.NewHealth()

	rsp := hdlr.Health(sc.apiCtx, struct{}{})
	Expect(rsp.Status()).To(Equal(http.StatusOK))

	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())
	body := testutil.MustUnmarshal[whiskerv1.HealthStatusResponse](t, recorder.Body.Bytes())
	Expect(*body).To(Equal(whiskerv1.HealthStatusResponse{Status: "ok"}))
}

func TestHealthAPIs(t *testing.T) {
	setupTest(t)

	hdlr := hdlrv1.NewHealth()
	apis := hdlr.APIs()

	Expect(apis).To(HaveLen(1))
	Expect(apis[0].Method).To(Equal(http.MethodGet))
	Expect(apis[0].Path).To(Equal(whiskerv1.HealthPath))
}
