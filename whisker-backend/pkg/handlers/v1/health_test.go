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
	"testing"

	. "github.com/onsi/gomega"

	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	hdlrv1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

func TestHealth(t *testing.T) {
	sc := setupTest(t)

	hdlr := hdlrv1.NewHealth()

	rsp := hdlr.Health(sc.apiCtx, struct{}{})
	Expect(rsp.Status()).To(Equal(http.StatusOK))
}

func TestHealthAPIs(t *testing.T) {
	setupTest(t)

	hdlr := hdlrv1.NewHealth()
	apis := hdlr.APIs()

	Expect(apis).To(HaveLen(1))
	Expect(apis[0].Method).To(Equal(http.MethodGet))
	Expect(apis[0].Path).To(Equal(whiskerv1.HealthPath))
}
