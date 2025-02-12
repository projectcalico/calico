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

package v1_test

import (
	"net/http"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/codec"
	v1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

func TestListFlows(t *testing.T) {
	sc := setupTest(t)

	req, err := http.NewRequest("GET", "/api/v1/flows", nil)
	Expect(err).ShouldNot(HaveOccurred())

	req.URL.RawQuery = "sortBy=dest"

	tt := []struct {
		description string
		request     *http.Request
		expected    *v1.ListFlowsParams
	}{
		{
			description: "Decoder parses sortBy query param with allowed value",
			request:     mustCreateGetRequest(t, "GET", "/api/v1/flows", map[string]string{"sortBy": "dest"}),
			expected:    &v1.ListFlowsParams{SortBy: v1.ListFlowsSortByDest},
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			params, err := codec.DecodeAndValidateRequestParams[v1.ListFlowsParams](sc.apiCtx, sc.URLVars, req)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(params).Should(Equal(tc.expected))
		})
	}
}

func mustCreateGetRequest(t *testing.T, method, path string, queryParams map[string]string) *http.Request {
	for _, param := range queryParams {
		path += "?" + param
	}
	req, err := http.NewRequest(method, path, nil)
	Expect(err).ShouldNot(HaveOccurred())
	return req

}
