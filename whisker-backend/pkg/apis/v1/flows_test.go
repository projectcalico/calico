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
	"net/url"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/codec"
	jsontestutil "github.com/projectcalico/calico/lib/std/testutils/json"
	v1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

func TestListFlows(t *testing.T) {
	sc := setupTest(t)

	tt := []struct {
		description string
		request     *http.Request
		expected    *v1.ListFlowsParams
	}{
		{
			description: "Decoder parses sortBy query param with allowed value",
			request:     mustCreateGetRequest("GET", "/api/v1/flows", map[string][]string{"sortBy": {"DestName", "SourceName"}}),
			expected:    &v1.ListFlowsParams{SortBy: v1.SortBys{v1.SortBy(proto.SortBy_DestName), v1.SortBy(proto.SortBy_SourceName)}},
		},
		{
			description: "Decoder parses sortBy query param with allowed value",
			request: mustCreateGetRequest("GET", "/api/v1/flows", map[string][]string{
				"filters": {"{\"source_names\":[{\"value\":\"foobar\",\"type\":\"Exact\"}],\"actions\":[\"Deny\"]}"}}),
			expected: &v1.ListFlowsParams{Filters: v1.Filters{
				SourceNames: []v1.FilterMatch[string]{{V: "foobar", Type: v1.MatchType(proto.MatchType_Exact)}},
				Actions:     v1.Actions{v1.Action(proto.Action_Deny)},
			}},
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			params, err := codec.DecodeAndValidateRequestParams[v1.ListFlowsParams](sc.apiCtx, sc.URLVars, tc.request)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(params).Should(Equal(tc.expected))
		})
	}
}

func TestUnmarshalFilters(t *testing.T) {
	setupTest(t)

	jsontestutil.MustMarshal(t, v1.FlowResponse{
		DestPort:        8080,
		DestNamespace:   "default-dest",
		DestName:        "test-pod-dest",
		SourceNamespace: "default",
		SourceName:      "test-pod",
		Action:          v1.Action(proto.Action_Pass),
		Reporter:        v1.Reporter(proto.Reporter_Src),
	})
}

func mustCreateGetRequest(method, path string, queryParams map[string][]string) *http.Request {
	req, err := http.NewRequest(method, path, nil)
	Expect(err).ShouldNot(HaveOccurred())
	req.URL.RawQuery = url.Values(queryParams).Encode()

	return req
}
