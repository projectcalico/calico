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
	_ "embed"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/codec"
	v1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

//go:embed testfiles/flow_filters_exact.json
var allFiltersSetToExactJson string

//go:embed testfiles/flow_filters_fuzzy.json
var allFiltersSetToFuzzyJson string

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
				"filters": {allFiltersSetToExactJson}}),
			expected: &v1.ListFlowsParams{Filters: v1.Filters{
				SourceNames:      []v1.FilterMatch[string]{{V: "src-name", Type: v1.MatchType(proto.MatchType_Exact)}},
				SourceNamespaces: []v1.FilterMatch[string]{{V: "src-namespace", Type: v1.MatchType(proto.MatchType_Exact)}},
				DestNames:        []v1.FilterMatch[string]{{V: "dest-name", Type: v1.MatchType(proto.MatchType_Exact)}},
				DestNamespaces:   []v1.FilterMatch[string]{{V: "dest-namespace", Type: v1.MatchType(proto.MatchType_Exact)}},
				DestPorts:        []v1.FilterMatch[int64]{{V: 8080, Type: v1.MatchType(proto.MatchType_Exact)}},
				Protocols:        []v1.FilterMatch[string]{{V: "tcp", Type: v1.MatchType(proto.MatchType_Exact)}},
				Actions:          v1.Actions{v1.Action(proto.Action_Deny), v1.Action(proto.Action_Pass)},
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

func TestListFlowsFilterHints_ValidFilterTypes(t *testing.T) {
	sc := setupTest(t)

	tt := []struct {
		description string
		typ         string
		expected    v1.FilterType
	}{
		{
			description: "Decoder parses DestName",
			typ:         "DestName",
			expected:    v1.FilterType(proto.FilterType_FilterTypeDestName),
		},
		{
			description: "Decoder parses SourceName",
			typ:         "SourceName",
			expected:    v1.FilterType(proto.FilterType_FilterTypeSourceName),
		},
		{
			description: "Decoder parses DestNamespace",
			typ:         "DestNamespace",
			expected:    v1.FilterType(proto.FilterType_FilterTypeDestNamespace),
		},
		{
			description: "Decoder parses SourceNamespace",
			typ:         "SourceNamespace",
			expected:    v1.FilterType(proto.FilterType_FilterTypeSourceNamespace),
		},
		{
			description: "Decoder parses PolicyTier",
			typ:         "PolicyTier",
			expected:    v1.FilterType(proto.FilterType_FilterTypePolicyTier),
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			req := mustCreateGetRequest("GET", "/api/v1/flows", map[string][]string{"type": {tc.typ}})
			params, err := codec.DecodeAndValidateRequestParams[v1.FlowFilterHintsRequest](sc.apiCtx, sc.URLVars, req)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(*params.Type).Should(Equal(tc.expected))
		})
	}
}

func TestListFlowsFilterHints_NoFilterTypeGiven(t *testing.T) {
	sc := setupTest(t)

	req := mustCreateGetRequest("GET", "/api/v1/flows", nil)
	_, err := codec.DecodeAndValidateRequestParams[v1.FlowFilterHintsRequest](sc.apiCtx, sc.URLVars, req)
	Expect(err).Should(HaveOccurred())
}

func TestListFlowsFilterHints_InvalidTypeGiven(t *testing.T) {
	sc := setupTest(t)

	req := mustCreateGetRequest("GET", "/api/v1/flows", map[string][]string{"type": {"FooBar"}})
	_, err := codec.DecodeAndValidateRequestParams[v1.FlowFilterHintsRequest](sc.apiCtx, sc.URLVars, req)
	Expect(err).Should(HaveOccurred())
}

func TestFilters_DecodedFromRawString(t *testing.T) {
	sc := setupTest(t)

	tt := []struct {
		description string
		request     *http.Request
		expected    v1.Filters
	}{
		{
			description: "Decoder decodes raw json strings properly for the Filter value (Exact matching)",
			request: mustCreateGetRequest(
				"GET", "/api/v1/flows",
				map[string][]string{
					"type":    {"SourceName"},
					"filters": {allFiltersSetToExactJson},
				},
			),
			expected: v1.Filters{
				SourceNames:      []v1.FilterMatch[string]{{V: "src-name", Type: v1.MatchType(proto.MatchType_Exact)}},
				SourceNamespaces: []v1.FilterMatch[string]{{V: "src-namespace", Type: v1.MatchType(proto.MatchType_Exact)}},
				DestNames:        []v1.FilterMatch[string]{{V: "dest-name", Type: v1.MatchType(proto.MatchType_Exact)}},
				DestNamespaces:   []v1.FilterMatch[string]{{V: "dest-namespace", Type: v1.MatchType(proto.MatchType_Exact)}},
				DestPorts:        []v1.FilterMatch[int64]{{V: 8080, Type: v1.MatchType(proto.MatchType_Exact)}},
				Protocols:        []v1.FilterMatch[string]{{V: "tcp", Type: v1.MatchType(proto.MatchType_Exact)}},
				Actions:          v1.Actions{v1.Action(proto.Action_Deny), v1.Action(proto.Action_Pass)},
			},
		},
		{
			description: "Decoder decodes raw json strings properly for the Filter value (Fuzzy matching)",
			request: mustCreateGetRequest(
				"GET", "/api/v1/flows",
				map[string][]string{
					"type":    {"SourceName"},
					"filters": {allFiltersSetToFuzzyJson},
				},
			),
			expected: v1.Filters{
				SourceNames:      []v1.FilterMatch[string]{{V: "src-name", Type: v1.MatchType(proto.MatchType_Fuzzy)}},
				SourceNamespaces: []v1.FilterMatch[string]{{V: "src-namespace", Type: v1.MatchType(proto.MatchType_Fuzzy)}},
				DestNames:        []v1.FilterMatch[string]{{V: "dest-name", Type: v1.MatchType(proto.MatchType_Fuzzy)}},
				DestNamespaces:   []v1.FilterMatch[string]{{V: "dest-namespace", Type: v1.MatchType(proto.MatchType_Fuzzy)}},
				DestPorts:        []v1.FilterMatch[int64]{{V: 8080, Type: v1.MatchType(proto.MatchType_Fuzzy)}},
				Protocols:        []v1.FilterMatch[string]{{V: "tcp", Type: v1.MatchType(proto.MatchType_Fuzzy)}},
				Actions:          v1.Actions{v1.Action(proto.Action_Deny), v1.Action(proto.Action_Pass)},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			params, err := codec.DecodeAndValidateRequestParams[v1.FlowFilterHintsRequest](sc.apiCtx, sc.URLVars, tc.request)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(params.Filters).Should(Equal(tc.expected), cmp.Diff(params.Filters, tc.expected))
		})
	}
}

func mustCreateGetRequest(method, path string, queryParams map[string][]string) *http.Request {
	req, err := http.NewRequest(method, path, nil)
	Expect(err).ShouldNot(HaveOccurred())
	req.URL.RawQuery = url.Values(queryParams).Encode()

	return req
}
