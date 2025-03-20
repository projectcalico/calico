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
				SourceNames:      v1.FilterMatches[string]{v1.NewFilterMatch("src-name", v1.MatchTypeExact)},
				SourceNamespaces: v1.FilterMatches[string]{v1.NewFilterMatch("src-namespace", v1.MatchTypeExact)},
				DestNames:        v1.FilterMatches[string]{v1.NewFilterMatch("dest-name", v1.MatchTypeExact)},
				DestNamespaces:   v1.FilterMatches[string]{v1.NewFilterMatch("dest-namespace", v1.MatchTypeExact)},
				DestPorts:        v1.FilterMatches[int64]{v1.NewFilterMatch(int64(8080), v1.MatchTypeExact)},
				Protocols:        v1.FilterMatches[string]{v1.NewFilterMatch("tcp", v1.MatchTypeExact)},
				Actions:          v1.Actions{v1.ActionDeny, v1.ActionPass},
				Policies: []v1.PolicyMatch{{
					Kind:      v1.PolicyKindCalicoNetworkPolicy,
					Tier:      v1.NewFilterMatch("default-tier", v1.MatchTypeExact),
					Name:      v1.NewFilterMatch("name", v1.MatchTypeExact),
					Namespace: v1.NewFilterMatch("namespace", v1.MatchTypeExact),
					Action:    v1.ActionDeny,
				}},
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
				SourceNames:      []v1.FilterMatch[string]{v1.NewFilterMatch("src-name", v1.MatchTypeExact)},
				SourceNamespaces: []v1.FilterMatch[string]{v1.NewFilterMatch("src-namespace", v1.MatchTypeExact)},
				DestNames:        []v1.FilterMatch[string]{v1.NewFilterMatch("dest-name", v1.MatchTypeExact)},
				DestNamespaces:   []v1.FilterMatch[string]{v1.NewFilterMatch("dest-namespace", v1.MatchTypeExact)},
				DestPorts:        []v1.FilterMatch[int64]{v1.NewFilterMatch(int64(8080), v1.MatchTypeExact)},
				Protocols:        []v1.FilterMatch[string]{v1.NewFilterMatch("tcp", v1.MatchTypeExact)},
				Actions:          v1.Actions{v1.Action(proto.Action_Deny), v1.Action(proto.Action_Pass)},
				Policies: []v1.PolicyMatch{{
					Kind:      v1.PolicyKindCalicoNetworkPolicy,
					Tier:      v1.NewFilterMatch("default-tier", v1.MatchTypeExact),
					Name:      v1.NewFilterMatch("name", v1.MatchTypeExact),
					Namespace: v1.NewFilterMatch("namespace", v1.MatchTypeExact),
					Action:    v1.ActionDeny,
				}},
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
				SourceNames:      []v1.FilterMatch[string]{v1.NewFilterMatch("src-name", v1.MatchTypeFuzzy)},
				SourceNamespaces: []v1.FilterMatch[string]{v1.NewFilterMatch("src-namespace", v1.MatchTypeFuzzy)},
				DestNames:        []v1.FilterMatch[string]{v1.NewFilterMatch("dest-name", v1.MatchTypeFuzzy)},
				DestNamespaces:   []v1.FilterMatch[string]{v1.NewFilterMatch("dest-namespace", v1.MatchTypeFuzzy)},
				DestPorts:        []v1.FilterMatch[int64]{v1.NewFilterMatch(int64(8080), v1.MatchTypeFuzzy)},
				Protocols:        []v1.FilterMatch[string]{v1.NewFilterMatch("tcp", v1.MatchTypeFuzzy)},
				Actions:          v1.Actions{v1.ActionDeny, v1.ActionPass},
				Policies: []v1.PolicyMatch{{
					Tier:      v1.NewFilterMatch("default-tier", v1.MatchTypeFuzzy),
					Name:      v1.NewFilterMatch("name", v1.MatchTypeFuzzy),
					Namespace: v1.NewFilterMatch("namespace", v1.MatchTypeFuzzy),
				}},
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
