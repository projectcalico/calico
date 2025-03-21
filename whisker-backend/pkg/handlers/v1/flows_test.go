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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	climocks "github.com/projectcalico/calico/goldmane/pkg/client/mocks"
	"github.com/projectcalico/calico/goldmane/proto"
	protomock "github.com/projectcalico/calico/goldmane/proto/mocks"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/testutil"
	"github.com/projectcalico/calico/lib/std/ptr"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	hdlrv1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

func TestListFlows(t *testing.T) {
	sc := setupTest(t)

	fsCli := new(climocks.FlowsClient)
	fsCli.On("List", mock.Anything, mock.Anything).Return(
		&proto.ListMetadata{
			TotalPages: 5,
		},
		[]*proto.FlowResult{
			{
				Flow: &proto.Flow{
					Key: &proto.FlowKey{
						SourceNamespace: "default",
						SourceName:      "test-pod",
						Policies: &proto.PolicyTrace{
							EnforcedPolicies: []*proto.PolicyHit{
								{
									Kind:        proto.PolicyKind_GlobalNetworkPolicy,
									Name:        "test-policy",
									Namespace:   "test-ns",
									Tier:        "test-tier",
									Action:      proto.Action_Allow,
									PolicyIndex: 1,
									RuleIndex:   2,
								},
							},
							PendingPolicies: []*proto.PolicyHit{
								{
									Kind:      proto.PolicyKind_NetworkPolicy,
									Name:      "test-policy",
									Namespace: "test-ns",
									Tier:      "test-tier",
									Action:    proto.Action_Deny,
								},
							},
						},
					},
				},
			},
		}, nil)

	hdlr := hdlrv1.NewFlows(fsCli)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))
	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())
	zerotime := time.Unix(0, 0)
	flows := testutil.MustUnmarshal[apiutil.List[whiskerv1.FlowResponse]](t, recorder.Body.Bytes())
	for i, flow := range flows.Items {
		flow.StartTime = zerotime
		flow.EndTime = zerotime
		flows.Items[i] = flow
	}
	Expect(flows).Should(
		Equal(&apiutil.List[whiskerv1.FlowResponse]{
			Meta: apiutil.ListMeta{
				TotalPages: 5,
			},
			Items: []whiskerv1.FlowResponse{
				{
					StartTime:       zerotime,
					EndTime:         zerotime,
					SourceNamespace: "default",
					SourceName:      "test-pod",
					Policies: whiskerv1.PolicyTrace{
						Enforced: []*whiskerv1.PolicyHit{
							{
								Kind:        whiskerv1.PolicyKind(proto.PolicyKind_GlobalNetworkPolicy),
								Name:        "test-policy",
								Namespace:   "test-ns",
								Tier:        "test-tier",
								Action:      whiskerv1.Action(proto.Action_Allow),
								PolicyIndex: 1,
								RuleIndex:   2,
							},
						},
						Pending: []*whiskerv1.PolicyHit{
							{
								Kind:      whiskerv1.PolicyKind(proto.PolicyKind_NetworkPolicy),
								Name:      "test-policy",
								Namespace: "test-ns",
								Tier:      "test-tier",
								Action:    whiskerv1.Action(proto.Action_Deny),
							},
						},
					},
				},
			},
		}))
}

func TestWatchFlows(t *testing.T) {
	sc := setupTest(t)

	fsCli := new(climocks.FlowsClient)
	flowStream := new(protomock.Flows_StreamClient[proto.FlowResult])

	flowStream.On("Recv").Return(&proto.FlowResult{
		Flow: &proto.Flow{
			Key: &proto.FlowKey{
				SourceNamespace: "default",
				SourceName:      "test-pod",
				Reporter:        proto.Reporter_Src,
				Action:          proto.Action_Pass,
			},
		},
	}, nil).Once()
	flowStream.On("Recv").Return(nil, io.EOF).Once()

	fsCli.On("Stream", mock.Anything, mock.Anything).Return(flowStream, nil)
	hdlr := hdlrv1.NewFlows(fsCli)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{Watch: true})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))

	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())

	zerotime := time.Unix(0, 0)
	var flows []whiskerv1.FlowResponse
	for _, data := range strings.Split(recorder.Body.String(), "\n\n") {
		if len(data) == 0 {
			continue
		}

		flow := testutil.MustUnmarshal[whiskerv1.FlowResponse](t, []byte(strings.TrimPrefix(data, "data: ")))
		flows = append(flows, *flow)
	}

	for i, flow := range flows {
		flow.StartTime = zerotime
		flow.EndTime = zerotime
		flows[i] = flow
	}
	expected := []whiskerv1.FlowResponse{
		{
			StartTime:       zerotime,
			EndTime:         zerotime,
			SourceNamespace: "default",
			SourceName:      "test-pod",
			Action:          whiskerv1.Action(proto.Action_Pass),
			Reporter:        whiskerv1.Reporter(proto.Reporter_Src),
		},
	}
	Expect(flows).Should(Equal(expected))
}

func TestWatchFlowsParameterConversion(t *testing.T) {
	sc := setupTest(t)

	var req *proto.FlowStreamRequest

	now := time.Now()
	tt := []struct {
		description       string
		params            whiskerv1.ListFlowsParams
		expected          *proto.FlowStreamRequest
		configureFlowsCli func(*climocks.FlowsClient)
	}{
		{
			description: "Watch set to true",
			params: whiskerv1.ListFlowsParams{
				Watch:        true,
				StartTimeGte: now.Unix(),
				Filters: whiskerv1.Filters{
					SourceNamespaces: []whiskerv1.FilterMatch[string]{{V: "src-ns"}},
					SourceNames:      []whiskerv1.FilterMatch[string]{{V: "src-name"}},
					DestNamespaces:   []whiskerv1.FilterMatch[string]{{V: "dst-ns"}},
					DestNames:        []whiskerv1.FilterMatch[string]{{V: "dst-name"}},
					Protocols:        []whiskerv1.FilterMatch[string]{{V: "tcp"}},
					DestPorts:        []whiskerv1.FilterMatch[int64]{{V: 6060}},
					Actions:          whiskerv1.Actions{whiskerv1.Action(proto.Action_Pass), whiskerv1.Action(proto.Action_Allow)},
					Policies: []whiskerv1.PolicyMatch{{
						Kind:      whiskerv1.PolicyKindCalicoNetworkPolicy,
						Tier:      whiskerv1.NewFilterMatch("default-tier", whiskerv1.MatchTypeExact),
						Name:      whiskerv1.NewFilterMatch("name", whiskerv1.MatchTypeExact),
						Namespace: whiskerv1.NewFilterMatch("namespace", whiskerv1.MatchTypeExact),
						Action:    whiskerv1.ActionDeny,
					}},
				},
			},
			expected: &proto.FlowStreamRequest{
				StartTimeGte: now.Unix(),
				Filter: &proto.Filter{
					SourceNamespaces: []*proto.StringMatch{{Value: "src-ns"}},
					SourceNames:      []*proto.StringMatch{{Value: "src-name"}},
					DestNamespaces:   []*proto.StringMatch{{Value: "dst-ns"}},
					DestNames:        []*proto.StringMatch{{Value: "dst-name"}},
					Protocols:        []*proto.StringMatch{{Value: "tcp"}},
					DestPorts:        []*proto.PortMatch{{Port: 6060}},
					Actions:          []proto.Action{proto.Action_Pass, proto.Action_Allow},
					Policies: []*proto.PolicyMatch{{
						Kind:      proto.PolicyKind_CalicoNetworkPolicy,
						Tier:      "default-tier",
						Name:      "name",
						Namespace: "namespace",
						Action:    proto.Action_Deny,
					}},
				},
			},
			configureFlowsCli: func(fsCli *climocks.FlowsClient) {
				fsCli.On("Stream", mock.Anything, mock.MatchedBy(func(arg *proto.FlowStreamRequest) bool {
					req = arg
					return true
				})).Return(nil, context.Canceled).Once()
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			req = nil

			mockFsCli := new(climocks.FlowsClient)
			tc.configureFlowsCli(mockFsCli)

			hdlr := hdlrv1.NewFlows(mockFsCli)
			rsp := hdlr.ListOrStream(sc.apiCtx, tc.params)
			Expect(rsp.Status()).Should(Equal(http.StatusInternalServerError))
			Expect(req.String()).Should(Equal(tc.expected.String()))
		})
	}
}

func TestListFlowsParameterConversion(t *testing.T) {
	sc := setupTest(t)

	var req *proto.FlowListRequest

	now := time.Now()
	tt := []struct {
		description       string
		params            whiskerv1.ListFlowsParams
		expected          *proto.FlowListRequest
		configureFlowsCli func(*climocks.FlowsClient)
	}{
		{
			description: "Watch set to false",
			params: whiskerv1.ListFlowsParams{
				SortBy: whiskerv1.SortBys{
					whiskerv1.SortBy(proto.SortBy_SourceType), whiskerv1.SortBy(proto.SortBy_SourceNamespace), whiskerv1.SortBy(proto.SortBy_SourceName),
					whiskerv1.SortBy(proto.SortBy_DestType), whiskerv1.SortBy(proto.SortBy_DestNamespace), whiskerv1.SortBy(proto.SortBy_DestName),
					whiskerv1.SortBy(proto.SortBy_Time),
				},
				StartTimeGte: now.Unix(),
				Filters: whiskerv1.Filters{
					SourceNamespaces: []whiskerv1.FilterMatch[string]{{V: "src-ns"}},
					SourceNames:      []whiskerv1.FilterMatch[string]{{V: "src-name"}},
					DestNamespaces:   []whiskerv1.FilterMatch[string]{{V: "dst-ns"}},
					DestNames:        []whiskerv1.FilterMatch[string]{{V: "dst-name"}},
					Protocols:        []whiskerv1.FilterMatch[string]{{V: "tcp"}},
					DestPorts:        []whiskerv1.FilterMatch[int64]{{V: 6060}},
					Actions:          whiskerv1.Actions{whiskerv1.Action(proto.Action_Pass), whiskerv1.Action(proto.Action_Allow)},
				},
			},
			expected: &proto.FlowListRequest{
				SortBy: []*proto.SortOption{
					{SortBy: proto.SortBy_SourceType}, {SortBy: proto.SortBy_SourceNamespace}, {SortBy: proto.SortBy_SourceName},
					{SortBy: proto.SortBy_DestType}, {SortBy: proto.SortBy_DestNamespace}, {SortBy: proto.SortBy_DestName},
					{SortBy: proto.SortBy_Time},
				},
				StartTimeGte: now.Unix(),
				Filter: &proto.Filter{
					SourceNamespaces: []*proto.StringMatch{{Value: "src-ns"}},
					SourceNames:      []*proto.StringMatch{{Value: "src-name"}},
					DestNamespaces:   []*proto.StringMatch{{Value: "dst-ns"}},
					DestNames:        []*proto.StringMatch{{Value: "dst-name"}},
					Protocols:        []*proto.StringMatch{{Value: "tcp"}},
					DestPorts:        []*proto.PortMatch{{Port: 6060}},
					Actions:          []proto.Action{proto.Action_Pass, proto.Action_Allow},
				},
			},
			configureFlowsCli: func(fsCli *climocks.FlowsClient) {
				fsCli.On("List", mock.Anything, mock.MatchedBy(func(arg *proto.FlowListRequest) bool {
					req = arg
					return true
				})).Return(nil, nil, context.Canceled).Once()
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			req = nil

			mockFsCli := new(climocks.FlowsClient)
			tc.configureFlowsCli(mockFsCli)

			hdlr := hdlrv1.NewFlows(mockFsCli)
			rsp := hdlr.ListOrStream(sc.apiCtx, tc.params)
			Expect(rsp.Status()).Should(Equal(http.StatusInternalServerError))
			Expect(req.String()).Should(Equal(tc.expected.String()))
		})
	}
}

func TestListFilterHints(t *testing.T) {
	sc := setupTest(t)

	fsCli := new(climocks.FlowsClient)
	fsCli.On("FilterHints", mock.Anything, mock.Anything).Return(
		&proto.ListMetadata{
			TotalPages: 5,
		},
		[]*proto.FilterHint{
			{Value: "foo"},
			{Value: "bar"},
		}, nil)

	hdlr := hdlrv1.NewFlows(fsCli)
	rsp := hdlr.ListFilterHints(sc.apiCtx, whiskerv1.FlowFilterHintsRequest{
		Type: ptr.ToPtr(whiskerv1.FilterType(proto.FilterType_FilterTypeDestNamespace)),
	})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))
	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())
	flows := testutil.MustUnmarshal[apiutil.List[whiskerv1.FlowFilterHintResponse]](t, recorder.Body.Bytes())

	Expect(flows).Should(
		Equal(&apiutil.List[whiskerv1.FlowFilterHintResponse]{
			Meta: apiutil.ListMeta{
				TotalPages: 5,
			},
			Items: []whiskerv1.FlowFilterHintResponse{
				{Value: "foo"},
				{Value: "bar"},
			},
		}))
}
