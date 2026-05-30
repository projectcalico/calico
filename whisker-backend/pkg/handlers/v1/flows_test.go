// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/testutil"
	"github.com/projectcalico/calico/lib/std/ptr"
	"github.com/projectcalico/calico/lib/std/time"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	v1mocks "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1/mocks"
	hdlrv1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

func TestListFlows(t *testing.T) {
	sc := setupTest(t)

	zerotime := time.Unix(0, 0)
	backend := new(v1mocks.FlowsBackend)
	backend.On("List", mock.Anything, mock.Anything).Return(
		5,
		[]whiskerv1.FlowResponse{
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
		}, nil)

	hdlr := hdlrv1.NewFlows(backend)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))
	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())
	flows := testutil.MustUnmarshal[apiutil.List[whiskerv1.FlowResponse]](t, recorder.Body.Bytes())
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

func TestListFlows_Error(t *testing.T) {
	sc := setupTest(t)

	backend := new(v1mocks.FlowsBackend)
	backend.On("List", mock.Anything, mock.Anything).Return(0, nil, context.Canceled)

	hdlr := hdlrv1.NewFlows(backend)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{})
	Expect(rsp.Status()).Should(Equal(http.StatusInternalServerError))
}

func TestWatchFlows(t *testing.T) {
	sc := setupTest(t)

	zerotime := time.Unix(0, 0)
	flowStream := new(v1mocks.FlowStream)
	flowStream.On("Recv").Return(&whiskerv1.FlowResponse{
		StartTime:       zerotime,
		EndTime:         zerotime,
		SourceNamespace: "default",
		SourceName:      "test-pod",
		Reporter:        whiskerv1.Reporter(proto.Reporter_Src),
		Action:          whiskerv1.Action(proto.Action_Pass),
	}, nil).Once()
	flowStream.On("Recv").Return(nil, io.EOF).Once()

	backend := new(v1mocks.FlowsBackend)
	backend.On("Stream", mock.Anything, mock.Anything).Return(flowStream, nil)

	hdlr := hdlrv1.NewFlows(backend)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{Watch: true})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))

	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())

	var flows []whiskerv1.FlowResponse
	for data := range strings.SplitSeq(recorder.Body.String(), "\n\n") {
		if len(data) == 0 {
			continue
		}

		flow := testutil.MustUnmarshal[whiskerv1.FlowResponse](t, []byte(strings.TrimPrefix(data, "data: ")))
		flows = append(flows, *flow)
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

func TestWatchFlows_StreamError(t *testing.T) {
	sc := setupTest(t)

	backend := new(v1mocks.FlowsBackend)
	backend.On("Stream", mock.Anything, mock.Anything).Return(nil, context.Canceled)

	hdlr := hdlrv1.NewFlows(backend)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{Watch: true})
	Expect(rsp.Status()).Should(Equal(http.StatusInternalServerError))
}

func TestListFilterHints(t *testing.T) {
	sc := setupTest(t)

	backend := new(v1mocks.FlowsBackend)
	backend.On("FilterHints", mock.Anything, mock.Anything).Return(
		5,
		[]whiskerv1.FlowFilterHintResponse{
			{Value: "foo"},
			{Value: "bar"},
		}, nil)

	hdlr := hdlrv1.NewFlows(backend)
	rsp := hdlr.ListFilterHints(sc.apiCtx, whiskerv1.FlowFilterHintsRequest{
		Type: ptr.ToPtr(whiskerv1.FilterType(proto.FilterType_FilterTypeDestNamespace)),
	})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))
	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())
	hints := testutil.MustUnmarshal[apiutil.List[whiskerv1.FlowFilterHintResponse]](t, recorder.Body.Bytes())

	Expect(hints).Should(
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

func TestListFilterHints_Error(t *testing.T) {
	sc := setupTest(t)

	backend := new(v1mocks.FlowsBackend)
	backend.On("FilterHints", mock.Anything, mock.Anything).Return(0, nil, context.Canceled)

	hdlr := hdlrv1.NewFlows(backend)
	rsp := hdlr.ListFilterHints(sc.apiCtx, whiskerv1.FlowFilterHintsRequest{
		Type: ptr.ToPtr(whiskerv1.FilterType(proto.FilterType_FilterTypeDestNamespace)),
	})
	Expect(rsp.Status()).Should(Equal(http.StatusInternalServerError))
}
