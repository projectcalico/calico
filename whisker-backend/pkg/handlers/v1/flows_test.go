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
	"errors"
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
	"github.com/projectcalico/calico/whisker-backend/pkg/auth"
	hdlrv1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

func TestListFlows(t *testing.T) {
	sc := setupTest(t)

	backend := new(v1mocks.FlowsBackend)
	backend.On("List", mock.Anything, mock.Anything).Return(
		5,
		[]whiskerv1.FlowResponse{
			{
				SourceNamespace: "default",
				SourceName:      "test-pod",
				Policies: whiskerv1.PolicyTrace{
					Enforced: []*whiskerv1.PolicyHit{
						{
							Kind:        whiskerv1.PolicyKindGlobalNetworkPolicy,
							Name:        "test-policy",
							Namespace:   "test-ns",
							Tier:        "test-tier",
							Action:      whiskerv1.ActionAllow,
							PolicyIndex: 1,
							RuleIndex:   2,
						},
					},
					Pending: []*whiskerv1.PolicyHit{
						{
							Kind:      whiskerv1.PolicyKindNetworkPolicy,
							Name:      "test-policy",
							Namespace: "test-ns",
							Tier:      "test-tier",
							Action:    whiskerv1.ActionDeny,
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
								Kind:        whiskerv1.PolicyKindGlobalNetworkPolicy,
								Name:        "test-policy",
								Namespace:   "test-ns",
								Tier:        "test-tier",
								Action:      whiskerv1.ActionAllow,
								PolicyIndex: 1,
								RuleIndex:   2,
							},
						},
						Pending: []*whiskerv1.PolicyHit{
							{
								Kind:      whiskerv1.PolicyKindNetworkPolicy,
								Name:      "test-policy",
								Namespace: "test-ns",
								Tier:      "test-tier",
								Action:    whiskerv1.ActionDeny,
							},
						},
					},
				},
			},
		}))
}

func TestWatchFlows(t *testing.T) {
	sc := setupTest(t)

	backend := new(v1mocks.StreamingFlowsBackend)
	flowStream := new(v1mocks.FlowStream)

	flowStream.On("Recv").Return(&whiskerv1.FlowResponse{
		SourceNamespace: "default",
		SourceName:      "test-pod",
		Reporter:        whiskerv1.ReporterSrc,
		Action:          whiskerv1.ActionPass,
	}, nil).Once()
	flowStream.On("Recv").Return(nil, io.EOF).Once()

	backend.On("Stream", mock.Anything, mock.Anything).Return(flowStream, nil)
	hdlr := hdlrv1.NewFlows(backend)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{Watch: true})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))

	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())

	zerotime := time.Unix(0, 0)
	var flows []whiskerv1.FlowResponse
	for data := range strings.SplitSeq(recorder.Body.String(), "\n\n") {
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
			Action:          whiskerv1.ActionPass,
			Reporter:        whiskerv1.ReporterSrc,
		},
	}
	Expect(flows).Should(Equal(expected))
}

func TestListFilterHints(t *testing.T) {
	sc := setupTest(t)

	backend := new(v1mocks.FlowsBackend)
	backend.On("FilterHints", mock.Anything, mock.Anything, mock.Anything).Return(
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

func TestListFlows_Error(t *testing.T) {
	sc := setupTest(t)

	backend := new(v1mocks.FlowsBackend)
	backend.On("List", mock.Anything, mock.Anything).Return(0, nil, context.Canceled)

	hdlr := hdlrv1.NewFlows(backend)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{})
	Expect(rsp.Status()).Should(Equal(http.StatusInternalServerError))
}

func TestWatchFlows_StreamError(t *testing.T) {
	sc := setupTest(t)

	backend := new(v1mocks.StreamingFlowsBackend)
	backend.On("Stream", mock.Anything, mock.Anything).Return(nil, context.Canceled)

	hdlr := hdlrv1.NewFlows(backend)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{Watch: true})
	Expect(rsp.Status()).Should(Equal(http.StatusInternalServerError))
}

func TestWatchFlows_Unsupported(t *testing.T) {
	sc := setupTest(t)

	// A plain FlowsBackend (e.g. Linseed) does not implement
	// StreamingFlowsBackend, so a watch request must be rejected with a clean
	// 400 rather than a generic 500.
	backend := new(v1mocks.FlowsBackend)

	hdlr := hdlrv1.NewFlows(backend)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{Watch: true})
	Expect(rsp.Status()).Should(Equal(http.StatusBadRequest))
}

func TestListFilterHints_Error(t *testing.T) {
	sc := setupTest(t)

	backend := new(v1mocks.FlowsBackend)
	backend.On("FilterHints", mock.Anything, mock.Anything, mock.Anything).Return(0, nil, context.Canceled)

	hdlr := hdlrv1.NewFlows(backend)
	rsp := hdlr.ListFilterHints(sc.apiCtx, whiskerv1.FlowFilterHintsRequest{
		Type: ptr.ToPtr(whiskerv1.FilterType(proto.FilterType_FilterTypeDestNamespace)),
	})
	Expect(rsp.Status()).Should(Equal(http.StatusInternalServerError))
}

// The tests below pin the handler's RBAC wiring: every serving path (list,
// stream, filter hints) must run flows through the configured FlowFilterFactory.
// The filtering logic itself is tested in whisker-backend/pkg/auth; here a fake
// filter proves the handler actually invokes it — a regression that drops one of
// these calls disables RBAC without failing any other test.

const redactedByTest = "redacted-by-test"

// fakeFlowFilter denies flows in denyNamespace and marks the policy hits of
// admitted flows so tests can tell redaction ran.
type fakeFlowFilter struct {
	denyNamespace string
}

func (f *fakeFlowFilter) IncludeFlow(flow *whiskerv1.FlowResponse) (bool, error) {
	return flow.SourceNamespace != f.denyNamespace, nil
}

func (f *fakeFlowFilter) RedactPolicies(flow *whiskerv1.FlowResponse) error {
	for _, hit := range flow.Policies.Enforced {
		hit.Name = redactedByTest
	}
	return nil
}

func fakeFilterFactory(denyNamespace string) auth.FlowFilterFactory {
	return func(context.Context) (auth.FlowFilter, error) {
		return &fakeFlowFilter{denyNamespace: denyNamespace}, nil
	}
}

func flowWithPolicy(ns string) whiskerv1.FlowResponse {
	return whiskerv1.FlowResponse{
		SourceNamespace: ns,
		SourceName:      "app",
		Policies: whiskerv1.PolicyTrace{
			Enforced: []*whiskerv1.PolicyHit{{Name: "secret-policy"}},
		},
	}
}

func TestListFlows_AppliesRBACFilter(t *testing.T) {
	sc := setupTest(t)

	backend := new(v1mocks.FlowsBackend)
	backend.On("List", mock.Anything, mock.Anything).Return(
		1, []whiskerv1.FlowResponse{flowWithPolicy("allowed"), flowWithPolicy("denied")}, nil)

	hdlr := hdlrv1.NewFlows(backend, hdlrv1.WithFlowFilterFactory(fakeFilterFactory("denied")))
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))

	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())
	flows := testutil.MustUnmarshal[apiutil.List[whiskerv1.FlowResponse]](t, recorder.Body.Bytes())

	Expect(flows.Items).Should(HaveLen(1))
	Expect(flows.Items[0].SourceNamespace).Should(Equal("allowed"))
	Expect(flows.Items[0].Policies.Enforced[0].Name).Should(Equal(redactedByTest))
}

func TestListFlows_RBACEmptiedPageReportsZeroPages(t *testing.T) {
	sc := setupTest(t)

	// The backend found a page of flows, but the RBAC filter admits none of
	// them. The UI must not be told there is a page to render with nothing in
	// it — an emptied single-page result reports zero pages.
	backend := new(v1mocks.FlowsBackend)
	backend.On("List", mock.Anything, mock.Anything).Return(
		1, []whiskerv1.FlowResponse{flowWithPolicy("denied")}, nil)

	hdlr := hdlrv1.NewFlows(backend, hdlrv1.WithFlowFilterFactory(fakeFilterFactory("denied")))
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))

	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())
	flows := testutil.MustUnmarshal[apiutil.List[whiskerv1.FlowResponse]](t, recorder.Body.Bytes())

	Expect(flows.Items).Should(BeEmpty())
	Expect(flows.Meta.TotalPages).Should(Equal(0))
}

func TestWatchFlows_AppliesRBACFilter(t *testing.T) {
	sc := setupTest(t)

	backend := new(v1mocks.StreamingFlowsBackend)
	flowStream := new(v1mocks.FlowStream)
	flowStream.On("Recv").Return(ptr.ToPtr(flowWithPolicy("denied")), nil).Once()
	flowStream.On("Recv").Return(ptr.ToPtr(flowWithPolicy("allowed")), nil).Once()
	flowStream.On("Recv").Return(nil, io.EOF).Once()
	backend.On("Stream", mock.Anything, mock.Anything).Return(flowStream, nil)

	hdlr := hdlrv1.NewFlows(backend, hdlrv1.WithFlowFilterFactory(fakeFilterFactory("denied")))
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

	Expect(flows).Should(HaveLen(1))
	Expect(flows[0].SourceNamespace).Should(Equal("allowed"))
	Expect(flows[0].Policies.Enforced[0].Name).Should(Equal(redactedByTest))
}

func TestListFilterHints_PassesRBACPredicate(t *testing.T) {
	sc := setupTest(t)

	// The handler cannot filter hints itself (backends derive them from source
	// flows), so it must hand the backend a predicate built from the filter
	// factory. Capture it and check it behaves like the configured filter,
	// including in-place redaction of admitted flows.
	var includeFlow whiskerv1.FlowFilterFunc
	backend := new(v1mocks.FlowsBackend)
	backend.On("FilterHints", mock.Anything, mock.Anything, mock.MatchedBy(func(f whiskerv1.FlowFilterFunc) bool {
		includeFlow = f
		return true
	})).Return(1, []whiskerv1.FlowFilterHintResponse{{Value: "foo"}}, nil)

	hdlr := hdlrv1.NewFlows(backend, hdlrv1.WithFlowFilterFactory(fakeFilterFactory("denied")))
	rsp := hdlr.ListFilterHints(sc.apiCtx, whiskerv1.FlowFilterHintsRequest{
		Type: ptr.ToPtr(whiskerv1.FilterType(proto.FilterType_FilterTypeDestNamespace)),
	})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))

	Expect(includeFlow).ShouldNot(BeNil())
	denied := flowWithPolicy("denied")
	ok, err := includeFlow(&denied)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(ok).Should(BeFalse())

	allowed := flowWithPolicy("allowed")
	ok, err = includeFlow(&allowed)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(ok).Should(BeTrue())
	Expect(allowed.Policies.Enforced[0].Name).Should(Equal(redactedByTest))
}

func TestFlows_RBACFilterFactoryError(t *testing.T) {
	// A factory failure (e.g. no authenticated user in the context) must fail
	// the request on every path, never fall through to unfiltered results.
	factory := auth.FlowFilterFactory(func(context.Context) (auth.FlowFilter, error) {
		return nil, errors.New("no user in context")
	})

	t.Run("list", func(t *testing.T) {
		sc := setupTest(t)
		backend := new(v1mocks.FlowsBackend)
		backend.On("List", mock.Anything, mock.Anything).Return(1, []whiskerv1.FlowResponse{flowWithPolicy("ns")}, nil)

		hdlr := hdlrv1.NewFlows(backend, hdlrv1.WithFlowFilterFactory(factory))
		rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{})
		Expect(rsp.Status()).Should(Equal(http.StatusInternalServerError))
	})

	t.Run("watch", func(t *testing.T) {
		sc := setupTest(t)
		backend := new(v1mocks.StreamingFlowsBackend)
		backend.On("Stream", mock.Anything, mock.Anything).Return(new(v1mocks.FlowStream), nil)

		hdlr := hdlrv1.NewFlows(backend, hdlrv1.WithFlowFilterFactory(factory))
		rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{Watch: true})
		Expect(rsp.Status()).Should(Equal(http.StatusInternalServerError))
	})

	t.Run("hints", func(t *testing.T) {
		sc := setupTest(t)
		backend := new(v1mocks.FlowsBackend)

		hdlr := hdlrv1.NewFlows(backend, hdlrv1.WithFlowFilterFactory(factory))
		rsp := hdlr.ListFilterHints(sc.apiCtx, whiskerv1.FlowFilterHintsRequest{
			Type: ptr.ToPtr(whiskerv1.FilterType(proto.FilterType_FilterTypeDestNamespace)),
		})
		Expect(rsp.Status()).Should(Equal(http.StatusInternalServerError))
	})
}
