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

package auth_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	"github.com/projectcalico/calico/whisker-backend/pkg/auth"
)

// fakeFilter denies flows whose source namespace matches denyNamespace and
// stamps the enforced policy hits of admitted flows, so tests can verify both
// halves of the FlowFilter contract without a real authorizer.
type fakeFilter struct{ denyNamespace string }

func (f *fakeFilter) IncludeFlow(flow *whiskerv1.FlowResponse) (bool, error) {
	return flow.SourceNamespace != f.denyNamespace, nil
}

func (f *fakeFilter) RedactPolicies(flow *whiskerv1.FlowResponse) error {
	for _, h := range flow.Policies.Enforced {
		h.Name = "redacted-by-fake"
	}
	return nil
}

func fakeFactory(denyNamespace string) auth.FlowFilterFactory {
	return func(context.Context) (auth.FlowFilter, error) {
		return &fakeFilter{denyNamespace: denyNamespace}, nil
	}
}

func flowWithHit(ns string) whiskerv1.FlowResponse {
	return whiskerv1.FlowResponse{
		SourceNamespace: ns,
		Policies: whiskerv1.PolicyTrace{
			Enforced: []*whiskerv1.PolicyHit{{Name: "policy", Namespace: ns}},
		},
	}
}

func TestFilterPlumbing_List(t *testing.T) {
	flows := []whiskerv1.FlowResponse{flowWithHit("allowed"), flowWithHit("denied")}

	result, err := auth.FilterFlowsFromUser(context.Background(), flows, fakeFactory("denied"))
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, "allowed", result[0].SourceNamespace)
	// Admitted flows are redacted in place.
	require.Equal(t, "redacted-by-fake", result[0].Policies.Enforced[0].Name)
}

func TestFilterPlumbing_Func(t *testing.T) {
	includeFlow, err := auth.FilterFuncFromUser(context.Background(), fakeFactory("denied"))
	require.NoError(t, err)

	denied := flowWithHit("denied")
	ok, err := includeFlow(&denied)
	require.NoError(t, err)
	require.False(t, ok)

	allowed := flowWithHit("allowed")
	ok, err = includeFlow(&allowed)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "redacted-by-fake", allowed.Policies.Enforced[0].Name)
}

type fakeFlowStream struct {
	flows []*whiskerv1.FlowResponse
	idx   int
}

func (s *fakeFlowStream) Recv() (*whiskerv1.FlowResponse, error) {
	if s.idx >= len(s.flows) {
		return nil, io.EOF
	}
	f := s.flows[s.idx]
	s.idx++
	return f, nil
}

func TestFilterPlumbing_Stream(t *testing.T) {
	denied, allowed := flowWithHit("denied"), flowWithHit("allowed")
	inner := &fakeFlowStream{flows: []*whiskerv1.FlowResponse{&denied, &allowed}}

	stream, err := auth.FilterStreamFromUser(context.Background(), inner, fakeFactory("denied"))
	require.NoError(t, err)

	flow, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, "allowed", flow.SourceNamespace)
	require.Equal(t, "redacted-by-fake", flow.Policies.Enforced[0].Name)

	_, err = stream.Recv()
	require.Equal(t, io.EOF, err)
}

func TestFilterPlumbing_NilFactory(t *testing.T) {
	flows := []whiskerv1.FlowResponse{flowWithHit("any")}

	result, err := auth.FilterFlowsFromUser(context.Background(), flows, nil)
	require.NoError(t, err)
	require.Equal(t, flows, result)

	includeFlow, err := auth.FilterFuncFromUser(context.Background(), nil)
	require.NoError(t, err)
	require.Nil(t, includeFlow)

	inner := &fakeFlowStream{}
	stream, err := auth.FilterStreamFromUser(context.Background(), inner, nil)
	require.NoError(t, err)
	require.Equal(t, whiskerv1.FlowStream(inner), stream)
}

func TestFilterPlumbing_FactoryError(t *testing.T) {
	failing := func(context.Context) (auth.FlowFilter, error) {
		return nil, errors.New("no user")
	}

	_, err := auth.FilterFlowsFromUser(context.Background(), nil, failing)
	require.Error(t, err)
	_, err = auth.FilterFuncFromUser(context.Background(), failing)
	require.Error(t, err)
	_, err = auth.FilterStreamFromUser(context.Background(), nil, failing)
	require.Error(t, err)
}
