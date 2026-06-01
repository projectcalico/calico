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

package goldmane

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	climocks "github.com/projectcalico/calico/goldmane/pkg/client/mocks"
	"github.com/projectcalico/calico/goldmane/proto"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

// TestBackendListParameterConversion verifies that List translates ListFlowsParams
// (sort options, time bounds, and filters) into the expected proto.FlowListRequest
// before handing it to the underlying Goldmane client.
func TestBackendListParameterConversion(t *testing.T) {
	RegisterTestingT(t)

	now := time.Now()
	params := whiskerv1.ListFlowsParams{
		SortBy: whiskerv1.SortBys{
			whiskerv1.SortBy(proto.SortBy_SourceType), whiskerv1.SortBy(proto.SortBy_SourceNamespace), whiskerv1.SortBy(proto.SortBy_SourceName),
			whiskerv1.SortBy(proto.SortBy_DestType), whiskerv1.SortBy(proto.SortBy_DestNamespace), whiskerv1.SortBy(proto.SortBy_DestName),
			whiskerv1.SortBy(proto.SortBy_Time),
		},
		StartTimeGte: now.Unix(),
		Filters: whiskerv1.Filters{
			Policies: []whiskerv1.PolicyMatch{{
				Kind:      whiskerv1.PolicyKindCalicoNetworkPolicy,
				Tier:      whiskerv1.NewFilterMatch("default-tier", whiskerv1.MatchTypeExact),
				Name:      whiskerv1.NewFilterMatch("name", whiskerv1.MatchTypeExact),
				Namespace: whiskerv1.NewFilterMatch("namespace", whiskerv1.MatchTypeExact),
			}},
			SourceNamespaces: []whiskerv1.FilterMatch[string]{{V: "src-ns"}},
			SourceNames:      []whiskerv1.FilterMatch[string]{{V: "src-name"}},
			DestNamespaces:   []whiskerv1.FilterMatch[string]{{V: "dst-ns"}},
			DestNames:        []whiskerv1.FilterMatch[string]{{V: "dst-name"}},
			Protocols:        []whiskerv1.FilterMatch[string]{{V: "tcp"}},
			DestPorts:        []whiskerv1.FilterMatch[int64]{{V: 6060}},
			Actions:          whiskerv1.Actions{whiskerv1.Action(proto.Action_Pass), whiskerv1.Action(proto.Action_Allow)},
			PendingActions:   whiskerv1.PendingActions{whiskerv1.Action(proto.Action_Pass), whiskerv1.Action(proto.Action_Allow)},
			Reporter:         whiskerv1.ReporterSrc,
		},
	}

	expected := &proto.FlowListRequest{
		SortBy: []*proto.SortOption{
			{SortBy: proto.SortBy_SourceType}, {SortBy: proto.SortBy_SourceNamespace}, {SortBy: proto.SortBy_SourceName},
			{SortBy: proto.SortBy_DestType}, {SortBy: proto.SortBy_DestNamespace}, {SortBy: proto.SortBy_DestName},
			{SortBy: proto.SortBy_Time},
		},
		StartTimeGte: now.Unix(),
		Filter: &proto.Filter{
			Policies: []*proto.PolicyMatch{{
				Kind:      proto.PolicyKind_CalicoNetworkPolicy,
				Tier:      &proto.StringMatch{Value: "default-tier"},
				Name:      &proto.StringMatch{Value: "name"},
				Namespace: &proto.StringMatch{Value: "namespace"},
			}},
			SourceNamespaces: []*proto.StringMatch{{Value: "src-ns"}},
			SourceNames:      []*proto.StringMatch{{Value: "src-name"}},
			DestNamespaces:   []*proto.StringMatch{{Value: "dst-ns"}},
			DestNames:        []*proto.StringMatch{{Value: "dst-name"}},
			Protocols:        []*proto.StringMatch{{Value: "tcp"}},
			DestPorts:        []*proto.PortMatch{{Port: 6060}},
			Actions:          []proto.Action{proto.Action_Pass, proto.Action_Allow},
			PendingActions:   []proto.Action{proto.Action_Pass, proto.Action_Allow},
			Reporter:         proto.Reporter_Src,
		},
	}

	var req *proto.FlowListRequest
	cli := new(climocks.FlowsClient)
	cli.On("List", mock.Anything, mock.MatchedBy(func(arg *proto.FlowListRequest) bool {
		req = arg
		return true
	})).Return(nil, nil, context.Canceled).Once()

	_, _, err := NewBackend(cli).List(context.Background(), params)
	Expect(err).To(HaveOccurred())
	Expect(req.String()).To(Equal(expected.String()))
}

// TestBackendStreamParameterConversion verifies that Stream translates the time
// bound and filters of ListFlowsParams into the expected proto.FlowStreamRequest.
func TestBackendStreamParameterConversion(t *testing.T) {
	RegisterTestingT(t)

	now := time.Now()
	params := whiskerv1.ListFlowsParams{
		StartTimeGte: now.Unix(),
		Filters: whiskerv1.Filters{
			SourceNamespaces: []whiskerv1.FilterMatch[string]{{V: "src-ns"}},
			SourceNames:      []whiskerv1.FilterMatch[string]{{V: "src-name"}},
			DestNamespaces:   []whiskerv1.FilterMatch[string]{{V: "dst-ns"}},
			DestNames:        []whiskerv1.FilterMatch[string]{{V: "dst-name"}},
			Protocols:        []whiskerv1.FilterMatch[string]{{V: "tcp"}},
			DestPorts:        []whiskerv1.FilterMatch[int64]{{V: 6060}},
			Actions:          whiskerv1.Actions{whiskerv1.Action(proto.Action_Pass), whiskerv1.Action(proto.Action_Allow)},
			PendingActions:   whiskerv1.PendingActions{whiskerv1.Action(proto.Action_Pass), whiskerv1.Action(proto.Action_Allow)},
			Reporter:         whiskerv1.ReporterSrc,
			Policies: []whiskerv1.PolicyMatch{{
				Kind:      whiskerv1.PolicyKindCalicoNetworkPolicy,
				Tier:      whiskerv1.NewFilterMatch("default-tier", whiskerv1.MatchTypeExact),
				Name:      whiskerv1.NewFilterMatch("name", whiskerv1.MatchTypeExact),
				Namespace: whiskerv1.NewFilterMatch("namespace", whiskerv1.MatchTypeExact),
				Action:    whiskerv1.ActionDeny,
			}},
		},
	}

	expected := &proto.FlowStreamRequest{
		StartTimeGte: now.Unix(),
		Filter: &proto.Filter{
			SourceNamespaces: []*proto.StringMatch{{Value: "src-ns"}},
			SourceNames:      []*proto.StringMatch{{Value: "src-name"}},
			DestNamespaces:   []*proto.StringMatch{{Value: "dst-ns"}},
			DestNames:        []*proto.StringMatch{{Value: "dst-name"}},
			Protocols:        []*proto.StringMatch{{Value: "tcp"}},
			DestPorts:        []*proto.PortMatch{{Port: 6060}},
			Actions:          []proto.Action{proto.Action_Pass, proto.Action_Allow},
			PendingActions:   []proto.Action{proto.Action_Pass, proto.Action_Allow},
			Reporter:         proto.Reporter_Src,
			Policies: []*proto.PolicyMatch{{
				Kind:      proto.PolicyKind_CalicoNetworkPolicy,
				Tier:      &proto.StringMatch{Value: "default-tier"},
				Name:      &proto.StringMatch{Value: "name"},
				Namespace: &proto.StringMatch{Value: "namespace"},
				Action:    proto.Action_Deny,
			}},
		},
	}

	var req *proto.FlowStreamRequest
	cli := new(climocks.FlowsClient)
	cli.On("Stream", mock.Anything, mock.MatchedBy(func(arg *proto.FlowStreamRequest) bool {
		req = arg
		return true
	})).Return(nil, context.Canceled).Once()

	_, err := NewBackend(cli).Stream(context.Background(), params)
	Expect(err).To(HaveOccurred())
	Expect(req.String()).To(Equal(expected.String()))
}
