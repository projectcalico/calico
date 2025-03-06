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

package v1

import (
	"strings"
	"time"

	"github.com/projectcalico/calico/goldmane/proto"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

func toProtoStringMatches(matches []whiskerv1.FilterMatch[string]) []*proto.StringMatch {
	var protos []*proto.StringMatch
	for _, match := range matches {
		protos = append(protos, &proto.StringMatch{
			Value: match.V,
			Type:  toProtoMatchType(match.Type),
		})
	}

	return protos
}

func toProtoActions(actions []whiskerv1.Action) []proto.Action {
	var protos []proto.Action
	for _, action := range actions {
		protos = append(protos, toProtoAction(action))
	}

	return protos
}

func toProtoPorts(matches []whiskerv1.FilterMatch[int64]) []*proto.PortMatch {
	var protos []*proto.PortMatch
	for _, match := range matches {
		protos = append(protos, &proto.PortMatch{
			Port: match.V,
		})
	}

	return protos
}

func toProtoAction(action whiskerv1.Action) proto.Action {
	switch action {
	case whiskerv1.ActionAllow:
		return proto.Action_Allow
	case whiskerv1.ActionDeny:
		return proto.Action_Deny
	case whiskerv1.ActionPass:
		return proto.Action_Pass
	}

	return proto.Action_ActionUnspecified
}

func toProtoMatchType(t whiskerv1.MatchType) proto.MatchType {
	switch t {
	case whiskerv1.MatchTypeExact:
		return proto.MatchType_Exact
	case whiskerv1.MatchTypeFuzzy:
		return proto.MatchType_Fuzzy
	}

	return proto.MatchType_Exact
}

func toProtoSortBy(sortBys []whiskerv1.ListFlowsSortBy) []*proto.SortOption {
	var opts []*proto.SortOption
	for _, sortBy := range sortBys {
		switch sortBy {
		case whiskerv1.ListFlowsSortByTime:
			opts = append(opts, &proto.SortOption{SortBy: proto.SortBy_Time})
		case whiskerv1.ListFlowsSortByDestName:
			opts = append(opts, &proto.SortOption{SortBy: proto.SortBy_DestName})
		case whiskerv1.ListFlowsSortByDestNamespace:
			opts = append(opts, &proto.SortOption{SortBy: proto.SortBy_DestNamespace})
		case whiskerv1.ListFlowsSortByDestType:
			opts = append(opts, &proto.SortOption{SortBy: proto.SortBy_DestType})
		case whiskerv1.ListFlowsSortBySourceName:
			opts = append(opts, &proto.SortOption{SortBy: proto.SortBy_SourceName})
		case whiskerv1.ListFlowsSortBySourceNamespace:
			opts = append(opts, &proto.SortOption{SortBy: proto.SortBy_SourceNamespace})
		case whiskerv1.ListFlowsSortBySourceType:
			opts = append(opts, &proto.SortOption{SortBy: proto.SortBy_SourceType})
		}
	}

	return opts
}

func protoToReporter(reporter proto.Reporter) whiskerv1.Reporter {
	switch reporter {
	case proto.Reporter_Src:
		return whiskerv1.ReporterSrc
	case proto.Reporter_Dst:
		return whiskerv1.ReporterDest
	}

	return whiskerv1.ReporterUnknown
}

func protoToAction(action proto.Action) whiskerv1.Action {
	switch action {
	case proto.Action_Allow:
		return whiskerv1.ActionAllow
	case proto.Action_Deny:
		return whiskerv1.ActionDeny
	case proto.Action_Pass:
		return whiskerv1.ActionPass
	}

	return whiskerv1.ActionUnknown
}

func protoToFlow(flow *proto.Flow) whiskerv1.FlowResponse {
	return whiskerv1.FlowResponse{
		StartTime: time.Unix(flow.StartTime, 0),
		EndTime:   time.Unix(flow.EndTime, 0),
		Action:    protoToAction(flow.Key.Action),

		SourceName:      flow.Key.SourceName,
		SourceNamespace: flow.Key.SourceNamespace,
		SourceLabels:    strings.Join(flow.SourceLabels, " | "),

		DestName:      flow.Key.DestName,
		DestNamespace: flow.Key.DestNamespace,
		DestLabels:    strings.Join(flow.DestLabels, " | "),

		Protocol:   flow.Key.Proto,
		DestPort:   flow.Key.DestPort,
		Reporter:   protoToReporter(flow.Key.Reporter),
		PacketsIn:  flow.PacketsIn,
		PacketsOut: flow.PacketsOut,
		BytesIn:    flow.BytesIn,
		BytesOut:   flow.PacketsIn,
	}
}
