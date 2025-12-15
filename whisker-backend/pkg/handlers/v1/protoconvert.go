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

	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

const (
	global = "Global"

	publicNetwork  = "PUBLIC NETWORK"
	privateNetwork = "PRIVATE NETWORK"

	pub = "pub"
	pvt = "pvt"
)

func toProtoStringMatches(matches []whiskerv1.FilterMatch[string], conv func(string) string) []*proto.StringMatch {
	var protos []*proto.StringMatch
	for _, match := range matches {
		val := match.V
		if conv != nil {
			val = conv(val)
		}
		protos = append(protos, &proto.StringMatch{
			Value: val,
			Type:  match.Type.AsProto(),
		})
	}

	return protos
}

func toProtoStringMatch(match whiskerv1.FilterMatch[string]) *proto.StringMatch {
	return &proto.StringMatch{
		Value: match.V,
		Type:  match.Type.AsProto(),
	}
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

func toProtoSortByOptions(sortBys whiskerv1.SortBys) []*proto.SortOption {
	var opts []*proto.SortOption
	for _, sortBy := range sortBys {
		opts = append(opts, &proto.SortOption{SortBy: sortBy.AsProto()})
	}

	return opts
}

func toProtoFilter(filters whiskerv1.Filters) *proto.Filter {
	return &proto.Filter{
		SourceNames:      toProtoStringMatches(filters.SourceNames, toProtoName),
		SourceNamespaces: toProtoStringMatches(filters.SourceNamespaces, toProtoNamespace),
		DestNames:        toProtoStringMatches(filters.DestNames, toProtoName),
		DestNamespaces:   toProtoStringMatches(filters.DestNamespaces, toProtoNamespace),
		Protocols:        toProtoStringMatches(filters.Protocols, nil),
		DestPorts:        toProtoPorts(filters.DestPorts),
		Actions:          filters.Actions.AsProtos(),
		PendingActions:   filters.PendingActions.AsProtos(),
		Policies:         toProtoPolicyMatch(filters.Policies),
		Reporter:         filters.Reporter.AsProto(),
	}
}

func toProtoPolicyMatch(policies []whiskerv1.PolicyMatch) []*proto.PolicyMatch {
	var protos []*proto.PolicyMatch
	for _, policy := range policies {
		protos = append(protos, &proto.PolicyMatch{
			Kind:      policy.Kind.AsProto(),
			Tier:      toProtoStringMatch(policy.Tier).Value,
			Name:      toProtoStringMatch(policy.Name).Value,
			Namespace: toProtoStringMatch(policy.Namespace).Value,
			Action:    policy.Action.AsProto(),
		})
	}
	return protos
}

func protoToPolicy(policyTrace *proto.PolicyTrace) whiskerv1.PolicyTrace {
	if policyTrace == nil {
		return whiskerv1.PolicyTrace{}
	}

	var enforced, pending []*whiskerv1.PolicyHit
	for _, hit := range policyTrace.EnforcedPolicies {
		enforced = append(enforced, protoToPolicyHit(hit))
	}
	for _, hit := range policyTrace.PendingPolicies {
		pending = append(pending, protoToPolicyHit(hit))
	}

	return whiskerv1.PolicyTrace{
		Enforced: enforced,
		Pending:  pending,
	}
}

func protoToPolicyHit(policyHit *proto.PolicyHit) *whiskerv1.PolicyHit {
	if policyHit == nil {
		return nil
	}

	return &whiskerv1.PolicyHit{
		Kind:        whiskerv1.PolicyKind(policyHit.Kind),
		Name:        policyHit.Name,
		Namespace:   policyHit.Namespace,
		Tier:        policyHit.Tier,
		Action:      whiskerv1.Action(policyHit.Action),
		PolicyIndex: policyHit.PolicyIndex,
		RuleIndex:   policyHit.RuleIndex,
		Trigger:     protoToPolicyHit(policyHit.Trigger),
	}
}

func protoToFlow(flow *proto.Flow) whiskerv1.FlowResponse {
	return whiskerv1.FlowResponse{
		StartTime: time.Unix(flow.StartTime, 0),
		EndTime:   time.Unix(flow.EndTime, 0),
		Action:    whiskerv1.Action(flow.Key.Action),

		SourceName:      protoToName(flow.Key.SourceName),
		SourceNamespace: flow.Key.SourceNamespace,
		SourceLabels:    strings.Join(flow.SourceLabels, " | "),

		DestName:      protoToName(flow.Key.DestName),
		DestNamespace: flow.Key.DestNamespace,
		DestLabels:    strings.Join(flow.DestLabels, " | "),

		Protocol:   flow.Key.Proto,
		DestPort:   flow.Key.DestPort,
		Reporter:   whiskerv1.Reporter(flow.Key.Reporter),
		Policies:   protoToPolicy(flow.Key.Policies),
		PacketsIn:  flow.PacketsIn,
		PacketsOut: flow.PacketsOut,
		BytesIn:    flow.BytesIn,
		BytesOut:   flow.BytesOut,
	}
}

// The Goldmane API uses an empty namespace to represent "no namespace", but the UI wants a value.
func protoToNamespace(namespace string) string {
	if namespace == "" || namespace == "-" {
		return global
	}
	return namespace
}

func toProtoNamespace(namespace string) string {
	if namespace == global {
		return "-"
	}
	return namespace
}

// The Goldmane API uses "pub" and "pvt" for special names - for public and private network spaces.
func protoToName(name string) string {
	switch name {
	case pub:
		return publicNetwork
	case pvt:
		return privateNetwork
	}
	return name
}

func toProtoName(name string) string {
	switch name {
	case publicNetwork:
		return pub
	case privateNetwork:
		return pvt
	}
	return name
}
