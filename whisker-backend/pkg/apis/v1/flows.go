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
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/codec"
	"github.com/projectcalico/calico/lib/std/time"
)

const (
	sep = "/"

	FlowsPath            = sep + "flows"
	FlowsFilterHintsPath = sep + "flows-filter-hints"
)

func init() {
	// Register a decoder for the SortBys.
	codec.RegisterCustomDecodeTypeFunc(func(vals []string) (SortBys, error) {
		var values []SortBy
		for _, v := range vals {
			if sortBy, exists := proto.SortBy_value[v]; exists {
				values = append(values, SortBy(sortBy))
			} else {
				return nil, fmt.Errorf("unknown sortBy value: %s", vals[0])
			}
		}
		return values, nil
	})

	// Register a decoder for the FilterType.
	codec.RegisterCustomDecodeTypeFunc(func(vals []string) (*FilterType, error) {
		for _, v := range vals {
			if filterType, exists := proto.FilterType_value["FilterType"+v]; exists {
				t := FilterType(filterType)
				return &t, nil
			}
		}

		allowedValues := slices.Collect(maps.Keys(proto.FilterType_value))
		for i, val := range allowedValues {
			allowedValues[i] = strings.TrimPrefix(val, "FilterType")
		}

		return nil, fmt.Errorf("unknown filter type value %s; allowed values are '%s'", vals[0], strings.Join(allowedValues, "', '"))
	})

	codec.RegisterURLQueryJSONType[Filters]()
}

func marshalToBytes(str interface{ String() string }) ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", str)), nil
}

// unmarshalProtoEnum unmarshals the bytes into the given int32 generic type (representing a proto enum) using the map
// provided.
//
// The parameter e is a pointer to a pointer, the reason being that pass a point makes a copy to that pointer
// so the assignment of `*e = <value>` wouldn't actually set the value for the given pointer.
//
// The use of this pointer to a pointer is so that the unmarshal functions for the int32 definitions can be consistently
// and easily made.
func unmarshalProtoEnum[E ~int32](e **E, b []byte, m map[string]int32) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}

	if a1, exists := m[str]; exists {
		**e = E(a1)
		return nil
	}
	return fmt.Errorf("unknown value: %s", str)
}

type Action proto.Action

const (
	ActionAllow Action = Action(proto.Action_Allow)
	ActionDeny  Action = Action(proto.Action_Deny)
	ActionPass  Action = Action(proto.Action_Pass)
)

type Actions []Action
type PendingActions []Action

func (p Action) String() string                { return proto.Action(p).String() }
func (p Action) MarshalJSON() ([]byte, error)  { return marshalToBytes(p) }
func (p *Action) UnmarshalJSON(b []byte) error { return unmarshalProtoEnum(&p, b, proto.Action_value) }
func (p Action) AsProto() proto.Action         { return proto.Action(p) }

func (a Actions) AsProtos() []proto.Action {
	var protos []proto.Action
	for _, a1 := range a {
		protos = append(protos, a1.AsProto())
	}
	return protos
}

func (a PendingActions) AsProtos() []proto.Action {
	var protos []proto.Action
	for _, a1 := range a {
		protos = append(protos, a1.AsProto())
	}
	return protos
}

type (
	SortBy  proto.SortBy
	SortBys []SortBy
)

func (p SortBy) String() string                { return proto.SortBy(p).String() }
func (p SortBy) MarshalJSON() ([]byte, error)  { return marshalToBytes(p) }
func (p *SortBy) UnmarshalJSON(b []byte) error { return unmarshalProtoEnum(&p, b, proto.SortBy_value) }
func (p SortBy) AsProto() proto.SortBy         { return proto.SortBy(p) }

func (ps SortBys) AsProtos() []proto.SortBy {
	var protos []proto.SortBy
	for _, p := range ps {
		protos = append(protos, p.AsProto())
	}
	return protos
}

type MatchType proto.MatchType

const (
	MatchTypeExact = MatchType(proto.MatchType_Exact)
	MatchTypeFuzzy = MatchType(proto.MatchType_Fuzzy)
)

func (p MatchType) String() string               { return proto.MatchType(p).String() }
func (p MatchType) MarshalJSON() ([]byte, error) { return marshalToBytes(p) }
func (p *MatchType) UnmarshalJSON(b []byte) error {
	return unmarshalProtoEnum(&p, b, proto.MatchType_value)
}
func (p MatchType) AsProto() proto.MatchType { return proto.MatchType(p) }

type Reporter proto.Reporter

const (
	ReporterSrc = Reporter(proto.Reporter_Src)
	ReporterDst = Reporter(proto.Reporter_Dst)
)

func (p Reporter) String() string               { return proto.Reporter(p).String() }
func (p Reporter) MarshalJSON() ([]byte, error) { return marshalToBytes(p) }
func (p *Reporter) UnmarshalJSON(b []byte) error {
	return unmarshalProtoEnum(&p, b, proto.Reporter_value)
}
func (p Reporter) AsProto() proto.Reporter { return proto.Reporter(p) }

type PolicyKind proto.PolicyKind

const (
	PolicyKindCalicoNetworkPolicy           = PolicyKind(proto.PolicyKind_CalicoNetworkPolicy)
	PolicyKindGlobalNetworkPolicy           = PolicyKind(proto.PolicyKind_GlobalNetworkPolicy)
	PolicyKindStagedNetworkPolicy           = PolicyKind(proto.PolicyKind_StagedNetworkPolicy)
	PolicyKindStagedGlobalNetworkPolicy     = PolicyKind(proto.PolicyKind_StagedGlobalNetworkPolicy)
	PolicyKindStagedKubernetesNetworkPolicy = PolicyKind(proto.PolicyKind_StagedKubernetesNetworkPolicy)

	PolicyKindNetworkPolicy        = PolicyKind(proto.PolicyKind_NetworkPolicy)
	PolicyKindClusterNetworkPolicy = PolicyKind(proto.PolicyKind_ClusterNetworkPolicy)

	PolicyKindProfile   = PolicyKind(proto.PolicyKind_Profile)
	PolicyKindEndOfTier = PolicyKind(proto.PolicyKind_EndOfTier)
)

func (p PolicyKind) String() string { return proto.PolicyKind(p).String() }

func (p PolicyKind) MarshalJSON() ([]byte, error) { return marshalToBytes(p) }
func (p *PolicyKind) UnmarshalJSON(b []byte) error {
	return unmarshalProtoEnum(&p, b, proto.PolicyKind_value)
}
func (p PolicyKind) AsProto() proto.PolicyKind { return proto.PolicyKind(p) }

type FilterType proto.FilterType

func (p FilterType) String() string               { return proto.FilterType(p).String() }
func (p FilterType) MarshalJSON() ([]byte, error) { return marshalToBytes(p) }
func (p *FilterType) UnmarshalJSON(b []byte) error {
	return unmarshalProtoEnum(&p, b, proto.FilterType_value)
}
func (p FilterType) AsProto() proto.FilterType { return proto.FilterType(p) }

type ListFlowsParams struct {
	Pagination `urlQuery:",inline"`

	Watch        bool    `urlQuery:"watch"`
	StartTimeGte int64   `urlQuery:"startTimeGte"`
	StartTimeLt  int64   `urlQuery:"startTimeLt"`
	SortBy       SortBys `urlQuery:"sortBy"`
	Filters      Filters `urlQuery:"filters"`
}

type FilterMatch[E comparable] struct {
	V    E         `json:"value"`
	Type MatchType `json:"type"`
}

func NewFilterMatch[E comparable](v E, matchType MatchType) FilterMatch[E] {
	return FilterMatch[E]{V: v, Type: matchType}
}

type FilterMatches[E comparable] []FilterMatch[E]

func (f FilterMatch[E]) Value() E {
	return f.V
}

type Filters struct {
	SourceNames      FilterMatches[string] `json:"source_names,omitempty"`
	SourceNamespaces FilterMatches[string] `json:"source_namespaces,omitempty"`
	DestNames        FilterMatches[string] `json:"dest_names,omitempty"`
	DestNamespaces   FilterMatches[string] `json:"dest_namespaces,omitempty"`
	Protocols        FilterMatches[string] `json:"protocols,omitempty"`
	DestPorts        FilterMatches[int64]  `json:"dest_ports,omitempty"`
	Actions          Actions               `json:"actions,omitempty"`
	PendingActions   PendingActions        `json:"pending_actions,omitempty"`
	Policies         []PolicyMatch         `json:"policies,omitempty"`
	Reporter         Reporter              `json:"reporter,omitempty"`
}

type PolicyMatch struct {
	Kind      PolicyKind          `json:"kind"`
	Tier      FilterMatch[string] `json:"tier"`
	Name      FilterMatch[string] `json:"name"`
	Namespace FilterMatch[string] `json:"namespace"`
	Action    Action              `json:"action"`
}

type FlowResponse struct {
	StartTime       time.Time   `json:"start_time"`
	EndTime         time.Time   `json:"end_time"`
	Action          Action      `json:"action"`
	SourceName      string      `json:"source_name"`
	SourceNamespace string      `json:"source_namespace"`
	SourceLabels    string      `json:"source_labels"`
	DestName        string      `json:"dest_name"`
	DestNamespace   string      `json:"dest_namespace"`
	DestLabels      string      `json:"dest_labels"`
	Protocol        string      `json:"protocol"`
	DestPort        int64       `json:"dest_port"`
	Reporter        Reporter    `json:"reporter"`
	Policies        PolicyTrace `json:"policies"`
	PacketsIn       int64       `json:"packets_in"`
	PacketsOut      int64       `json:"packets_out"`
	BytesIn         int64       `json:"bytes_in"`
	BytesOut        int64       `json:"bytes_out"`
}

type PolicyTrace struct {
	Enforced []*PolicyHit `json:"enforced"`
	Pending  []*PolicyHit `json:"pending"`
}

type PolicyHit struct {
	Kind        PolicyKind `json:"kind"`
	Name        string     `json:"name"`
	Namespace   string     `json:"namespace"`
	Tier        string     `json:"tier"`
	Action      Action     `json:"action"`
	PolicyIndex int64      `json:"policy_index"`
	RuleIndex   int64      `json:"rule_index"`
	Trigger     *PolicyHit `json:"trigger"`
}

type FlowFilterHintsRequest struct {
	Pagination `urlQuery:",inline"`

	// Type represents the filter type to get hints for.
	// Note that this is a pointer because the 0 value of the Filter type fails the required check.
	Type    *FilterType `urlQuery:"type" validate:"required"`
	Filters Filters     `urlQuery:"filters"`
}

type Pagination struct {
	Page     int `urlQuery:"page"`
	PageSize int `urlQuery:"pageSize"`
}

type FlowFilterHintResponse struct {
	Value string `json:"value"`
}
