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
	"time"

	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/codec"
)

const (
	sep = "/"

	FlowsPath = sep + "flows"
)

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
type Actions []Action

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

type SortBy proto.SortBy
type SortBys []SortBy

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

func (p MatchType) String() string               { return proto.MatchType(p).String() }
func (p MatchType) MarshalJSON() ([]byte, error) { return marshalToBytes(p) }
func (p *MatchType) UnmarshalJSON(b []byte) error {
	return unmarshalProtoEnum(&p, b, proto.MatchType_value)
}
func (p MatchType) AsProto() proto.MatchType { return proto.MatchType(p) }

type Reporter proto.Reporter

func (p Reporter) String() string               { return proto.Reporter(p).String() }
func (p Reporter) MarshalJSON() ([]byte, error) { return marshalToBytes(p) }
func (p *Reporter) UnmarshalJSON(b []byte) error {
	return unmarshalProtoEnum(&p, b, proto.Reporter_value)
}
func (p Reporter) AsProto() proto.Reporter { return proto.Reporter(p) }

type PolicyKind proto.PolicyKind

func (p PolicyKind) String() string { return proto.PolicyKind(p).String() }

func (p PolicyKind) MarshalJSON() ([]byte, error) { return marshalToBytes(p) }
func (p *PolicyKind) UnmarshalJSON(b []byte) error {
	return unmarshalProtoEnum(&p, b, proto.PolicyKind_value)
}
func (p PolicyKind) AsProto() proto.PolicyKind { return proto.PolicyKind(p) }

func init() {
	// Register a decoder for the listFlowsSortBy.
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

	codec.RegisterURLQueryJSONType[Filters]()
}

type ListFlowsParams struct {
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
