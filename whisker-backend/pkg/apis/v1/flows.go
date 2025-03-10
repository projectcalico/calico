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
	"fmt"
	"time"

	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/codec"
)

const (
	sep = "/"

	FlowsPath = sep + "flows"
)

func init() {
	// Register a decoder for the listFlowsSortBy.
	codec.RegisterCustomDecodeTypeFunc(func(vals []string) ([]proto.SortBy, error) {
		var values []proto.SortBy
		for _, v := range vals {
			if sortBy, exists := proto.SortBy_value[v]; exists {
				values = append(values, proto.SortBy(sortBy))
			} else {
				return nil, fmt.Errorf("unknown sortBy value: %s", vals[0])
			}
		}
		return values, nil
	})

	codec.RegisterURLQueryJSONType[Filters]()
}

type ListFlowsParams struct {
	Watch        bool           `urlQuery:"watch"`
	StartTimeGte int64          `urlQuery:"startTimeGte"`
	StartTimeLt  int64          `urlQuery:"startTimeLt"`
	SortBy       []proto.SortBy `urlQuery:"sortBy"`
	Filters      Filters        `urlQuery:"filters"`
}

type FilterMatch[E comparable] struct {
	V    E               `json:"value"`
	Type proto.MatchType `json:"type"`
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
	Actions          []proto.Action        `json:"actions,omitempty"`
}

type FlowResponse struct {
	StartTime       time.Time      `json:"start_time"`
	EndTime         time.Time      `json:"end_time"`
	Action          proto.Action   `json:"action"`
	SourceName      string         `json:"source_name"`
	SourceNamespace string         `json:"source_namespace"`
	SourceLabels    string         `json:"source_labels"`
	DestName        string         `json:"dest_name"`
	DestNamespace   string         `json:"dest_namespace"`
	DestLabels      string         `json:"dest_labels"`
	Protocol        string         `json:"protocol"`
	DestPort        int64          `json:"dest_port"`
	Reporter        proto.Reporter `json:"reporter"`
	Policies        PolicyTrace    `json:"policies"`
	PacketsIn       int64          `json:"packets_in"`
	PacketsOut      int64          `json:"packets_out"`
	BytesIn         int64          `json:"bytes_in"`
	BytesOut        int64          `json:"bytes_out"`
}

type PolicyTrace struct {
	Enforced []*PolicyHit `json:"enforced"`
	Pending  []*PolicyHit `json:"pending"`
}

type PolicyHit struct {
	Kind        proto.PolicyKind `json:"kind"`
	Name        string           `json:"name"`
	Namespace   string           `json:"namespace"`
	Tier        string           `json:"tier"`
	Action      proto.Action     `json:"action"`
	PolicyIndex int64            `json:"policy_index"`
	RuleIndex   int64            `json:"rule_index"`
	Trigger     *PolicyHit       `json:"trigger"`
}
