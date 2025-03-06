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

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/codec"
)

const (
	sep = "/"

	FlowsPath = sep + "flows"
)

func init() {
	// Register a decoder for the listFlowsSortBy.
	codec.RegisterCustomDecodeTypeFunc(func(vals []string) ([]ListFlowsSortBy, error) {
		var values []ListFlowsSortBy
		for _, v := range vals {
			switch ListFlowsSortBy(v) {
			case ListFlowsSortByDefault, ListFlowsSortByDestName, ListFlowsSortBySrcName:
				values = append(values, ListFlowsSortBy(v))
			default:
				return nil, fmt.Errorf("unknown sortBy value: %s", vals[0])
			}
		}
		return values, nil
	})

	codec.RegisterURLQueryJSONType[Filters]()
}

// ListFlowsSortBy represents the different values you can use to sort by in the list flows API. It is unexported so that
// strings cannot be cast as this type external to this package, ensuring that users cannot set invalid sort by parameters
// to the API structs using this type.
//
// The decode function registered in the init function ensures that any string that would be decoded into this type is
// allowed, and fails to decode for invalid values.
type ListFlowsSortBy string

const (
	ListFlowsSortByDefault  ListFlowsSortBy = ""
	ListFlowsSortBySrcName  ListFlowsSortBy = "source_name"
	ListFlowsSortByDestName ListFlowsSortBy = "dest_name"
)

func (s ListFlowsSortBy) String() string {
	return string(s)
}

type MatchType string

const (
	MatchTypeExact MatchType = "exact"
	MatchTypeFuzzy MatchType = "fuzzy"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionPass  Action = "pass"
)

func (m MatchType) String() string {
	return string(m)
}

type ListFlowsParams struct {
	Watch        bool              `urlQuery:"watch"`
	StartTimeGte int64             `urlQuery:"startTimeGte"`
	StartTimeLt  int64             `urlQuery:"startTimeLt"`
	SortBy       []ListFlowsSortBy `urlQuery:"sortBy"`
	Filters      Filters           `urlQuery:"filters"`
}

type FilterMatch[E comparable] struct {
	V    E         `json:"value"`
	Type MatchType `json:"type"`
}

func (f FilterMatch[E]) setDefaults() FilterMatch[E] {
	if len(f.Type) == 0 {
		f.Type = MatchTypeExact
	}

	return f
}

type FilterMatches[E comparable] []FilterMatch[E]

func (f FilterMatches[E]) setDefaults() FilterMatches[E] {
	for i := range f {
		f[i] = f[i].setDefaults()
	}

	return f
}

func (p *ListFlowsParams) SetDefaults() {
	p.Filters = p.Filters.setDefaults()
}

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
	Actions          []Action              `json:"actions,omitempty"`
}

func (f Filters) setDefaults() Filters {
	f.SourceNames = f.SourceNames.setDefaults()
	f.SourceNamespaces = f.SourceNamespaces.setDefaults()
	f.DestNames = f.DestNames.setDefaults()
	f.DestNamespaces = f.DestNamespaces.setDefaults()
	f.Protocols = f.Protocols.setDefaults()
	f.DestPorts = f.DestPorts.setDefaults()

	return f
}

type FlowResponse struct {
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	Action          Action    `json:"action"`
	SourceName      string    `json:"source_name"`
	SourceNamespace string    `json:"source_namespace"`
	SourceLabels    string    `json:"source_labels"`
	DestName        string    `json:"dest_name"`
	DestNamespace   string    `json:"dest_namespace"`
	DestLabels      string    `json:"dest_labels"`
	Protocol        string    `json:"protocol"`
	DestPort        int64     `json:"dest_port"`
	Reporter        string    `json:"reporter"`
	PacketsIn       int64     `json:"packets_in"`
	PacketsOut      int64     `json:"packets_out"`
	BytesIn         int64     `json:"bytes_in"`
	BytesOut        int64     `json:"bytes_out"`
}
