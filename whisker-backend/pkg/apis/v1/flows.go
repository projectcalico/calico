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
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/codec"
	"time"
)

const (
	sep = "/"

	FlowsPath       = sep + "flows"
	FlowsStreamPath = FlowsPath + sep + "_stream"
)

func init() {
	codec.RegisterCustomDecodeTypeFunc(func() {}, listFlowsSortBy(""))
}

type listFlowsSortBy string

const (
	listFlowsSortByDest listFlowsSortBy = "dest"
)

type ListFlowsParams struct {
	StartTimeGt time.Time       `urlParam:"startTimeGt"`
	StartTimeLt time.Time       `urlParam:"startTimeLt"`
	SortBy      listFlowsSortBy `urlParam:"sortBy"`

	Filters FlowsFilters
}

type StreamFlowsParams struct {
	Filters FlowsFilters
}

type FlowsFilters struct {
}

type FlowResponse struct {
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	Action          string    `json:"action"`
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
