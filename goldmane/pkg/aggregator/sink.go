// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package aggregator

import "github.com/projectcalico/calico/goldmane/pkg/internal/types"

// Sink is an interface that can receive aggregated flows.
type Sink interface {
	Receive(*FlowCollection)
}

func NewFlowCollection(start, end int64) *FlowCollection {
	return &FlowCollection{
		StartTime: start,
		EndTime:   end,
		Flows:     make([]types.Flow, 0),
	}
}

type FlowCollection struct {
	StartTime int64
	EndTime   int64
	Flows     []types.Flow
}

func (fc *FlowCollection) AddFlow(flow types.Flow) {
	fc.Flows = append(fc.Flows, flow)
}
