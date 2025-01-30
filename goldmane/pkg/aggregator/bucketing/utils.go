// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bucketing

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
)

func GetStartTime(interval int) int64 {
	// Start time should always align to interval boundaries so that on restart
	// we can deterministically create a consistent set of buckets. e.g., if the interval is 30s,
	// then the start time should be a multiple of 30s.
	var startTime int64
	for {
		startTime = time.Now().Unix() + int64(interval)
		if startTime%int64(interval) == 0 {
			// We found a multiple - break out of the loop.
			break
		}
		logrus.WithField("start_time", startTime).Debug("Waiting for start time to align to interval")
		time.Sleep(1 * time.Second)
	}
	return startTime
}

// FlowCollection represents a collection of Flows and the time range they cover.
type FlowCollection struct {
	StartTime int64
	EndTime   int64
	Flows     []types.Flow
}

func NewFlowCollection(start, end int64) *FlowCollection {
	return &FlowCollection{
		StartTime: start,
		EndTime:   end,
		Flows:     make([]types.Flow, 0),
	}
}

// AddFlow adds a flow to the collection.
func (fc *FlowCollection) AddFlow(flow types.Flow) {
	fc.Flows = append(fc.Flows, flow)
}
