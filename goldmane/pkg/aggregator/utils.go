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

package aggregator

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
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

// FlowBuilder provides an interface for building Flows. It allows us to conserve memory by
// only rendering Flow objects when they match the filter.
type FlowBuilder interface {
	// Build returns a Flow and its ID.
	Build(*proto.Filter) (*types.Flow, int64)
}

func NewCachedFlowBuilder(d *DiachronicFlow, s, e int64) FlowBuilder {
	return &cachedFlowBuilder{
		d: d,
		s: s,
		e: e,
	}
}

type cachedFlowBuilder struct {
	d *DiachronicFlow
	s int64
	e int64

	// cache the result in case we get called multiple times so we can
	// avoid re-aggregating the flow.
	cachedFlow *types.Flow
}

func (f *cachedFlowBuilder) Build(filter *proto.Filter) (*types.Flow, int64) {
	if types.Matches(filter, f.d.Key) {
		if f.cachedFlow == nil {
			logrus.WithFields(logrus.Fields{
				"start":  f.s,
				"end":    f.e,
				"flowID": f.d.ID,
			}).Debug("Building flow")

			flow := f.d.Aggregate(f.s, f.e)
			f.cachedFlow = flow
		}
		return f.cachedFlow, f.d.ID
	}
	return nil, 0
}
