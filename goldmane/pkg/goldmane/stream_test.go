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

package aggregator_test

import (
	"fmt"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

// Make sure we don't receive any duplicate flows. FlowKey is unique within a timeframe, so
// augment it with time information to get a globally unique ID across time.
type globalFlowID struct {
	key       types.FlowKey
	startTime int64
	endTime   int64
}

// enforcedFlowSet is a set of flows. It allows us to ensure that we don't receive duplicate flows.
type enforcedFlowSet struct {
	flows map[globalFlowID]struct{}
}

func newEnforcedFlowSet() *enforcedFlowSet {
	return &enforcedFlowSet{
		flows: make(map[globalFlowID]struct{}),
	}
}

// add adds a flow to the set. If the flow already exists, it returns an error.
func (fs *enforcedFlowSet) add(result *proto.FlowResult) error {
	flow := globalFlowID{
		key:       *types.ProtoToFlowKey(result.Flow.Key),
		startTime: result.Flow.StartTime,
		endTime:   result.Flow.EndTime,
	}
	if _, ok := fs.flows[flow]; ok {
		return fmt.Errorf("duplicate flow: %+v", result.Flow)
	}
	fs.flows[flow] = struct{}{}
	return nil
}
