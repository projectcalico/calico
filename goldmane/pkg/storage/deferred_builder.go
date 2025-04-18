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

package storage

import (
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

// FlowBuilder provides an interface for building Flows. It allows us to conserve memory by
// only rendering Flow objects when they match the filter.
type FlowBuilder interface {
	BuildInto(*proto.Filter, *proto.FlowResult) bool
}

func NewDeferredFlowBuilder(d *DiachronicFlow, s, e int64) FlowBuilder {
	return &DeferredFlowBuilder{
		d: d,
		w: d.GetWindows(s, e),
		s: s,
		e: e,
	}
}

// DeferredFlowBuilder is a FlowBuilder that defers the construction of the Flow object until it's needed.
type DeferredFlowBuilder struct {
	d *DiachronicFlow
	s int64
	e int64

	// w is the set of windows that this flow is in at the time this builder is instantiated.
	// We hold references to the underlying Window objects so that we can aggregate across them on another
	// goroutine without worrying about the original DiachronicFlow windows being modified.
	//
	// Note: This is a bit of a hack, but it works for now. We can clean this up a lot by reconciling
	// the Window and AggregationBucket objects, which fill similar roles.
	w []*Window
}

func (f *DeferredFlowBuilder) BuildInto(filter *proto.Filter, res *proto.FlowResult) bool {
	if f.d.Matches(filter, f.s, f.e) {
		if tf := f.d.AggregateWindows(f.w); tf != nil {
			types.FlowIntoProto(tf, res.Flow)
			res.Id = f.d.ID
			return true
		}
	}
	return false
}
