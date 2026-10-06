// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

type FlowProvider interface {
	Iter(*proto.Filter, func(FlowBuilder) bool)
}

type Receiver interface {
	Receive(FlowProvider, string)
}

// FlowBuilder provides an interface for building Flows. It allows us to conserve memory by
// only rendering Flow objects when they match the filter.
type FlowBuilder interface {
	BuildInto(*proto.Filter, *proto.FlowResult) bool
}

func NewDeferredFlowBuilder(d *DiachronicFlow, s, e int64) FlowBuilder {
	w, ok := d.bucketWindow(s, e)
	return &DeferredFlowBuilder{d: d, w: w, ok: ok}
}

// DeferredFlowBuilder is a FlowBuilder that defers the construction of the Flow object until it's needed.
type DeferredFlowBuilder struct {
	d *DiachronicFlow

	// w is a copy of the flow's window for the bucket, taken under the flow's lock, so BuildInto
	// can run on the gRPC goroutine without touching the live windows.
	w  Window
	ok bool
}

func (f *DeferredFlowBuilder) BuildInto(filter *proto.Filter, res *proto.FlowResult) bool {
	if !f.ok || (filter != nil && !types.Matches(filter, &f.d.Key)) {
		return false
	}
	tf := newAggregateFlow(f.d)
	f.d.aggregateWindow(tf, &f.w)
	types.FlowIntoProto(tf, res.Flow)
	res.Id = f.d.ID
	return true
}
