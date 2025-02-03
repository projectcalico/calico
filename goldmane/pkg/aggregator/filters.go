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
	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

// Matches returns true if the given flow matches the given filter.
func Matches(filter *proto.Filter, flow *types.Flow) bool {
	if filter == nil {
		// No filter provided - all Flows match.
		return true
	}

	stringComps := []simpleComparison[string]{
		{filterVal: filter.SourceName, flowVal: flow.Key.SourceName},
		{filterVal: filter.DestName, flowVal: flow.Key.DestName},
		{filterVal: filter.SourceNamespace, flowVal: flow.Key.SourceNamespace},
		{filterVal: filter.DestNamespace, flowVal: flow.Key.DestNamespace},
		{filterVal: filter.Protocol, flowVal: flow.Key.Proto},
	}
	intComps := []simpleComparison[int64]{
		{filterVal: filter.DestPort, flowVal: flow.Key.DestPort},
	}
	for _, c := range stringComps {
		if !c.matches() {
			return false
		}
	}
	for _, c := range intComps {
		if !c.matches() {
			return false
		}
	}

	// TODO: Policy matching.

	// All specified filters match. Return true.
	return true
}

type simpleComparison[E comparable] struct {
	filterVal E
	flowVal   E
}

func (c simpleComparison[E]) matches() bool {
	var empty E
	if c.filterVal == empty {
		// No filter value specified, so this comparison matches.
		return true
	}
	return c.filterVal == c.flowVal
}
