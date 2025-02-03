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
	"unique"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

// matches returns true if the given flow matches the given filter.
func matches(filter *proto.Filter, flow *types.Flow) bool {
	if filter == nil {
		// No filter provided - all Flows match.
		return true
	}

	comps := []matcher{
		&simpleComparison[string]{filterVal: filter.SourceName, flowVal: flow.Key.SourceName},
		&simpleComparison[string]{filterVal: filter.DestName, flowVal: flow.Key.DestName},
		&simpleComparison[string]{filterVal: filter.SourceNamespace, flowVal: flow.Key.SourceNamespace},
		&simpleComparison[string]{filterVal: filter.DestNamespace, flowVal: flow.Key.DestNamespace},
		&simpleComparison[string]{filterVal: filter.Protocol, flowVal: flow.Key.Proto},
		&simpleComparison[int64]{filterVal: filter.DestPort, flowVal: flow.Key.DestPort},
		&policyComparison{filterVal: filter.Policy, flowVal: flow.Key.Policies},
	}
	for _, c := range comps {
		if !c.matches() {
			return false
		}
	}

	// All specified filters match. Return true.
	return true
}

type matcher interface {
	matches() bool
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

	// TODO: Should support partial matches in the case of strings.
	return c.filterVal == c.flowVal
}

type policyComparison struct {
	filterVal *proto.PolicyMatch
	flowVal   unique.Handle[types.PolicyTrace]
}

func (c policyComparison) matches() bool {
	// TODO: Implement policy comparison.
	return true
}
