// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package auth

import (
	"context"

	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

// FlowFilter decides whether a flow should be visible to the current user, and
// redacts the parts of an admitted flow the user is not authorized to view.
type FlowFilter interface {
	IncludeFlow(flow *whiskerv1.FlowResponse) (bool, error)
	// RedactPolicies obfuscates, in place, the policy hits on an admitted flow
	// that the user is not authorized to view. Callers must invoke it on every
	// flow IncludeFlow admits before exposing the flow.
	RedactPolicies(flow *whiskerv1.FlowResponse) error
}

// FlowFilterFactory creates a per-request FlowFilter from the request context.
// Implementations may return an error if the context lacks a required user.
type FlowFilterFactory func(ctx context.Context) (FlowFilter, error)

// filterFlows returns only the flows the given filter includes, with policy
// hits the user cannot view redacted. Ordering is preserved.
func filterFlows(flows []whiskerv1.FlowResponse, filter FlowFilter) ([]whiskerv1.FlowResponse, error) {
	var result []whiskerv1.FlowResponse
	for i := range flows {
		ok, err := filter.IncludeFlow(&flows[i])
		if err != nil {
			return nil, err
		}
		if ok {
			if err := filter.RedactPolicies(&flows[i]); err != nil {
				return nil, err
			}
			result = append(result, flows[i])
		}
	}
	return result, nil
}

// FilterFlowsFromUser is a convenience that extracts the user from the context,
// creates a FlowFilter, and filters the given flows.
func FilterFlowsFromUser(ctx context.Context, flows []whiskerv1.FlowResponse, factory FlowFilterFactory) ([]whiskerv1.FlowResponse, error) {
	if factory == nil {
		return flows, nil
	}
	filter, err := factory(ctx)
	if err != nil {
		return nil, err
	}
	return filterFlows(flows, filter)
}

// FilterFuncFromUser builds the per-request FlowFilter and returns it as a
// predicate, for callers (e.g. backends deriving filter hints) that need to
// gate flows incrementally rather than filter a slice. The predicate also
// redacts unauthorized policy hits, in place, on every flow it admits. Returns
// a nil func when no factory is configured.
func FilterFuncFromUser(ctx context.Context, factory FlowFilterFactory) (whiskerv1.FlowFilterFunc, error) {
	if factory == nil {
		return nil, nil
	}
	filter, err := factory(ctx)
	if err != nil {
		return nil, err
	}
	return func(flow *whiskerv1.FlowResponse) (bool, error) {
		ok, err := filter.IncludeFlow(flow)
		if err != nil || !ok {
			return ok, err
		}
		return true, filter.RedactPolicies(flow)
	}, nil
}

// FilterStreamFromUser wraps a FlowStream and filters out flows the user cannot
// see. The returned stream has the same Recv() contract as the inner stream.
func FilterStreamFromUser(ctx context.Context, inner whiskerv1.FlowStream, factory FlowFilterFactory) (whiskerv1.FlowStream, error) {
	if factory == nil {
		return inner, nil
	}
	filter, err := factory(ctx)
	if err != nil {
		return nil, err
	}
	return &filteredStream{inner: inner, filter: filter}, nil
}

type filteredStream struct {
	inner  whiskerv1.FlowStream
	filter FlowFilter
}

func (s *filteredStream) Recv() (*whiskerv1.FlowResponse, error) {
	for {
		flow, err := s.inner.Recv()
		if err != nil {
			return nil, err
		}
		ok, err := s.filter.IncludeFlow(flow)
		if err != nil {
			return nil, err
		}
		if ok {
			if err := s.filter.RedactPolicies(flow); err != nil {
				return nil, err
			}
			return flow, nil
		}
	}
}
