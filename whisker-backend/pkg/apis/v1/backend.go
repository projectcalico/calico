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

package v1

import "context"

// FlowsBackend abstracts the flow data source so the handler is independent of
// the upstream (Goldmane, Linseed, etc.). Each upstream implements this interface
// and converts its native types to FlowResponse directly, avoiding lossy
// round-trips through intermediate representations.
//
// Streaming (watch) is an optional capability: upstreams that can stream flows
// additionally implement StreamingFlowsBackend. The handler detects support at
// runtime and rejects watch requests for upstreams that lack it, rather than
// every backend being forced to provide a no-op Stream.
type FlowsBackend interface {
	List(ctx context.Context, params ListFlowsParams) (totalPages int, flows []FlowResponse, err error)
	// FilterHints returns filter-value hints. includeFlow, when non-nil, gates the
	// source flows the hints are derived from so a user only sees values from
	// flows they are permitted to view (e.g. RBAC); without it an unscoped query
	// could leak names/namespaces/policies from namespaces the user cannot list.
	FilterHints(ctx context.Context, params FlowFilterHintsRequest, includeFlow FlowFilterFunc) (totalPages int, hints []FlowFilterHintResponse, err error)
}

// FlowFilterFunc reports whether a flow should be visible to the current user.
// It is the predicate form of the RBAC flow filter, passed to backends that
// derive results (e.g. filter hints) from a set of flows so they can drop flows
// the user cannot see before exposing any data from them.
type FlowFilterFunc func(flow *FlowResponse) (bool, error)

// StreamingFlowsBackend is a FlowsBackend that can also stream (watch) flows.
// Upstreams that cannot stream (e.g. Linseed) implement only FlowsBackend.
type StreamingFlowsBackend interface {
	FlowsBackend
	Stream(ctx context.Context, params ListFlowsParams) (FlowStream, error)
}

// FlowStream is an iterator over streamed flow results.
type FlowStream interface {
	Recv() (*FlowResponse, error)
}
