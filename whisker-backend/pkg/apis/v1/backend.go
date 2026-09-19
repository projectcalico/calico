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

import (
	"context"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
)

// FlowsBackend abstracts the flow data source so the handler does not depend on
// any one upstream. Implementations convert their own types to FlowResponse.
//
// Streaming is optional: an upstream that can stream also implements
// StreamingFlowsBackend, and the handler rejects watch requests for one that
// does not.
type FlowsBackend interface {
	// List returns one page of flows and the page and result totals across all
	// pages. Pages are 0-based; a non-positive page size means everything in one
	// page.
	List(ctx context.Context, params ListFlowsParams) (meta apiutil.ListMeta, flows []FlowResponse, err error)

	// FilterHints returns one page of filter-value hints and the page and result
	// totals across all pages. includeFlow, when non-nil, gates the flows the
	// hints are derived from, so the response cannot leak values from flows the
	// caller may not see.
	FilterHints(ctx context.Context, params FlowFilterHintsRequest, includeFlow FlowFilterFunc) (meta apiutil.ListMeta, hints []FlowFilterHintResponse, err error)
}

// FlowFilterFunc reports whether a flow should be visible to the current user.
// It is the predicate form of the RBAC flow filter, passed to backends that
// derive results (e.g. filter hints) from a set of flows so they can drop flows
// the user cannot see before exposing any data from them.
type FlowFilterFunc func(flow *FlowResponse) (bool, error)

// StreamingFlowsBackend is a FlowsBackend that can also stream (watch) flows.
// An upstream that cannot stream implements only FlowsBackend.
type StreamingFlowsBackend interface {
	FlowsBackend
	Stream(ctx context.Context, params ListFlowsParams) (FlowStream, error)
}

// FlowStream is an iterator over streamed flow results.
type FlowStream interface {
	Recv() (*FlowResponse, error)
}
