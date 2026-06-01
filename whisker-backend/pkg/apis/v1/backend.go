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
type FlowsBackend interface {
	List(ctx context.Context, params ListFlowsParams) (totalPages int, flows []FlowResponse, err error)
	Stream(ctx context.Context, params ListFlowsParams) (FlowStream, error)
	FilterHints(ctx context.Context, params FlowFilterHintsRequest) (totalPages int, hints []FlowFilterHintResponse, err error)
}

// FlowStream is an iterator over streamed flow results.
type FlowStream interface {
	Recv() (*FlowResponse, error)
}
