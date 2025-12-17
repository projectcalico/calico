// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package goldmane

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

// listRequest is an internal helper used to synchronously request matching flows from the aggregator.
type listRequest struct {
	respCh chan *listResponse
	req    *proto.FlowListRequest
}

type listResponse struct {
	results *proto.FlowListResult
	err     error
}

// List returns a list of flows that match the given request. It uses a channel to
// synchronously request the flows from the aggregator.
func (a *Goldmane) List(req *proto.FlowListRequest) (*proto.FlowListResult, error) {
	respCh := make(chan *listResponse)
	defer close(respCh)
	a.listRequests <- listRequest{respCh, req}
	resp := <-respCh
	return resp.results, resp.err
}

func (a *Goldmane) queryFlows(req *proto.FlowListRequest) *listResponse {
	logrus.WithFields(logrus.Fields{"req": req}).Debug("Received flow request")

	// Sanitize the time range, resolving any relative time values.
	req.StartTimeGte, req.StartTimeLt = a.normalizeTimeRange(req.StartTimeGte, req.StartTimeLt)

	// Validate the request.
	if err := a.validateListRequest(req); err != nil {
		return &listResponse{nil, err}
	}

	flowsToReturn, meta, err := a.flowStore.List(req)
	if err != nil {
		logrus.WithError(err).Warn("Error listing flows")
		return &listResponse{nil, err}
	}

	return &listResponse{&proto.FlowListResult{
		Meta: &proto.ListMetadata{
			TotalPages:   int64(meta.TotalPages),
			TotalResults: int64(meta.TotalResults),
		},
		Flows: a.flowsToResult(flowsToReturn),
	}, nil}
}

// flowsToResult converts a list of internal Flow objects to a list of proto.FlowResult objects.
func (a *Goldmane) flowsToResult(flows []*types.Flow) []*proto.FlowResult {
	var flowsToReturn []*proto.FlowResult
	for _, flow := range flows {
		flowsToReturn = append(flowsToReturn, &proto.FlowResult{
			Flow: types.FlowToProto(flow),
			Id:   a.flowStore.ID(*flow.Key),
		})
	}
	return flowsToReturn
}

func (a *Goldmane) validateListRequest(req *proto.FlowListRequest) error {
	if err := a.validateTimeRange(req.StartTimeGte, req.StartTimeLt); err != nil {
		return err
	}
	if len(req.SortBy) > 1 {
		return fmt.Errorf("at most one sort order is supported")
	}
	return nil
}
