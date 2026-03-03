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
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/proto"
)

// filterHintsRequest is an internal helper used to synchronously request filter hints from the aggregator.
type filterHintsRequest struct {
	respCh chan *filterHintsResponse
	req    *proto.FilterHintsRequest
}

type filterHintsResponse struct {
	results *proto.FilterHintsResult
	err     error
}

func (a *Goldmane) Hints(req *proto.FilterHintsRequest) (*proto.FilterHintsResult, error) {
	logrus.WithField("req", req).Debug("Received hints request")

	respCh := make(chan *filterHintsResponse)
	defer close(respCh)
	a.filterHintsRequests <- filterHintsRequest{respCh, req}
	resp := <-respCh

	return resp.results, resp.err
}

func (a *Goldmane) queryFilterHints(req *proto.FilterHintsRequest) *filterHintsResponse {
	logrus.WithFields(logrus.Fields{"req": req}).Debug("Received filter hints request.")

	// Sanitize the time range, resolving any relative time values.
	req.StartTimeGte, req.StartTimeLt = a.normalizeTimeRange(req.StartTimeGte, req.StartTimeLt)

	// Validate the request.
	if err := a.validateTimeRange(req.StartTimeGte, req.StartTimeLt); err != nil {
		return &filterHintsResponse{nil, err}
	}

	values, meta, err := a.flowStore.FilterHints(req)
	if err != nil {
		logrus.WithError(err).Warn("Error listing filter hints")
		return &filterHintsResponse{nil, err}
	}

	var hints []*proto.FilterHint
	for _, value := range values {
		hints = append(hints, &proto.FilterHint{Value: value})
	}

	return &filterHintsResponse{&proto.FilterHintsResult{
		Meta: &proto.ListMetadata{
			TotalPages:   int64(meta.TotalPages),
			TotalResults: int64(meta.TotalResults),
		},
		Hints: hints,
	}, nil}
}
