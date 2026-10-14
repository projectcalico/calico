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

package goldmane_test

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

// Streams past the limit are rejected with an error, and a closed stream frees its slot.
func TestStreamLimit(t *testing.T) {
	aggregator := goldmane.NewGoldmane(goldmane.WithRolloverTime(time.Hour))
	<-aggregator.Run(time.Now().Unix())
	defer aggregator.Stop()

	var streams []stream.Stream
	for range 100 {
		s, err := aggregator.Stream(&proto.FlowStreamRequest{})
		if err != nil {
			t.Fatalf("stream %d: %v", len(streams), err)
		}
		streams = append(streams, s)
	}

	s, err := aggregator.Stream(&proto.FlowStreamRequest{})
	if status.Code(err) != codes.ResourceExhausted || s != nil {
		t.Fatalf("got stream %v, err %v; want ResourceExhausted", s, err)
	}

	streams[0].Close()
	s, err = aggregator.Stream(&proto.FlowStreamRequest{})
	if err != nil {
		t.Fatalf("stream after close: %v", err)
	}
	s.Close()
	for _, s := range streams[1:] {
		s.Close()
	}
}
