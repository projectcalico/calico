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

package stream_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/proto"
)

// activeStreams reads goldmane_num_streams from the default registry.
func activeStreams(t *testing.T) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "goldmane_num_streams" {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatal("goldmane_num_streams not registered")
	return 0
}

// A client closing its stream drops the gauge straight away, and closing it again doesn't
// drop it a second time.
func TestCloseUpdatesStreamGauge(t *testing.T) {
	base := activeStreams(t)
	sm := stream.NewStreamManager()

	s := sm.Register(&proto.FlowStreamRequest{}, 1)
	if got := activeStreams(t); got != base+1 {
		t.Fatalf("after register: gauge %v, want %v", got, base+1)
	}
	s.Close()
	if got := activeStreams(t); got != base {
		t.Fatalf("after close: gauge %v, want %v", got, base)
	}
	s.Close()
	if got := activeStreams(t); got != base {
		t.Fatalf("after second close: gauge %v, want %v", got, base)
	}
}

// A stream the manager closes for falling behind leaves the gauge once, even when its client
// closes it afterwards.
func TestOverflowCloseUpdatesStreamGaugeOnce(t *testing.T) {
	base := activeStreams(t)
	sm := stream.NewStreamManager()

	s := sm.Register(&proto.FlowStreamRequest{}, 1)
	for range 1000 {
		sm.Receive(twoFlows{}, "")
	}
	if got := activeStreams(t); got != base {
		t.Fatalf("after overflow: gauge %v, want %v", got, base)
	}
	s.Close()
	if got := activeStreams(t); got != base {
		t.Fatalf("after client close: gauge %v, want %v", got, base)
	}
}
