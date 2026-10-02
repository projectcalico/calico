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

package goldmane

import (
	"context"
	"testing"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

// A steady flow of new streams must not stop the main loop from serving other work.
func TestBackfillsDoNotStarveMainLoop(t *testing.T) {
	sm := &busyStreamManager{backfills: make(chan stream.Stream, 1024)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			select {
			case sm.backfills <- &fakeStream{}:
			case <-ctx.Done():
				return
			}
		}
	}()

	gm := NewGoldmane(WithRolloverTime(time.Hour))
	gm.streams = sm
	<-gm.Run(time.Now().Unix())
	defer gm.Stop()

	done := make(chan struct{})
	go func() {
		_, _ = gm.Statistics(&proto.StatisticsRequest{Type: proto.StatisticType_PacketCount})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("statistics request not served while backfills were pending")
	}
}

type busyStreamManager struct {
	backfills chan stream.Stream
}

func (m *busyStreamManager) Run(context.Context) {}
func (m *busyStreamManager) Register(*proto.FlowStreamRequest, int) chan stream.Stream {
	return nil
}
func (m *busyStreamManager) Backfills() <-chan stream.Stream          { return m.backfills }
func (m *busyStreamManager) Receive(storage.FlowProvider, string)      {}
func (m *busyStreamManager) GoLive(string, int64)                      { time.Sleep(time.Millisecond) }

type fakeStream struct{}

func (s *fakeStream) Flows() <-chan storage.FlowBuilder { return nil }
func (s *fakeStream) Close()                            {}
func (s *fakeStream) Ctx() context.Context              { return context.Background() }
func (s *fakeStream) StartTimeGte() int64               { return 0 }
func (s *fakeStream) ID() string                        { return "fake" }
