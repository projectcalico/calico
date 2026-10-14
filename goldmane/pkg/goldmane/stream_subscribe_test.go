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
	"sync"
	"testing"

	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const (
	interleaveRollovers = 30
	interleaveBackfill  = 5
)

// addLiveFlow adds a flow to the bucket holding the current time and waits until the main loop
// has stored it, so the bucket is complete before a rollover streams it.
func (s *streamBench) addLiveFlow() {
	now := s.clock.Now().Unix()
	s.gm.Receive(types.ProtoToFlow(testutils.NewRandomFlow(now)), "")

	deadline := time.Now().Add(5 * time.Second)
	for {
		res, err := s.gm.List(&proto.FlowListRequest{StartTimeGte: now, StartTimeLt: now + benchBucketSec})
		if err != nil {
			s.tb.Fatal(err)
		}
		if len(res.Flows) > 0 {
			return
		}
		if time.Now().After(deadline) {
			s.tb.Fatalf("flow at %d was never stored", now)
		}
		time.Sleep(time.Millisecond)
	}
}

// bucketStarts reads st until it goes quiet and returns the bucket start time of each flow.
func bucketStarts(st stream.Stream) []int64 {
	var starts []int64
	res := &proto.FlowResult{Flow: &proto.Flow{}}
	for {
		select {
		case f := <-st.Flows():
			if f.BuildInto(&proto.Filter{}, res) {
				starts = append(starts, res.Flow.StartTime)
			}
		case <-time.After(200 * time.Millisecond):
			return starts
		}
	}
}

// checkContiguous fails unless starts steps forward exactly one bucket at a time, which every
// stream sees when each bucket holds one flow and is sent once.
func checkContiguous(t *testing.T, name string, starts []int64) {
	t.Helper()
	if len(starts) == 0 {
		t.Fatalf("%s: no flows", name)
	}
	for i := 1; i < len(starts); i++ {
		if starts[i]-starts[i-1] != benchBucketSec {
			t.Fatalf("%s: bucket %d follows %d in %v", name, starts[i], starts[i-1], starts)
		}
	}
}

// Streams opened while rollovers fire must see each bucket once, in order, through to the last
// bucket streamed. Registering and backfilling in separate main loop steps let a rollover in
// between send a bucket twice or skip it.
func TestStreamOpenedDuringRolloversSeesEachBucketOnce(t *testing.T) {
	bench := newStreamBench(t)
	bench.fill(1)

	reference := bench.openStream(bench.clock.Now().Unix() - interleaveBackfill*benchBucketSec)
	if reference == nil {
		t.Fatal("reference stream rejected")
	}
	t.Cleanup(reference.Close)

	opened := make(chan stream.Stream, interleaveRollovers)
	for range interleaveRollovers {
		bench.addLiveFlow()
		start := bench.clock.Now().Unix() - interleaveBackfill*benchBucketSec
		go func() { opened <- bench.openStream(start) }()
		bench.rollover()
	}
	bench.fence()

	streams := make([]stream.Stream, interleaveRollovers)
	for i := range streams {
		streams[i] = <-opened
		if streams[i] == nil {
			t.Fatalf("stream %d rejected", i)
		}
		t.Cleanup(streams[i].Close)
	}

	want := bucketStarts(reference)
	checkContiguous(t, "reference", want)

	got := make([][]int64, len(streams))
	var wg sync.WaitGroup
	for i, st := range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i] = bucketStarts(st)
		}()
	}
	wg.Wait()

	last := want[len(want)-1]
	for i, starts := range got {
		checkContiguous(t, "stream", starts)
		if starts[len(starts)-1] != last {
			t.Fatalf("stream %d ends at bucket %d, reference ends at %d", i, starts[len(starts)-1], last)
		}
	}
}
