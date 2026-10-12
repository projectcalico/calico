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
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const (
	benchNow       = 100000
	benchBucketSec = 15
	benchHistory   = 240
)

type streamBench struct {
	tb     testing.TB
	gm     *goldmane.Goldmane
	roller *rolloverController
	clock  *clock
}

func newStreamBench(b *testing.B) *streamBench {
	logrus.SetLevel(logrus.ErrorLevel)
	c := newClock(benchNow)
	roller := &rolloverController{ch: make(chan time.Time), clock: c, aggregationWindowSecs: benchBucketSec}
	gm := goldmane.NewGoldmane(
		goldmane.WithRolloverFunc(roller.After),
		goldmane.WithNowFunc(c.Now),
	)
	<-gm.Run(c.Now().Unix())
	b.Cleanup(gm.Stop)
	return &streamBench{tb: b, gm: gm, roller: roller, clock: c}
}

// fence returns once the main loop has handled everything queued before it. It sends an
// inverted time range, which the main loop rejects without touching any flows.
func (s *streamBench) fence() {
	if _, err := s.gm.Statistics(&proto.StatisticsRequest{StartTimeGte: 10, StartTimeLt: 5}); err == nil {
		s.tb.Fatal("fence request was not rejected")
	}
}

func (s *streamBench) rollover() {
	now := s.clock.Now()
	s.clock.Advance(benchBucketSec * time.Second)
	s.roller.ch <- now
}

// openStream returns nil when the stream is rejected, so churn benchmarks can count rejections.
func (s *streamBench) openStream(start int64) stream.Stream {
	st, err := s.gm.Stream(&proto.FlowStreamRequest{StartTimeGte: start})
	if err != nil {
		return nil
	}
	return st
}

// fill puts perBucket distinct flows into each of the last benchHistory buckets.
func (s *streamBench) fill(perBucket int) {
	now := s.clock.Now().Unix()
	for k := int64(1); k <= benchHistory; k++ {
		for range perBucket {
			s.gm.Receive(types.ProtoToFlow(testutils.NewRandomFlow(now-k*benchBucketSec)), "")
		}
	}
	s.fence()
}

func (s *streamBench) openDrained(b *testing.B, start int64) stream.Stream {
	st, err := s.gm.Stream(&proto.FlowStreamRequest{StartTimeGte: start})
	if err != nil {
		b.Fatal(err)
	}
	go func() {
		res := &proto.FlowResult{Flow: &proto.Flow{}}
		for f := range st.Flows() {
			if f == nil {
				return
			}
			f.BuildInto(nil, res)
		}
	}()
	return st
}

// drainCount reads from st until n flows arrive, returning time to first flow.
func drainCount(b *testing.B, st stream.Stream, n int) time.Duration {
	start := time.Now()
	var first time.Duration
	res := &proto.FlowResult{Flow: &proto.Flow{}}
	for i := range n {
		select {
		case f := <-st.Flows():
			if i == 0 {
				first = time.Since(start)
			}
			f.BuildInto(nil, res)
		case <-time.After(5 * time.Second):
			b.Fatalf("got %d of %d flows", i, n)
		}
	}
	return first
}

func countBackfill(st stream.Stream) int {
	n := 0
	for {
		select {
		case <-st.Flows():
			n++
		case <-time.After(300 * time.Millisecond):
			return n
		}
	}
}

// BenchmarkStreamRolloverFanout times one rollover on the main loop with n live streams.
func BenchmarkStreamRolloverFanout(b *testing.B) {
	for _, n := range []int{0, 1, 10, 100} {
		b.Run(fmt.Sprintf("streams=%d", n), func(b *testing.B) {
			s := newStreamBench(b)
			for range n {
				st := s.openDrained(b, 0)
				b.Cleanup(st.Close)
			}
			s.fence()
			b.ReportAllocs()
			for b.Loop() {
				s.rollover()
				s.fence()
			}
		})
	}
}

// BenchmarkStreamRegisterBackfill opens a stream over full history and drains every backfilled flow.
func BenchmarkStreamRegisterBackfill(b *testing.B) {
	for _, perBucket := range []int{10, 100} {
		b.Run(fmt.Sprintf("flowsPerBucket=%d", perBucket), func(b *testing.B) {
			s := newStreamBench(b)
			s.fill(perBucket)
			start := s.clock.Now().Unix() - benchHistory*benchBucketSec

			probe, err := s.gm.Stream(&proto.FlowStreamRequest{StartTimeGte: start})
			if err != nil {
				b.Fatal(err)
			}
			want := countBackfill(probe)
			probe.Close()
			if want == 0 {
				b.Fatal("no backfilled flows")
			}

			var firstTotal time.Duration
			b.ReportAllocs()
			for b.Loop() {
				st, err := s.gm.Stream(&proto.FlowStreamRequest{StartTimeGte: start})
				if err != nil {
					b.Fatal(err)
				}
				firstTotal += drainCount(b, st, want)
				st.Close()
			}
			b.ReportMetric(float64(firstTotal.Nanoseconds())/float64(b.N), "first-flow-ns")
			b.ReportMetric(float64(want), "flows")
		})
	}
}

// BenchmarkStreamChurnMainLoopLatency measures main loop round trips while streams
// with full backfill open and close concurrently.
func BenchmarkStreamChurnMainLoopLatency(b *testing.B) {
	for _, churners := range []int{0, 4, 16} {
		b.Run(fmt.Sprintf("churners=%d", churners), func(b *testing.B) {
			s := newStreamBench(b)
			s.fill(100)
			start := s.clock.Now().Unix() - benchHistory*benchBucketSec

			stop := make(chan struct{})
			var wg sync.WaitGroup
			var opened, rejected atomic.Int64
			for range churners {
				wg.Go(func() {
					for {
						select {
						case <-stop:
							return
						default:
						}
						st := s.openStream(start)
						if st == nil {
							rejected.Add(1)
							continue
						}
						opened.Add(1)
						for range 1000 {
							if _, ok := <-st.Flows(); !ok {
								break
							}
						}
						st.Close()
					}
				})
			}

			var lat []time.Duration
			b.ReportAllocs()
			for b.Loop() {
				t := time.Now()
				s.fence()
				lat = append(lat, time.Since(t))
			}
			close(stop)
			wg.Wait()

			slices.Sort(lat)
			b.ReportMetric(float64(lat[len(lat)*99/100].Nanoseconds()), "p99-ns")
			b.ReportMetric(float64(lat[len(lat)-1].Nanoseconds()), "max-ns")
			b.ReportMetric(float64(opened.Load())/float64(b.N), "opens/op")
			b.ReportMetric(float64(rejected.Load()), "rejected")
		})
	}
}

// BenchmarkReceiveWithStreamChurn measures ingest while streams register and close.
func BenchmarkReceiveWithStreamChurn(b *testing.B) {
	for _, churners := range []int{0, 4, 16} {
		b.Run(fmt.Sprintf("churners=%d", churners), func(b *testing.B) {
			s := newStreamBench(b)
			now := s.clock.Now().Unix()
			fl := make([]*types.Flow, 1000)
			for i := range fl {
				fl[i] = types.ProtoToFlow(testutils.NewRandomFlow(now))
			}

			stop := make(chan struct{})
			var wg sync.WaitGroup
			var opened, rejected atomic.Int64
			for range churners {
				wg.Go(func() {
					for {
						select {
						case <-stop:
							return
						default:
						}
						if st := s.openStream(now - 60); st != nil {
							opened.Add(1)
							st.Close()
						} else {
							rejected.Add(1)
						}
					}
				})
			}

			i := 0
			b.ReportAllocs()
			for b.Loop() {
				s.gm.Receive(fl[i], "")
				i = (i + 1) % len(fl)
			}
			s.fence()
			close(stop)
			wg.Wait()
			b.ReportMetric(float64(opened.Load())/float64(b.N), "opens/op")
			b.ReportMetric(float64(rejected.Load()), "rejected")
		})
	}
}
