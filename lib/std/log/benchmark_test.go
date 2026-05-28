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

package log

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// slowWriter discards every Write but pauses for `delay` per call.
// Simulates a slow downstream sink (terminal, container stdout consumer).
type slowWriter struct {
	delay time.Duration
}

func (w *slowWriter) Write(p []byte) (int, error) {
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
	return len(p), nil
}

// installBenchHook attaches a background log hook with the given writer/
// channel-size/disableLogDropping wired in, just like Configure does, but
// without going through Configure's sync.Once guard. Returns a cleanup
// function that restores logrus's prior state and lets the background
// goroutine exit.
func installBenchHook(tb testing.TB, w io.Writer, channelSize int, disableLogDropping bool) {
	tb.Helper()
	stdLogger := logrus.StandardLogger()
	origHooks := stdLogger.Hooks
	origFormatter := stdLogger.Formatter
	origLevel := stdLogger.Level
	origOut := stdLogger.Out

	stdLogger.SetFormatter(newFormatter("benchmark"))
	stdLogger.SetLevel(logrus.InfoLevel)

	ch := make(chan queuedLog, channelSize)
	dest := newStreamDestination(
		logrus.InfoLevel,
		w,
		ch,
		disableLogDropping,
		nil,
	)
	hook := newBackgroundHook(
		filterLevels(logrus.InfoLevel),
		logrus.PanicLevel,
		"benchmark",
		[]*destination{dest},
		nil,
		nil,
	)
	hook.start()
	stdLogger.ReplaceHooks(logrus.LevelHooks{})
	stdLogger.AddHook(hook)
	stdLogger.SetOutput(io.Discard)

	tb.Cleanup(func() {
		// Close the destination's channel so loopWritingLogs exits and
		// doesn't leak into subsequent benchmarks/tests.
		close(ch)
		stdLogger.ReplaceHooks(origHooks)
		stdLogger.SetFormatter(origFormatter)
		stdLogger.SetLevel(origLevel)
		stdLogger.SetOutput(origOut)
	})
}

// BenchmarkLogChannelDispatch measures throughput of log emission through
// the full backgroundHook.Fire path. Each iteration emits one log line
// across multiple goroutines.
//
// The single-goroutine number is the per-emission cost (formatter +
// findUserCaller + channel send + queue handoff). The parallel variant
// shows how contention on logrus's internal mutex affects throughput.
func BenchmarkLogChannelDispatch(b *testing.B) {
	cases := []struct {
		name          string
		writeDelay    time.Duration
		numGoroutines int
		channelSize   int
	}{
		{"serial/fast-writer", 0, 1, logQueueSize},
		{"parallel-4/fast-writer", 0, 4, logQueueSize},
		{"parallel-16/fast-writer", 0, 16, logQueueSize},
		{"parallel-16/slow-writer-200us", 200 * time.Microsecond, 16, 10_000},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			installBenchHook(b, &slowWriter{delay: c.writeDelay}, c.channelSize, true)

			b.ReportAllocs()
			b.ResetTimer()

			if c.numGoroutines <= 1 {
				for i := 0; i < b.N; i++ {
					logrus.WithField("i", i).Info("benchmark")
				}
				return
			}

			perG := b.N / c.numGoroutines
			extra := b.N % c.numGoroutines
			var wg sync.WaitGroup
			wg.Add(c.numGoroutines)
			for g := 0; g < c.numGoroutines; g++ {
				n := perG
				if g < extra {
					n++
				}
				go func(gid, n int) {
					defer wg.Done()
					for i := 0; i < n; i++ {
						logrus.WithField("g", gid).Info("benchmark")
					}
				}(g, n)
			}
			wg.Wait()
		})
	}
}

// BenchmarkLogChannelWorstCallerLatency reports the worst observed
// per-emission caller latency under heavy contention. With a small
// channel + disableLogDropping=true, the destination's send call blocks
// when the channel fills; this measures how long callers actually wait
// inside one log.Info under that pressure.
//
// Reported as a custom metric "max-caller-ns/op" via b.ReportMetric;
// ns/op itself is the average emission time (less interesting here).
func BenchmarkLogChannelWorstCallerLatency(b *testing.B) {
	const (
		writeDelay    = 200 * time.Microsecond
		numGoroutines = 16
		channelSize   = logQueueSize
	)

	installBenchHook(b, &slowWriter{delay: writeDelay}, channelSize, true)

	var maxLatencyNS int64

	b.ReportAllocs()
	b.ResetTimer()

	perG := b.N / numGoroutines
	extra := b.N % numGoroutines
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		n := perG
		if g < extra {
			n++
		}
		go func(gid, n int) {
			defer wg.Done()
			for i := 0; i < n; i++ {
				start := time.Now()
				logrus.WithField("g", gid).Info("benchmark")
				lat := int64(time.Since(start))
				for {
					prev := atomic.LoadInt64(&maxLatencyNS)
					if lat <= prev || atomic.CompareAndSwapInt64(&maxLatencyNS, prev, lat) {
						break
					}
				}
			}
		}(g, n)
	}
	wg.Wait()

	b.ReportMetric(float64(atomic.LoadInt64(&maxLatencyNS)), "max-caller-ns/op")
}
