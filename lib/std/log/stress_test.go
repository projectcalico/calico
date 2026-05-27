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
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// slowWriter discards everything but takes `delay` per Write call. Simulates
// a slow downstream sink (terminal, container stdout consumer, etc.).
type slowWriter struct {
	delay   time.Duration
	writes  atomic.Int64
	bytesIn atomic.Int64
}

func (w *slowWriter) Write(p []byte) (int, error) {
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
	w.writes.Add(1)
	w.bytesIn.Add(int64(len(p)))
	return len(p), nil
}

// TestStressLogChannelDoesNotBlockCallers reproduces felix-FV conditions:
// DebugDisableLogDropping=true, screen-only destination, slow consumer.
//
// With the current channel-size=100 + blocking send, if N goroutines each
// emit M logs faster than the consumer can write, callers MUST block when
// the channel fills. This test measures the worst-case caller latency
// (time spent inside one log.Info call).
//
// What we expect to see if the channel-blocking hypothesis is correct:
//   - Total elapsed dominated by (numGoroutines*numLogs)*writeDelay (consumer-bound).
//   - p99 caller latency >> single write delay (callers waiting on full channel).
//
// What we'd see in a healthy world:
//   - Caller latency ≈ writeDelay (or instantaneous if channel has room).
func TestStressLogChannelDoesNotBlockCallers(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}

	// Felix-FV-like setup: DebugDisableLogDropping=true, single screen dest.
	const (
		writeDelay    = 1 * time.Millisecond
		numGoroutines = 4
		numLogsPerG   = 200
		// p99 budget = a little more than writeDelay; if any caller waits
		// substantially longer, the channel is blocking the foreground
		// goroutine.
		callerBudgetP99 = 50 * time.Millisecond
	)

	writer := &slowWriter{delay: writeDelay}

	// Reuse the std logger so we exercise the real Fire path. We replace
	// the formatter/output/hook for this test only.
	stdLogger := logrus.StandardLogger()
	origHooks := stdLogger.Hooks
	origFormatter := stdLogger.Formatter
	origLevel := stdLogger.Level
	origOut := stdLogger.Out
	t.Cleanup(func() {
		stdLogger.ReplaceHooks(origHooks)
		stdLogger.SetFormatter(origFormatter)
		stdLogger.SetLevel(origLevel)
		stdLogger.SetOutput(origOut)
	})

	stdLogger.SetFormatter(newFormatter("stresstest"))
	stdLogger.SetLevel(logrus.InfoLevel)

	dest := newStreamDestination(
		logrus.InfoLevel,
		writer,
		make(chan queuedLog, logQueueSize),
		true, // DebugDisableLogDropping == felix FV
		nil,  // no write-error counter
	)
	hook := newBackgroundHook(
		filterLevels(logrus.InfoLevel),
		logrus.PanicLevel, // no syslog
		"stresstest",
		[]*destination{dest},
		nil, // no debug filename regex
		nil, // no dropped counter
	)
	hook.start()
	stdLogger.ReplaceHooks(logrus.LevelHooks{})
	stdLogger.AddHook(hook)
	stdLogger.SetOutput(io.Discard)

	// Worst latency observed across all goroutines.
	var maxLatencyNS int64

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	start := time.Now()
	for g := 0; g < numGoroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < numLogsPerG; i++ {
				callStart := time.Now()
				logrus.WithField("g", gid).WithField("i", i).Info("stress")
				lat := time.Since(callStart)
				// Track max latency monotonically.
				for {
					prev := atomic.LoadInt64(&maxLatencyNS)
					if int64(lat) <= prev || atomic.CompareAndSwapInt64(&maxLatencyNS, prev, int64(lat)) {
						break
					}
				}
			}
		}(g)
	}
	wg.Wait()
	elapsed := time.Since(start)

	totalLogs := numGoroutines * numLogsPerG
	worstCaller := time.Duration(atomic.LoadInt64(&maxLatencyNS))
	t.Logf("total elapsed=%v over %d logs across %d goroutines (writeDelay=%v, writes=%d)",
		elapsed, totalLogs, numGoroutines, writeDelay, writer.writes.Load())
	t.Logf("worst caller latency=%v (budget p99=%v)", worstCaller, callerBudgetP99)

	if worstCaller > callerBudgetP99 {
		t.Errorf("a caller blocked for %v inside log.Info — channel is blocking the foreground", worstCaller)
	}
}

// TestStressLogChannelMatchesFelixFV is a bigger version that mimics felix
// FV's actual log volume: hundreds of small log lines per second from many
// goroutines, sustained over a few seconds.
func TestStressLogChannelMatchesFelixFV(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}

	const (
		writeDelay    = 200 * time.Microsecond // ~5k writes/sec ceiling
		numGoroutines = 64                     // many goroutines, like felix
		duration      = 2 * time.Second
	)

	writer := &slowWriter{delay: writeDelay}
	stdLogger := logrus.StandardLogger()
	origHooks := stdLogger.Hooks
	origFormatter := stdLogger.Formatter
	origLevel := stdLogger.Level
	origOut := stdLogger.Out
	t.Cleanup(func() {
		stdLogger.ReplaceHooks(origHooks)
		stdLogger.SetFormatter(origFormatter)
		stdLogger.SetLevel(origLevel)
		stdLogger.SetOutput(origOut)
	})

	stdLogger.SetFormatter(newFormatter("stresstest"))
	stdLogger.SetLevel(logrus.InfoLevel)
	dest := newStreamDestination(
		logrus.InfoLevel,
		writer,
		make(chan queuedLog, 10000), // big channel: rules out channel-fill blocking
		true,
		nil,
	)
	hook := newBackgroundHook(
		filterLevels(logrus.InfoLevel),
		logrus.PanicLevel,
		"stresstest",
		[]*destination{dest},
		nil,
		nil,
	)
	hook.start()
	stdLogger.ReplaceHooks(logrus.LevelHooks{})
	stdLogger.AddHook(hook)
	stdLogger.SetOutput(io.Discard)

	stop := make(chan struct{})
	var totalLogs atomic.Int64
	var maxLatencyNS int64

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				callStart := time.Now()
				logrus.WithField("g", gid).Info("stress2")
				lat := time.Since(callStart)
				totalLogs.Add(1)
				for {
					prev := atomic.LoadInt64(&maxLatencyNS)
					if int64(lat) <= prev || atomic.CompareAndSwapInt64(&maxLatencyNS, prev, int64(lat)) {
						break
					}
				}
			}
		}(g)
	}

	time.Sleep(duration)
	close(stop)
	wg.Wait()

	worst := time.Duration(atomic.LoadInt64(&maxLatencyNS))
	rate := float64(totalLogs.Load()) / duration.Seconds()
	fmt.Printf("STRESS: rate=%.0f logs/sec total=%d worst-caller-block=%v\n",
		rate, totalLogs.Load(), worst)
	t.Logf("rate=%.0f logs/sec, worst caller latency=%v", rate, worst)
}
