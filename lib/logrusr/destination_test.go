// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
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

package logrusr_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	. "github.com/projectcalico/calico/lib/logrusr"
)

var testCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "test_counter",
	Help: "Number of logs dropped and errors encountered while logging.",
})

func init() {
	prometheus.MustRegister(testCounter)
}

// TestMain installs the Calico formatter on the standard logger so
// caller-reporting tests have the file:line in the emitted lines.
func TestMain(m *testing.M) {
	ConfigureFormatter("test")
	log.SetLevel(log.DebugLevel)
	os.Exit(m.Run())
}

// captureStandardLoggerOutput redirects logrus's standard logger to a
// buffer for the duration of the test.
func captureStandardLoggerOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	saved := log.StandardLogger().Out
	buf := &bytes.Buffer{}
	log.StandardLogger().Out = buf
	t.Cleanup(func() {
		log.StandardLogger().Out = saved
	})
	return buf
}

// ----- Caller reporting -----

func TestCallerReporting_LogInfo(t *testing.T) {
	buf := captureStandardLoggerOutput(t)
	log.Info("Test log")
	if !strings.Contains(buf.String(), "destination_test.go") {
		t.Errorf("expected destination_test.go in output: %s", buf.String())
	}
}

func TestCallerReporting_LoggerInfo(t *testing.T) {
	buf := captureStandardLoggerOutput(t)
	log.StandardLogger().Info("Test log")
	if !strings.Contains(buf.String(), "destination_test.go") {
		t.Errorf("expected destination_test.go in output: %s", buf.String())
	}
}

func TestCallerReporting_WithField(t *testing.T) {
	buf := captureStandardLoggerOutput(t)
	log.WithField("foo", "bar").Info("Test log")
	if !strings.Contains(buf.String(), "destination_test.go") {
		t.Errorf("expected destination_test.go in output: %s", buf.String())
	}
}

func TestCallerReporting_RateLimitedLogger(t *testing.T) {
	// The stack walker in GetFileInfo skips both logrus and lib/logrusr
	// frames, so a wrapper like RateLimitedLogger resolves to the file
	// that actually called it, not ratelimited.go.
	buf := captureStandardLoggerOutput(t)
	rl := NewRateLimitedLogger(OptInterval(time.Hour))
	rl.Info("Test log")
	out := buf.String()
	if !strings.Contains(out, "destination_test.go") {
		t.Errorf("expected destination_test.go in output: %s", out)
	}
	if strings.Contains(out, "ratelimited.go") {
		t.Errorf("did not expect ratelimited.go in output: %s", out)
	}
}

func TestLogrusAllLevelsInOrder(t *testing.T) {
	// Formatter.init() pre-computes various strings on this assumption.
	for idx, level := range log.AllLevels {
		if int(level) != idx {
			t.Errorf("log.AllLevels[%d] = %d, want %d", idx, level, idx)
		}
	}
}

// ----- Formatter -----

func TestFormatter(t *testing.T) {
	cases := []struct {
		name           string
		entry          log.Entry
		expectedLog    string
		expectedSyslog string
	}{
		{
			name:           "Empty",
			entry:          log.Entry{Caller: &runtime.Frame{}},
			expectedLog:    "0001-01-01 00:00:00.000 [PANIC][<PID>] . <nil>: \n",
			expectedSyslog: "PANIC . <nil>: \n",
		},
		{
			name: "Basic",
			entry: log.Entry{
				Level: log.InfoLevel,
				Time:  theTime(t),
				Caller: &runtime.Frame{
					File: "biff.com/bar/foo.go",
					Line: 123,
				},
				Data: log.Fields{
					"__flush__": true, // Internal value, should be ignored.
				},
				Message: "The answer is 42.",
			},
			expectedLog:    "2017-03-15 11:22:33.123 [INFO][<PID>] foo.go 123: The answer is 42.\n",
			expectedSyslog: "INFO foo.go 123: The answer is 42.\n",
		},
		{
			name: "With fields",
			entry: log.Entry{
				Level: log.WarnLevel,
				Time:  theTime(t),
				Caller: &runtime.Frame{
					File: "biff.com/bar/foo.go",
					Line: 123,
				},
				Data: log.Fields{
					"a":   10,
					"b":   "foobar",
					"c":   theTime(t),
					"err": errors.New("an error"),
				},
				Message: "The answer is 42.",
			},
			expectedLog:    "2017-03-15 11:22:33.123 [WARNING][<PID>] foo.go 123: The answer is 42. a=10 b=\"foobar\" c=2017-03-15 11:22:33.123 +0000 UTC err=an error\n",
			expectedSyslog: "WARNING foo.go 123: The answer is 42. a=10 b=\"foobar\" c=2017-03-15 11:22:33.123 +0000 UTC err=an error\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &Formatter{}
			out, err := f.Format(&tc.entry)
			if err != nil {
				t.Fatalf("Format returned error: %v", err)
			}
			expected := strings.Replace(tc.expectedLog, "<PID>", fmt.Sprintf("%v", os.Getpid()), 1)
			if string(out) != expected {
				t.Errorf("Format output mismatch\n  got:  %q\n  want: %q", string(out), expected)
			}
			if got := FormatForSyslog(&tc.entry); got != tc.expectedSyslog {
				t.Errorf("FormatForSyslog output mismatch\n  got:  %q\n  want: %q", got, tc.expectedSyslog)
			}
		})
	}
}

func theTime(t *testing.T) time.Time {
	t.Helper()
	tm, err := time.Parse("2006-01-02 15:04:05.000", "2017-03-15 11:22:33.123")
	if err != nil {
		t.Fatalf("time.Parse: %v", err)
	}
	return tm
}

// ----- BackgroundHook -----

var (
	message1 = QueuedLog{
		Level:         log.InfoLevel,
		Message:       []byte("Message"),
		SyslogMessage: "syslog message",
	}
	message2 = QueuedLog{
		Level:         log.InfoLevel,
		Message:       []byte("Message2"),
		SyslogMessage: "syslog message2",
	}
)

// backgroundHookHarness wires a BackgroundHook up to a channel-backed
// destination and returns everything a test needs to drive it.
type backgroundHookHarness struct {
	c      chan QueuedLog
	logger *log.Logger
}

func newBackgroundHookHarness(t *testing.T, name string, opts ...BackgroundHookOpt) backgroundHookHarness {
	t.Helper()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "logutilstests",
		Name:      name,
	})
	c := make(chan QueuedLog, 10)
	testDest := &Destination{
		Level:   log.DebugLevel,
		Channel: c,
	}
	bh := NewBackgroundHook(log.AllLevels, log.DebugLevel, []*Destination{testDest}, counter, opts...)

	logger := log.New()
	logger.SetReportCaller(true)
	logger.AddHook(bh)
	logger.SetLevel(log.DebugLevel)
	logger.Out = &NullWriter{}

	return backgroundHookHarness{c: c, logger: logger}
}

func TestBackgroundHook_LetsDebugThrough(t *testing.T) {
	h := newBackgroundHookHarness(t, "debug_through")
	h.logger.Debug("Hello")
	ql := expectReceive(t, h.c, time.Second)
	if !strings.Contains(string(ql.Message), "level=debug msg=Hello") {
		t.Errorf("unexpected message: %s", string(ql.Message))
	}
}

func TestBackgroundHook_DebugFilterRejectsUnmatched(t *testing.T) {
	h := newBackgroundHookHarness(t, "debug_filter_reject",
		WithDebugFileRegexp(regexp.MustCompile("another_file_for_test")))
	h.logger.Debug("Hello")
	expectNoReceive(t, h.c, 50*time.Millisecond)
}

func TestBackgroundHook_DebugFilterAcceptsMatched(t *testing.T) {
	h := newBackgroundHookHarness(t, "debug_filter_accept",
		WithDebugFileRegexp(regexp.MustCompile("another_file_for_test")))
	debugFromAnotherFile(h.logger, "What?")
	ql := expectReceive(t, h.c, time.Second)
	if !strings.Contains(string(ql.Message), `level=debug msg="What?"`) {
		t.Errorf("unexpected message: %s", string(ql.Message))
	}
}

func TestBackgroundHook_DebugFilterDoesNotAffectInfo(t *testing.T) {
	h := newBackgroundHookHarness(t, "debug_filter_info",
		WithDebugFileRegexp(regexp.MustCompile("another_file_for_test")))
	h.logger.Info("Hello")
	ql := expectReceive(t, h.c, time.Second)
	if !strings.Contains(string(ql.Message), `level=info msg=Hello`) {
		t.Errorf("unexpected message: %s", string(ql.Message))
	}
}

func TestBackgroundHook_PanicBlocksForBackgroundThread(t *testing.T) {
	h := newBackgroundHookHarness(t, "panic_blocks")

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = recover() }() // logger.Panic panics; swallow it here.
		h.logger.Panic("Should flush")
	}()

	ql := expectReceive(t, h.c, time.Second)
	if ql.WaitGroup == nil {
		t.Fatalf("expected WaitGroup on queued log")
	}
	// Should still be blocked on the WaitGroup.
	expectNotClosed(t, done, 50*time.Millisecond)
	ql.WaitGroup.Done()
	expectClosed(t, done, time.Second)
}

func TestBackgroundHook_ForceFlushBlocksForBackgroundThread(t *testing.T) {
	h := newBackgroundHookHarness(t, "force_flush_blocks")

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.logger.WithField(FieldForceFlush, true).Info("Should flush")
	}()

	ql := expectReceive(t, h.c, time.Second)
	if ql.WaitGroup == nil {
		t.Fatalf("expected WaitGroup on queued log")
	}
	expectNotClosed(t, done, 50*time.Millisecond)
	ql.WaitGroup.Done()
	expectClosed(t, done, time.Second)
}

func TestBackgroundHook_NormalInfoDoesNotBlock(t *testing.T) {
	h := newBackgroundHookHarness(t, "normal_info_no_block")

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.logger.Info("Should not flush")
	}()

	ql := expectReceive(t, h.c, time.Second)
	if ql.WaitGroup != nil {
		t.Fatalf("expected no WaitGroup on queued log, got %v", ql.WaitGroup)
	}
	expectClosed(t, done, time.Second)
}

// ----- Stream Destination -----

func newStreamDest(t *testing.T, dropDisabled bool) (*Destination, chan QueuedLog, *io.PipeReader, *io.PipeWriter) {
	t.Helper()
	c := make(chan QueuedLog, 1)
	pr, pw := io.Pipe()
	s := NewStreamDestination(log.InfoLevel, pw, c, dropDisabled, testCounter)
	return s, c, pr, pw
}

func TestStreamDestination_ReportsDroppedLogs(t *testing.T) {
	s, c, _, _ := newStreamDest(t, false)
	// First message should be queued.
	if !s.Send(message1) {
		t.Fatalf("first Send should succeed")
	}
	// Second message should be dropped.
	if s.Send(message1) {
		t.Fatalf("second Send should fail (channel full)")
	}
	// Drain the queue.
	if got := <-c; !queuedLogEqual(got, message1) {
		t.Fatalf("drain: got %+v want %+v", got, message1)
	}
	// Third message should go through with NumSkippedLogs=1.
	if !s.Send(message1) {
		t.Fatalf("third Send should succeed")
	}
	want := message1
	want.NumSkippedLogs = 1
	if got := <-c; !queuedLogEqual(got, want) {
		t.Fatalf("dropped-report: got %+v want %+v", got, want)
	}
	// Counter resets on subsequent messages.
	if !s.Send(message1) {
		t.Fatalf("fourth Send should succeed")
	}
	if got := <-c; !queuedLogEqual(got, message1) {
		t.Fatalf("after reset: got %+v want %+v", got, message1)
	}
}

func TestStreamDestination_DroppingDisabledBlocks(t *testing.T) {
	s, c, _, _ := newStreamDest(t, true)
	if !s.Send(message1) {
		t.Fatalf("first Send should succeed")
	}
	done := make(chan bool, 1)
	go func() {
		// Second Send will block since the channel is full and dropping is disabled.
		done <- s.Send(message2)
	}()
	// Give the goroutine a chance to try to write.
	time.Sleep(10 * time.Millisecond)
	if got := <-c; !queuedLogEqual(got, message1) {
		t.Fatalf("first drain: got %+v want %+v", got, message1)
	}
	if got := <-c; !queuedLogEqual(got, message2) {
		t.Fatalf("second drain: got %+v want %+v", got, message2)
	}
	if !<-done {
		t.Fatalf("blocked Send should have returned true")
	}
}

func TestStreamDestination_LoopWritingLogs_Basic(t *testing.T) {
	s, _, pr, _ := newStreamDest(t, false)
	go s.LoopWritingLogs()
	t.Cleanup(func() { s.Close() })

	if !s.Send(message1) {
		t.Fatalf("Send failed")
	}
	if got := readMsg(t, pr); got != "Message" {
		t.Fatalf("got %q want %q", got, "Message")
	}
}

func TestStreamDestination_LoopWritingLogs_ReportsDropped(t *testing.T) {
	s, c, pr, _ := newStreamDest(t, false)
	go s.LoopWritingLogs()
	t.Cleanup(func() { s.Close() })

	// Bypass Send() to force NumSkippedLogs.
	c <- QueuedLog{
		Level:          log.InfoLevel,
		Message:        []byte("Message"),
		SyslogMessage:  "syslog message",
		NumSkippedLogs: 1,
	}
	if got := readMsg(t, pr); got != "... dropped 1 logs ...\n" {
		t.Fatalf("dropped notice: got %q", got)
	}
	if got := readMsg(t, pr); got != "Message" {
		t.Fatalf("message: got %q", got)
	}
}

func TestStreamDestination_LoopWritingLogs_TriggersWaitGroup(t *testing.T) {
	s, c, pr, _ := newStreamDest(t, false)
	go s.LoopWritingLogs()
	t.Cleanup(func() { s.Close() })

	wg := &sync.WaitGroup{}
	wg.Add(1)
	c <- QueuedLog{
		Level:         log.InfoLevel,
		Message:       []byte("Message"),
		SyslogMessage: "syslog message",
		WaitGroup:     wg,
	}
	got := readMsg(t, pr)
	wg.Wait()
	if got != "Message" {
		t.Fatalf("got %q want %q", got, "Message")
	}
}

// ----- Syslog Destination -----

func newSyslogDest(t *testing.T, dropDisabled bool) (*Destination, chan QueuedLog, *io.PipeReader, *io.PipeWriter) {
	t.Helper()
	c := make(chan QueuedLog, 1)
	pr, pw := io.Pipe()
	s := NewSyslogDestination(log.InfoLevel, (*mockSyslogWriter)(pw), c, dropDisabled, testCounter)
	return s, c, pr, pw
}

func TestSyslogDestination_DroppingDisabledBlocks(t *testing.T) {
	s, c, _, _ := newSyslogDest(t, true)
	if !s.Send(message1) {
		t.Fatalf("first Send should succeed")
	}
	done := make(chan bool, 1)
	go func() {
		done <- s.Send(message2)
	}()
	time.Sleep(10 * time.Millisecond)
	if got := <-c; !queuedLogEqual(got, message1) {
		t.Fatalf("first drain: got %+v want %+v", got, message1)
	}
	if got := <-c; !queuedLogEqual(got, message2) {
		t.Fatalf("second drain: got %+v want %+v", got, message2)
	}
	if !<-done {
		t.Fatalf("blocked Send should have returned true")
	}
}

func TestSyslogDestination_LoopWritingLogs_LevelPrefix(t *testing.T) {
	cases := []struct {
		level log.Level
		name  string
	}{
		{log.InfoLevel, "INFO"},
		{log.WarnLevel, "WARNING"},
		{log.DebugLevel, "DEBUG"},
		{log.ErrorLevel, "ERROR"},
		{log.FatalLevel, "CRITICAL"},
		{log.PanicLevel, "CRITICAL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, ch, pr, _ := newSyslogDest(t, false)
			go s.LoopWritingLogs()
			t.Cleanup(func() { s.Close() })

			ql := message1
			ql.Level = c.level
			if !s.Send(ql) {
				t.Fatalf("Send failed")
			}
			// Prevent the unused-variable lint.
			_ = ch
			if got := readMsg(t, pr); got != c.name+" syslog message" {
				t.Fatalf("got %q want %q", got, c.name+" syslog message")
			}
		})
	}
}

func TestSyslogDestination_LoopWritingLogs_ReportsDropped(t *testing.T) {
	s, c, pr, _ := newSyslogDest(t, false)
	go s.LoopWritingLogs()
	t.Cleanup(func() { s.Close() })

	c <- QueuedLog{
		Level:          log.InfoLevel,
		Message:        []byte("Message"),
		SyslogMessage:  "syslog message",
		NumSkippedLogs: 1,
	}
	if got := readMsg(t, pr); got != "WARNING ... dropped 1 logs ...\n" {
		t.Fatalf("dropped notice: got %q", got)
	}
	if got := readMsg(t, pr); got != "INFO syslog message" {
		t.Fatalf("message: got %q", got)
	}
}

func TestSyslogDestination_LoopWritingLogs_TriggersWaitGroup(t *testing.T) {
	s, c, pr, _ := newSyslogDest(t, false)
	go s.LoopWritingLogs()
	t.Cleanup(func() { s.Close() })

	wg := &sync.WaitGroup{}
	wg.Add(1)
	c <- QueuedLog{
		Level:         log.InfoLevel,
		Message:       []byte("Message"),
		SyslogMessage: "syslog message",
		WaitGroup:     wg,
	}
	got := readMsg(t, pr)
	wg.Wait()
	if got != "INFO syslog message" {
		t.Fatalf("got %q want %q", got, "INFO syslog message")
	}
}

// ----- Helpers -----

// expectReceive waits for a value on c up to timeout, failing the test if
// nothing arrives.
func expectReceive(t *testing.T, c <-chan QueuedLog, timeout time.Duration) QueuedLog {
	t.Helper()
	select {
	case ql := <-c:
		return ql
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for QueuedLog after %v", timeout)
		return QueuedLog{}
	}
}

// expectNoReceive fails the test if a value arrives on c within timeout.
func expectNoReceive(t *testing.T, c <-chan QueuedLog, timeout time.Duration) {
	t.Helper()
	select {
	case ql := <-c:
		t.Fatalf("did not expect a QueuedLog but got %+v", ql)
	case <-time.After(timeout):
	}
}

// expectClosed waits up to timeout for c to be closed.
func expectClosed(t *testing.T, c <-chan struct{}, timeout time.Duration) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(timeout):
		t.Fatalf("channel not closed within %v", timeout)
	}
}

// expectNotClosed fails the test if c closes within timeout.
func expectNotClosed(t *testing.T, c <-chan struct{}, timeout time.Duration) {
	t.Helper()
	select {
	case <-c:
		t.Fatalf("channel closed unexpectedly within %v", timeout)
	case <-time.After(timeout):
	}
}

// readMsg reads one message from a pipe with a 1s timeout. Reading is
// blocking, so we run it in a goroutine and select on a timer.
func readMsg(t *testing.T, pr *io.PipeReader) string {
	t.Helper()
	type result struct {
		s   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		b := make([]byte, 1024)
		n, err := pr.Read(b)
		ch <- result{s: string(b[:n]), err: err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("pipe read: %v", r.err)
		}
		return r.s
	case <-time.After(time.Second):
		t.Fatalf("pipe read timed out")
		return ""
	}
}

// queuedLogEqual compares two QueuedLog values on their public fields
// (Message is []byte so Go's == doesn't work).
func queuedLogEqual(a, b QueuedLog) bool {
	if a.Level != b.Level {
		return false
	}
	if !bytes.Equal(a.Message, b.Message) {
		return false
	}
	if a.SyslogMessage != b.SyslogMessage {
		return false
	}
	if a.NumSkippedLogs != b.NumSkippedLogs {
		return false
	}
	return a.WaitGroup == b.WaitGroup
}

// ----- Mock syslog writer -----

type mockSyslogWriter io.PipeWriter

func (s *mockSyslogWriter) Debug(m string) error {
	_, err := fmt.Fprintf((*io.PipeWriter)(s), "DEBUG %s", m)
	return err
}
func (s *mockSyslogWriter) Info(m string) error {
	_, err := fmt.Fprintf((*io.PipeWriter)(s), "INFO %s", m)
	return err
}
func (s *mockSyslogWriter) Warning(m string) error {
	_, err := fmt.Fprintf((*io.PipeWriter)(s), "WARNING %s", m)
	return err
}
func (s *mockSyslogWriter) Err(m string) error {
	_, err := fmt.Fprintf((*io.PipeWriter)(s), "ERROR %s", m)
	return err
}
func (s *mockSyslogWriter) Crit(m string) error {
	_, err := fmt.Fprintf((*io.PipeWriter)(s), "CRITICAL %s", m)
	return err
}

// ----- Benchmarks & Fuzz -----

// Benchmark "result" variables — reading/writing a global prevents the
// loop from being optimised away.
var BenchOut bool
var BenchIn bool

func BenchmarkRegexpEmpty(b *testing.B) {
	re := regexp.MustCompile("")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BenchOut = BenchOut != re.MatchString("endpoint_mgr.go")
	}
}

func BenchmarkRegexpNilcheck(b *testing.B) {
	re := regexp.MustCompile("")
	if b.N > 0 || BenchIn {
		re = nil
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if re != nil {
			BenchOut = BenchOut != re.MatchString("endpoint_mgr.go")
		}
	}
}

func BenchmarkRegexpStar(b *testing.B) {
	re := regexp.MustCompile(".*")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BenchOut = BenchOut != re.MatchString("endpoint_mgr.go")
	}
}

// FuzzAppendTime fuzzes AppendTime against the stdlib time.Time.AppendFormat
// to make sure they agree.
func FuzzAppendTime(f *testing.F) {
	pool := sync.Pool{
		New: func() any {
			return &bytes.Buffer{}
		},
	}

	tFormat := "2006-01-02 15:04:05.000"
	var zeroTime time.Time
	f.Add(int(zeroTime.Unix()), int(zeroTime.Nanosecond()))
	f.Add(0, 0)
	// time.Now() at time of writing with various nanos.
	f.Add(1257894000, 0)
	f.Add(1257894000, 1)
	f.Add(1257894000, 100)
	f.Add(1257894000, 1000)
	f.Add(1257894000, 10000)
	f.Add(1257894000, 100000)
	f.Add(1257894000, 112345)
	f.Fuzz(func(t *testing.T, secs, nanos int) {
		timeVal := time.Unix(int64(secs), int64(nanos))
		buf1 := pool.Get().(*bytes.Buffer)
		buf2 := pool.Get().(*bytes.Buffer)
		{
			buf1.Write(timeVal.AppendFormat(buf1.AvailableBuffer(), tFormat))
			AppendTime(buf2, timeVal)
			if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
				t.Fatalf("Expected %s, got %s", buf1.String(), buf2.String())
			}
			buf1.Reset()
			buf2.Reset()
		}
		{
			utc := timeVal.UTC()
			buf1.Write(utc.AppendFormat(buf1.AvailableBuffer(), tFormat))
			AppendTime(buf2, utc)
			if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
				t.Fatalf("UTC: Expected %s, got %s", buf1.String(), buf2.String())
			}
			buf1.Reset()
			buf2.Reset()
		}
		pool.Put(buf1)
		pool.Put(buf2)
	})
}
