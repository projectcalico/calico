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

// Internal tests covering the unexported destination/hook/formatter machinery.
// These are the lib/std/log equivalents of the libcalico-go/lib/logutils test
// suite, rewritten as standard testing.T tests so lib/std/go.mod doesn't need
// Ginkgo/Gomega.

package log

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// fixedTime is the synthetic timestamp used by the Formatter table tests.
func fixedTime() time.Time {
	t, err := time.Parse("2006-01-02 15:04:05.000", "2017-03-15 11:22:33.123")
	if err != nil {
		panic(err)
	}
	return t
}

// TestFormatterTable exercises the formatter against fully-specified logrus
// entries and asserts byte-exact output for both the main and syslog formats.
// This locks in the format that operator dashboards and grep patterns expect.
func TestFormatterTable(t *testing.T) {
	cases := []struct {
		name     string
		entry    logrus.Entry
		wantLog  string
		wantSlog string
	}{
		// Note: the libcalico-go "empty" subtest expected `<nil> <nil>` for the
		// file/line when entry.Caller was nil. In lib/std/log we always have
		// fallback stack-walking, so an empty entry never produces `<nil>` —
		// the formatter finds *something*. That subtest is omitted.
		{
			name: "basic",
			entry: logrus.Entry{
				Level: logrus.InfoLevel,
				Time:  fixedTime(),
				Caller: &runtime.Frame{
					File: "biff.com/bar/foo.go",
					Line: 123,
				},
				Data: logrus.Fields{
					// Internal field; must be stripped from output.
					fieldForceFlush: true,
				},
				Message: "The answer is 42.",
			},
			wantLog:  "2017-03-15 11:22:33.123 [INFO][<PID>] foo.go 123: The answer is 42.\n",
			wantSlog: "INFO foo.go 123: The answer is 42.\n",
		},
		{
			name: "with fields",
			entry: logrus.Entry{
				Level: logrus.WarnLevel,
				Time:  fixedTime(),
				Caller: &runtime.Frame{
					File: "biff.com/bar/foo.go",
					Line: 123,
				},
				Data: logrus.Fields{
					"a":   10,
					"b":   "foobar",
					"c":   fixedTime(),
					"err": errors.New("an error"),
				},
				Message: "The answer is 42.",
			},
			wantLog:  `2017-03-15 11:22:33.123 [WARNING][<PID>] foo.go 123: The answer is 42. a=10 b="foobar" c=2017-03-15 11:22:33.123 +0000 UTC err=an error` + "\n",
			wantSlog: `WARNING foo.go 123: The answer is 42. a=10 b="foobar" c=2017-03-15 11:22:33.123 +0000 UTC err=an error` + "\n",
		},
	}

	f := newFormatter("")
	pid := fmt.Sprintf("%d", os.Getpid())
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entry := c.entry
			out, err := f.Format(&entry)
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			wantLog := strings.ReplaceAll(c.wantLog, "<PID>", pid)
			if string(out) != wantLog {
				t.Errorf("Format mismatch:\n  got:  %q\n  want: %q", string(out), wantLog)
			}
			gotSlog := formatForSyslog(&entry, "")
			if gotSlog != c.wantSlog {
				t.Errorf("Syslog mismatch:\n  got:  %q\n  want: %q", gotSlog, c.wantSlog)
			}
		})
	}
}

// TestLogrusLevelsConsistent locks in the assumption that the indexes in
// logrus.AllLevels match the numeric values of the level constants. The
// formatter's pre-computed infix table relies on this.
func TestLogrusLevelsConsistent(t *testing.T) {
	for idx, level := range logrus.AllLevels {
		if int(level) != idx {
			t.Errorf("logrus.AllLevels[%d] = %v (int %d); want %d", idx, level, int(level), idx)
		}
	}
}

var (
	testMsg1 = queuedLog{
		Level:         logrus.InfoLevel,
		Message:       []byte("Message"),
		SyslogMessage: "syslog message",
	}
	testMsg2 = queuedLog{
		Level:         logrus.InfoLevel,
		Message:       []byte("Message2"),
		SyslogMessage: "syslog message2",
	}
)

// TestStreamDestinationDropCounter verifies that the destination tracks
// dropped logs when the channel fills, then reports the drop count on the
// next successfully-queued log.
func TestStreamDestinationDropCounter(t *testing.T) {
	c := make(chan queuedLog, 1)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	t.Cleanup(func() { _ = pw.Close() })
	d := newStreamDestination(logrus.InfoLevel, pw, c, false, nil)

	if ok := d.send(testMsg1); !ok {
		t.Fatalf("first send should succeed")
	}
	// Channel is full; second send drops and increments the counter.
	if ok := d.send(testMsg1); ok {
		t.Fatalf("second send should have been dropped")
	}
	// Drain.
	<-c
	// Third send succeeds and carries NumSkippedLogs=1.
	if ok := d.send(testMsg1); !ok {
		t.Fatalf("third send should succeed")
	}
	got := <-c
	if got.NumSkippedLogs != 1 {
		t.Errorf("NumSkippedLogs = %d, want 1", got.NumSkippedLogs)
	}
	// Counter resets after being reported.
	if ok := d.send(testMsg1); !ok {
		t.Fatalf("fourth send should succeed")
	}
	got = <-c
	if got.NumSkippedLogs != 0 {
		t.Errorf("NumSkippedLogs not reset after reporting; got %d", got.NumSkippedLogs)
	}
}

// TestStreamDestinationNoDropBlocks verifies that disableLogDropping makes
// the destination block instead of dropping when the channel is full.
func TestStreamDestinationNoDropBlocks(t *testing.T) {
	c := make(chan queuedLog, 1)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	t.Cleanup(func() { _ = pw.Close() })
	d := newStreamDestination(logrus.InfoLevel, pw, c, true, nil)

	if ok := d.send(testMsg1); !ok {
		t.Fatalf("first send should succeed")
	}
	done := make(chan bool, 1)
	go func() {
		done <- d.send(testMsg2)
	}()
	// Give the goroutine a chance to block.
	time.Sleep(20 * time.Millisecond)
	select {
	case <-done:
		t.Fatalf("second send should have blocked")
	default:
	}
	// Drain to unblock.
	if got := <-c; !bytes.Equal(got.Message, testMsg1.Message) {
		t.Fatalf("got msg1=%q, want %q", got.Message, testMsg1.Message)
	}
	if got := <-c; !bytes.Equal(got.Message, testMsg2.Message) {
		t.Fatalf("got msg2=%q, want %q", got.Message, testMsg2.Message)
	}
	if !<-done {
		t.Fatalf("blocked send should ultimately succeed")
	}
}

// TestStreamDestinationLoopWritesAndFlushes verifies that the background
// writer drains the channel, propagates dropped-log markers, and signals
// WaitGroups for flush-on-fatal flows.
func TestStreamDestinationLoopWritesAndFlushes(t *testing.T) {
	c := make(chan queuedLog, 4)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	d := newStreamDestination(logrus.InfoLevel, pw, c, false, nil)

	go d.loopWritingLogs()
	t.Cleanup(func() { close(c) })

	readMsg := func() string {
		b := make([]byte, 1024)
		n, err := pr.Read(b)
		if err != nil {
			t.Fatalf("pipe read: %v", err)
		}
		return string(b[:n])
	}

	// Normal message.
	c <- testMsg1
	if got := readMsg(); got != "Message" {
		t.Errorf("got %q, want %q", got, "Message")
	}

	// Skipped-logs marker emitted ahead of the message.
	c <- queuedLog{
		Level:          logrus.InfoLevel,
		Message:        []byte("Message"),
		NumSkippedLogs: 1,
	}
	if got := readMsg(); got != "... dropped 1 logs ...\n" {
		t.Errorf("drop marker: got %q", got)
	}
	if got := readMsg(); got != "Message" {
		t.Errorf("after-drop message: got %q", got)
	}

	// WaitGroup is signalled when the message is written.
	wg := &sync.WaitGroup{}
	wg.Add(1)
	c <- queuedLog{
		Level:     logrus.InfoLevel,
		Message:   []byte("Message"),
		WaitGroup: wg,
	}
	_ = readMsg()
	wg.Wait() // would block forever if not signalled
}

// mockSyslogWriter implements syslogWriter on top of an io.PipeWriter, with
// a prefix per level so tests can verify level mapping.
type mockSyslogWriter struct{ w *io.PipeWriter }

func (s mockSyslogWriter) Debug(m string) error {
	_, err := fmt.Fprintf(s.w, "DEBUG %s", m)
	return err
}
func (s mockSyslogWriter) Info(m string) error { _, err := fmt.Fprintf(s.w, "INFO %s", m); return err }
func (s mockSyslogWriter) Warning(m string) error {
	_, err := fmt.Fprintf(s.w, "WARNING %s", m)
	return err
}
func (s mockSyslogWriter) Err(m string) error { _, err := fmt.Fprintf(s.w, "ERROR %s", m); return err }
func (s mockSyslogWriter) Crit(m string) error {
	_, err := fmt.Fprintf(s.w, "CRITICAL %s", m)
	return err
}

// TestSyslogDestinationLevelMapping verifies that each logrus level is
// translated to the right syslog severity prefix.
func TestSyslogDestinationLevelMapping(t *testing.T) {
	cases := []struct {
		level logrus.Level
		want  string
	}{
		{logrus.DebugLevel, "DEBUG"},
		{logrus.InfoLevel, "INFO"},
		{logrus.WarnLevel, "WARNING"},
		{logrus.ErrorLevel, "ERROR"},
		{logrus.FatalLevel, "CRITICAL"},
		{logrus.PanicLevel, "CRITICAL"},
	}

	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			ch := make(chan queuedLog, 1)
			pr, pw := io.Pipe()
			t.Cleanup(func() { _ = pr.Close() })
			d := newSyslogDestination(c.level, mockSyslogWriter{w: pw}, ch, false, nil)
			go d.loopWritingLogs()
			t.Cleanup(func() { close(ch) })

			ql := testMsg1
			ql.Level = c.level
			if ok := d.send(ql); !ok {
				t.Fatalf("send should succeed")
			}

			b := make([]byte, 1024)
			n, err := pr.Read(b)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			got := string(b[:n])
			want := c.want + " syslog message"
			if got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

// TestBackgroundHookDebugRegexpFilter verifies that the debug-filename regex
// filters debug logs based on the caller's source file.
func TestBackgroundHookDebugRegexpFilter(t *testing.T) {
	ch := make(chan queuedLog, 10)
	d := &destination{level: logrus.DebugLevel, channel: ch}

	re := regexp.MustCompile("another_caller_for_test")
	bh := newBackgroundHook(logrus.AllLevels, logrus.DebugLevel, "", []*destination{d}, re, nil)

	// Build a logger that runs through our hook with our formatter.
	lg := logrus.New()
	lg.SetFormatter(newFormatter(""))
	lg.SetOutput(&nullWriter{})
	lg.AddHook(bh)
	lg.SetLevel(logrus.DebugLevel)

	// Debug from THIS file (internal_test.go) should NOT match the regex.
	lg.Debug("from this file")
	select {
	case ql := <-ch:
		t.Errorf("debug from this file unexpectedly emitted: %s", string(ql.Message))
	case <-time.After(20 * time.Millisecond):
		// good
	}

	// Debug from the other test-helper file should match and pass through.
	// We populate entry.Caller explicitly so the regex sees the test helper's
	// file (the BackgroundHook's stack walk would otherwise skip past
	// helpers that live inside the log package itself).
	lg.SetReportCaller(true)
	t.Cleanup(func() { lg.SetReportCaller(false) })
	debugFromAnotherCaller(lg, "from other file")
	lg.SetReportCaller(false)
	select {
	case ql := <-ch:
		if !bytes.Contains(ql.Message, []byte("from other file")) {
			t.Errorf("unexpected message: %s", string(ql.Message))
		}
	case <-time.After(200 * time.Millisecond):
		t.Errorf("debug from matching file did not emit")
	}

	// Info should pass regardless of the debug regex.
	lg.Info("info from this file")
	select {
	case ql := <-ch:
		if !bytes.Contains(ql.Message, []byte("info from this file")) {
			t.Errorf("info had wrong message: %s", string(ql.Message))
		}
	case <-time.After(200 * time.Millisecond):
		t.Errorf("info was unexpectedly filtered")
	}
}

// TestBackgroundHookFatalBlocksForFlush verifies that Panic/Fatal logs carry
// a WaitGroup that callers can use to block until the log is written.
func TestBackgroundHookFatalBlocksForFlush(t *testing.T) {
	ch := make(chan queuedLog, 1)
	d := &destination{level: logrus.DebugLevel, channel: ch}
	bh := newBackgroundHook(logrus.AllLevels, logrus.DebugLevel, "", []*destination{d}, nil, nil)

	lg := logrus.New()
	lg.SetFormatter(newFormatter(""))
	lg.SetOutput(&nullWriter{})
	lg.AddHook(bh)
	lg.ExitFunc = func(code int) {} // disable os.Exit on Fatal

	emitted := make(chan struct{})
	go func() {
		defer close(emitted)
		// Panic logs trigger the wait-group path; recover so the test stays alive.
		defer func() { _ = recover() }()
		lg.Panic("flush me")
	}()

	var ql queuedLog
	select {
	case ql = <-ch:
	case <-time.After(time.Second):
		t.Fatalf("hook did not deliver Panic log")
	}
	if ql.WaitGroup == nil {
		t.Fatalf("Panic log should carry a WaitGroup for flush coordination")
	}
	// emitted goroutine should still be blocked waiting on WaitGroup.
	select {
	case <-emitted:
		t.Fatalf("emitter unblocked before WaitGroup.Done")
	case <-time.After(20 * time.Millisecond):
		// good
	}
	ql.WaitGroup.Done()
	select {
	case <-emitted:
	case <-time.After(time.Second):
		t.Fatalf("emitter did not unblock after WaitGroup.Done")
	}
}

// TestBackgroundHookForceFlushField verifies that the FieldForceFlush field
// triggers the same flush-blocking behavior as Fatal/Panic, without escalating
// the level.
func TestBackgroundHookForceFlushField(t *testing.T) {
	ch := make(chan queuedLog, 1)
	d := &destination{level: logrus.DebugLevel, channel: ch}
	bh := newBackgroundHook(logrus.AllLevels, logrus.DebugLevel, "", []*destination{d}, nil, nil)

	lg := logrus.New()
	lg.SetFormatter(newFormatter(""))
	lg.SetOutput(&nullWriter{})
	lg.AddHook(bh)

	emitted := make(chan struct{})
	go func() {
		defer close(emitted)
		lg.WithField(FieldForceFlush, true).Info("flush me")
	}()

	var ql queuedLog
	select {
	case ql = <-ch:
	case <-time.After(time.Second):
		t.Fatalf("hook did not deliver flush log")
	}
	if ql.WaitGroup == nil {
		t.Fatalf("FieldForceFlush log should carry a WaitGroup")
	}
	select {
	case <-emitted:
		t.Fatalf("emitter unblocked before WaitGroup.Done")
	case <-time.After(20 * time.Millisecond):
	}
	ql.WaitGroup.Done()
	<-emitted
}

// TestBackgroundHookNoFlushByDefault verifies that ordinary Info logs do NOT
// carry a WaitGroup and emitters do not block waiting for the destination.
func TestBackgroundHookNoFlushByDefault(t *testing.T) {
	ch := make(chan queuedLog, 1)
	d := &destination{level: logrus.DebugLevel, channel: ch}
	bh := newBackgroundHook(logrus.AllLevels, logrus.DebugLevel, "", []*destination{d}, nil, nil)

	lg := logrus.New()
	lg.SetFormatter(newFormatter(""))
	lg.SetOutput(&nullWriter{})
	lg.AddHook(bh)

	emitted := make(chan struct{})
	go func() {
		defer close(emitted)
		lg.Info("no flush")
	}()
	select {
	case <-emitted:
	case <-time.After(time.Second):
		t.Fatalf("emitter blocked on Info log")
	}
	select {
	case ql := <-ch:
		if ql.WaitGroup != nil {
			t.Errorf("ordinary Info should not carry a WaitGroup")
		}
	default:
		t.Errorf("Info log was not delivered to destination")
	}
}

// mockFormatter is a logrus.Formatter that just counts invocations and
// captures the last entry; used by the rate-limited logger table tests.
type mockFormatter struct {
	count atomic.Int32
	entry *logrus.Entry
}

func (m *mockFormatter) Format(e *logrus.Entry) ([]byte, error) {
	m.count.Add(1)
	m.entry = e
	return nil, nil
}

// TestRateLimitedLoggerComprehensive covers the full matrix of emit methods
// against the throttling, burst, force, and field-propagation behavior of
// the rate-limited logger. Equivalent to the libcalico-go DescribeTable.
func TestRateLimitedLoggerComprehensive(t *testing.T) {
	type entry struct {
		name           string
		expectedLevel  logrus.Level
		testLevelGuard bool
		fn             func(l Logger)
	}
	entries := []entry{
		{"Debug", logrus.DebugLevel, true, func(l Logger) { l.Debug("log", "now") }},
		{"Print", logrus.InfoLevel, false, func(l Logger) { l.Print("log", "now") }},
		{"Info", logrus.InfoLevel, true, func(l Logger) { l.Info("log", "now") }},
		{"Warn", logrus.WarnLevel, true, func(l Logger) { l.Warn("log", "now") }},
		{"Warning", logrus.WarnLevel, true, func(l Logger) { l.Warning("log", "now") }},
		{"Error", logrus.ErrorLevel, true, func(l Logger) { l.Error("log", "now") }},
		{"Debugf", logrus.DebugLevel, true, func(l Logger) { l.Debugf("log %s", "hello") }},
		{"Printf", logrus.InfoLevel, false, func(l Logger) { l.Printf("log %s", "hello") }},
		{"Infof", logrus.InfoLevel, true, func(l Logger) { l.Infof("log %s", "hello") }},
		{"Warnf", logrus.WarnLevel, true, func(l Logger) { l.Warnf("log %s", "hello") }},
		{"Warningf", logrus.WarnLevel, true, func(l Logger) { l.Warningf("log %s", "hello") }},
		{"Errorf", logrus.ErrorLevel, true, func(l Logger) { l.Errorf("log %s", "hello") }},
		{"Debugln", logrus.DebugLevel, true, func(l Logger) { l.Debugln("log", "now") }},
		{"Println", logrus.InfoLevel, false, func(l Logger) { l.Println("log", "now") }},
		{"Infoln", logrus.InfoLevel, true, func(l Logger) { l.Infoln("log", "now") }},
		{"Warnln", logrus.WarnLevel, true, func(l Logger) { l.Warnln("log", "now") }},
		{"Warningln", logrus.WarnLevel, true, func(l Logger) { l.Warningln("log", "now") }},
		{"Errorln", logrus.ErrorLevel, true, func(l Logger) { l.Errorln("log", "now") }},
	}
	for _, c := range entries {
		t.Run(c.name, func(t *testing.T) {
			counter := &mockFormatter{}
			lr := &logrus.Logger{
				Out:       os.Stderr,
				Formatter: counter,
				Hooks:     make(logrus.LevelHooks),
				Level:     logrus.DebugLevel,
			}
			impl := &logrusLogger{entry: logrus.NewEntry(lr)}
			rl := NewRateLimitedLogger(WithInterval(200*time.Millisecond), WithBaseLogger(impl))
			rl = rl.WithError(errors.New("error"))
			rl = rl.WithField("a", 1)
			rl = rl.WithFields(Fields{"b": 2, "c": "3"})

			// Level filtering: lowering the level below the call's level should
			// suppress emission entirely.
			if c.testLevelGuard {
				for lvl := c.expectedLevel - 1; lvl > logrus.PanicLevel; lvl-- {
					lr.SetLevel(lvl)
					c.fn(rl)
				}
				lr.SetLevel(logrus.DebugLevel)
			}

			// First processed log emits.
			c.fn(rl.WithError(errors.New("error")))
			if got := counter.count.Load(); got != 1 {
				t.Fatalf("count after first log = %d, want 1", got)
			}
			data := counter.entry.Data
			for k, want := range map[string]any{"a": 1, "b": 2, "c": "3"} {
				if data[k] != want {
					t.Errorf("field %s = %v, want %v", k, data[k], want)
				}
			}
			if _, ok := data["error"]; !ok {
				t.Errorf("expected 'error' field on first emit")
			}
			if _, ok := data[fieldLogSkipped]; ok {
				t.Errorf("first emit should not have %q field", fieldLogSkipped)
			}
			if _, ok := data[fieldLogNextLog]; !ok {
				t.Errorf("first emit should have %q field", fieldLogNextLog)
			}

			// Next two within the interval are throttled.
			c.fn(rl.WithField("a", 1))
			c.fn(rl.WithField("a", 1))
			if got := counter.count.Load(); got != 1 {
				t.Fatalf("count after throttled = %d, want 1", got)
			}

			// After the interval, the next log emits and reports logsSkipped.
			time.Sleep(220 * time.Millisecond)
			c.fn(rl.WithFields(Fields{"b": 2, "c": "3"}))
			if got := counter.count.Load(); got != 2 {
				t.Fatalf("count after interval = %d, want 2", got)
			}
			if got, ok := counter.entry.Data[fieldLogSkipped]; !ok || got != 2 {
				t.Errorf("logsSkipped = %v (ok=%v), want 2", got, ok)
			}

			// Force bypasses throttling on the immediate next emit.
			c.fn(Force(rl))
			if got := counter.count.Load(); got != 3 {
				t.Fatalf("count after Force = %d, want 3", got)
			}
			if _, ok := counter.entry.Data[fieldLogSkipped]; ok {
				t.Errorf("Force emit should not carry %q field", fieldLogSkipped)
			}
			if counter.entry.Level != c.expectedLevel {
				t.Errorf("Force emit level = %v, want %v", counter.entry.Level, c.expectedLevel)
			}

			// Burst behavior.
			counter.count.Store(0)
			rl = NewRateLimitedLogger(
				WithInterval(200*time.Millisecond),
				WithBurst(2),
				WithBaseLogger(impl),
			)
			c.fn(rl) // first emit, resets
			c.fn(rl) // burst 1
			c.fn(rl) // burst 2 (carries nextLog because burst remainder is now 0)
			c.fn(rl) // throttled
			c.fn(rl) // throttled
			if got := counter.count.Load(); got != 3 {
				t.Fatalf("burst count = %d, want 3", got)
			}
			time.Sleep(220 * time.Millisecond)
			c.fn(rl) // resets again, reports logsSkipped=2
			if got, ok := counter.entry.Data[fieldLogSkipped]; !ok || got != 2 {
				t.Errorf("burst-reset logsSkipped = %v, want 2", got)
			}
		})
	}
}

// FuzzAppendTime fuzzes the appendTime helper against the stdlib's
// time.AppendFormat to ensure they agree byte-for-byte. This guards the
// optimized hot-path formatter against drifts in RFC3339Nano internals.
func FuzzAppendTime(f *testing.F) {
	pool := sync.Pool{New: func() any { return &bytes.Buffer{} }}
	const layout = "2006-01-02 15:04:05.000"

	f.Add(int(time.Time{}.Unix()), int(time.Time{}.Nanosecond()))
	f.Add(0, 0)
	f.Add(1257894000, 0)
	f.Add(1257894000, 1)
	f.Add(1257894000, 100)
	f.Add(1257894000, 1000)
	f.Add(1257894000, 10000)
	f.Add(1257894000, 100000)
	f.Add(1257894000, 112345)

	check := func(t *testing.T, tv time.Time) {
		b1 := pool.Get().(*bytes.Buffer)
		b2 := pool.Get().(*bytes.Buffer)
		defer pool.Put(b1)
		defer pool.Put(b2)
		b1.Write(tv.AppendFormat(b1.AvailableBuffer(), layout))
		appendTime(b2, tv)
		if !bytes.Equal(b1.Bytes(), b2.Bytes()) {
			t.Fatalf("mismatch at %v:\n  stdlib: %s\n  ours:   %s", tv, b1.String(), b2.String())
		}
		b1.Reset()
		b2.Reset()
	}

	f.Fuzz(func(t *testing.T, secs, nanos int) {
		tv := time.Unix(int64(secs), int64(nanos))
		check(t, tv)
		check(t, tv.UTC())
	})
}
