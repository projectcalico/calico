// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package log_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/lib/std/log"
	"github.com/projectcalico/calico/lib/std/testutils/assert"
)

func init() {
	log.MarkForTesting()
}

func TestFileLocationWithDifferentInvocations(t *testing.T) {
	tt := []struct {
		description string
		logFunc     func(logger log.Logger)
	}{
		{
			description: "logger.Info",
			logFunc:     func(logger log.Logger) { logger.Info("Test log") },
		},
		{
			description: "logger.WithField(...).Info",
			logFunc:     func(logger log.Logger) { logger.Info("Test log") },
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := log.New(
				log.WithLevel(log.DebugLevel),
				log.WithOutput(buf))
			tc.logFunc(logger)
			assert.ContainsSubstring(t, "logrus_test.go", buf.String())
		})
	}
}

func TestFormatter(t *testing.T) {
	tt := []struct {
		description string
		fields      log.Fields
		expectedLog string
	}{
		{
			description: "Basic",
			fields: log.Fields{
				"__flush__": true, // Internal value that should be ignored.
			},
			expectedLog: "<TIME> [INFO][<PID>] <FILE> <LINE>: The answer is 42.\n",
		},
		{
			description: "With fields",
			fields: log.Fields{
				"a":   10,
				"b":   "foobar",
				"c":   theTime(),
				"err": errors.New("an error"),
			},
			expectedLog: "<TIME> [INFO][<PID>] <FILE> <LINE>: The answer is 42. a=10 b=\"foobar\" c=2017-03-15 11:22:33.123 +0000 UTC err=an error\n",
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			buf := &bytes.Buffer{}
			var entryTime string
			logger := log.New(
				log.WithLevel(log.DebugLevel),
				log.WithOutput(buf),
				log.WithHooks(log.NewHook([]log.Level{log.InfoLevel}, func(entry log.Entry) error {
					timeBuff := bytes.NewBuffer(nil)
					log.AppendTime(timeBuff, entry.GetTime())
					entryTime = timeBuff.String()
					return nil
				})))

			file, line := getLine()
			logger.WithFields(tc.fields).Info("The answer is 42.")

			expectedLog := strings.Replace(tc.expectedLog, "<PID>", fmt.Sprintf("%v", os.Getpid()), 1)
			expectedLog = strings.Replace(expectedLog, "<TIME>", fmt.Sprintf("%v", entryTime), 1)
			expectedLog = strings.Replace(expectedLog, "<FILE>", fmt.Sprintf("%v", file), 1)
			expectedLog = strings.Replace(expectedLog, "<LINE>", fmt.Sprintf("%v", line+1), 1)
			assert.Equal(t, expectedLog, buf.String())
		})
	}
}

func getLine() (string, int) {
	_, file, line, _ := runtime.Caller(1)
	return path.Base(file), line
}

func theTime() time.Time {
	theTime, err := time.Parse("2006-01-02 15:04:05.000", "2017-03-15 11:22:33.123")
	if err != nil {
		panic(err)
	}
	return theTime
}

var (
	message1 = log.QueuedLog{
		Level:         log.InfoLevel,
		Message:       []byte("Message"),
		SyslogMessage: "syslog message",
	}
	message2 = log.QueuedLog{
		Level:         log.InfoLevel,
		Message:       []byte("Message2"),
		SyslogMessage: "syslog message2",
	}
)

func TestBackgroundHookFlushing(t *testing.T) {
	tt := []struct {
		description     string
		logFunc         func(logger log.Logger)
		expectedMessage string
		hookOpts        []log.BackgroundHookOpt
		shouldFlush     bool
	}{
		{
			description: "Let debug logs through by default",
			logFunc: func(logger log.Logger) {
				logger.Debug("Hello")
			},
			expectedMessage: "level=debug msg=Hello",
			shouldFlush:     true,
		},
		{
			description: "Should filter debug logs with regex option",
			logFunc: func(logger log.Logger) {
				logger.Debug("Hello")
			},
			hookOpts: []log.BackgroundHookOpt{
				log.WithDebugFileRegexp(regexp.MustCompile("another_file_for_test")),
			},
			shouldFlush: false,
		},
		{
			description: "Should debug logs when regex matches",
			logFunc: func(logger log.Logger) {
				debugFromAnotherFile(logger, "What?")
			},
			expectedMessage: "level=debug msg=\"What?\"",
			hookOpts: []log.BackgroundHookOpt{
				log.WithDebugFileRegexp(regexp.MustCompile("another_file_for_test")),
			},
			shouldFlush: true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			c := make(chan log.QueuedLog, 10)
			testDest := &log.Destination{
				Level:   log.DebugLevel,
				Channel: c,
			}

			logger := log.New(
				log.WithFormatter(log.NewTextFormatter(log.TextFormatterConfig{})),
				log.WithLevel(log.DebugLevel),
				log.WithOutput(&log.NullWriter{}),
				log.WithBackgroundHook(log.AllLevels, log.DebugLevel, []*log.Destination{testDest}, nil, tc.hookOpts...))

			ctx := context.Background()
			tc.logFunc(logger)
			ql, err := chanutil.ReadWithDeadline(ctx, c, 5*time.Second)
			if tc.shouldFlush {
				assert.NoError(t, err)
				assert.ContainsSubstring(t, tc.expectedMessage, string(ql.Message))
			} else {
				assert.ErrorIs(t, chanutil.ErrDeadlineExceeded, err)
			}
		})
	}
}

func TestBackgroundHookFlushing_BackgroundBlockingScenarios(t *testing.T) {
	tt := []struct {
		description     string
		logFunc         func(t *testing.T, logger log.Logger)
		expectedMessage string
		hookOpts        []log.BackgroundHookOpt
		shouldBlock     bool
	}{
		{
			description: "When calling Panic, should block waiting for the background thread",
			logFunc: func(t *testing.T, logger log.Logger) {
				assert.Panic(t, func() { logger.Panic("Should flush") })
			},
			shouldBlock: true,
		},
		{
			description: "When calling Panic, should block waiting for the background thread",
			logFunc: func(t *testing.T, logger log.Logger) {
				logger.WithField(log.FieldForceFlush, true).Info("Should flush")
			},
			shouldBlock: true,
		},
		{
			description: "When calling Panic, should block waiting for the background thread",
			logFunc: func(t *testing.T, logger log.Logger) {
				logger.Info("Should not flush")
			},
			shouldBlock: false,
		},
	}
	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			ctx := context.Background()
			c := make(chan log.QueuedLog, 10)
			testDest := &log.Destination{
				Level:   log.DebugLevel,
				Channel: c,
			}

			logger := log.New(
				log.WithFormatter(log.NewTextFormatter(log.TextFormatterConfig{})),
				log.WithLevel(log.DebugLevel),
				log.WithOutput(&log.NullWriter{}),
				log.WithBackgroundHook(log.AllLevels, log.DebugLevel, []*log.Destination{testDest}, nil))

			done := make(chan struct{})
			go func() {
				defer close(done)
				tc.logFunc(t, logger)
			}()

			ql, err := chanutil.ReadWithDeadline(ctx, c, 1*time.Second)
			assert.NoError(t, err)
			if tc.shouldBlock {
				assert.NotNil(t, ql.WaitGroup)
				_, err = chanutil.ReadWithDeadline(ctx, done, 5*time.Second)
				assert.ErrorIs(t, chanutil.ErrDeadlineExceeded, err)
				ql.WaitGroup.Done()
				_, err = chanutil.ReadWithDeadline(ctx, done, 5*time.Second)
				assert.ErrorIs(t, chanutil.ErrChannelClosed, err)
			} else {
				assert.Nil(t, ql.WaitGroup)
				_, err = chanutil.ReadWithDeadline(ctx, done, 5*time.Second)
				assert.ErrorIs(t, chanutil.ErrChannelClosed, err)
			}
		})
	}
}

func readNextMsg(pr *io.PipeReader) (string, error) {
	b := make([]byte, 1024)
	n, err := pr.Read(b)
	if err != nil {
		return "", err
	}
	return string(b[:n]), nil
}

func TestStreamDestination_ReportsDroppedLogsToBackgroundThread(t *testing.T) {
	c := make(chan log.QueuedLog, 1)
	_, pw := io.Pipe()
	s := log.NewStreamDestination(
		log.InfoLevel, pw, c, false, nil,
	)

	// The first message should be queued on the channel.
	assert.Equal(t, true, s.Send(message1))
	// The second message should be dropped.  Drop counter should now be 1.
	assert.Equal(t, false, s.Send(message1))
	// Drain the queue.
	assert.ObjectsEqual(t, message1, <-c)
	// The third message should go through.
	assert.Equal(t, true, s.Send(message1))
	assert.ObjectsEqual(t, <-c, log.QueuedLog{
		Level:          log.InfoLevel,
		Message:        []byte("Message"),
		SyslogMessage:  "syslog message",
		NumSkippedLogs: 1,
	})
	// Subsequent messages should have the counter reset.
	assert.Equal(t, true, s.Send(message1))
	assert.ObjectsEqual(t, <-c, message1)
}

func TestDestination_DoesNotDropLogsWhenDropLogsDisabled(t *testing.T) {
	tt := []struct {
		description string
		destination func() (chan log.QueuedLog, *log.Destination)
	}{
		{
			description: "StreamDestination",
			destination: func() (chan log.QueuedLog, *log.Destination) {
				c := make(chan log.QueuedLog, 1)
				_, pw := io.Pipe()
				return c, log.NewStreamDestination(
					log.InfoLevel, pw, c, true, nil,
				)
			},
		},
		{
			description: "SyslogDestination",
			destination: func() (chan log.QueuedLog, *log.Destination) {
				c := make(chan log.QueuedLog, 1)
				_, pw := io.Pipe()
				return c, log.NewSyslogDestination(
					log.InfoLevel, (*mockSyslogWriter)(pw), c, true, nil,
				)
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			c, dest := tc.destination()
			// The first message should be queued on the channel.
			assert.Equal(t, true, dest.Send(message1))
			done := make(chan bool)
			go func() {
				defer close(done)
				// Second message should block so we do it in a goroutine.
				assert.Equal(t, true, dest.Send(message2))
			}()

			// Drain the queue.
			assert.ObjectsEqual(t, <-c, message1)
			assert.ObjectsEqual(t, <-c, message2)

			_, err := chanutil.ReadWithDeadline(context.Background(), done, 1*time.Second)
			assert.ErrorIs(t, chanutil.ErrDeadlineExceeded, err)
		})
	}
}

func newQueuedLog(l log.Level, msg, sysMsg string, skipped uint, wg *sync.WaitGroup) log.QueuedLog {
	return log.QueuedLog{
		Level:          l,
		Message:        []byte(msg),
		SyslogMessage:  sysMsg,
		NumSkippedLogs: skipped,
		WaitGroup:      wg,
	}
}

func TestStreamDestination_WithRealBackgroundThread(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	createStreamDest := func() (chan log.QueuedLog, *io.PipeReader, *log.Destination) {
		c := make(chan log.QueuedLog, 1)
		pr, pw := io.Pipe()
		return c, pr, log.NewStreamDestination(log.InfoLevel, pw, c, false, nil)
	}

	createSyslogDest := func(l log.Level) func() (chan log.QueuedLog, *io.PipeReader, *log.Destination) {
		return func() (chan log.QueuedLog, *io.PipeReader, *log.Destination) {
			c := make(chan log.QueuedLog, 1)
			pr, pw := io.Pipe()
			return c, pr, log.NewSyslogDestination(l, (*mockSyslogWriter)(pw), c, false, nil)
		}
	}

	type test struct {
		description      string
		queuedLog        log.QueuedLog
		expectedMessages []string
		bypassSend       bool
		destination      func() (chan log.QueuedLog, *io.PipeReader, *log.Destination)
	}

	tt := []test{
		{
			description:      "[StreamDestination] should write a log (no WaitGroup)",
			destination:      createStreamDest,
			queuedLog:        message1,
			expectedMessages: []string{"Message"},
		},
		{
			description:      "[StreamDestination] should log number of dropped logs",
			destination:      createStreamDest,
			queuedLog:        newQueuedLog(log.InfoLevel, "Message", "syslog message", 1, nil),
			expectedMessages: []string{"... dropped 1 logs ...\n", "Message"},
			bypassSend:       true,
		},
		{
			description:      "[StreamDestination] should trigger WaitGroup",
			destination:      createStreamDest,
			queuedLog:        newQueuedLog(log.InfoLevel, "Message", "syslog message", 0, nil),
			expectedMessages: []string{"Message"},
			bypassSend:       true,
		},
		{
			description:      "[SyslogDestination] should log number of dropped logs",
			destination:      createSyslogDest(log.InfoLevel),
			queuedLog:        newQueuedLog(log.InfoLevel, "Message", "syslog message", 1, nil),
			expectedMessages: []string{"WARNING ... dropped 1 logs ...\n", "INFO syslog message"},
			bypassSend:       true,
		},
		{
			description:      "[SyslogDestination] should trigger WaitGroup",
			destination:      createSyslogDest(log.InfoLevel),
			queuedLog:        newQueuedLog(log.InfoLevel, "Message", "syslog message", 0, nil),
			expectedMessages: []string{"INFO syslog message"},
			bypassSend:       true,
		},
	}

	levelTests := []struct {
		level log.Level
		text  string
	}{
		{log.InfoLevel, "INFO"},
		{log.WarnLevel, "WARNING"},
		{log.DebugLevel, "DEBUG"},
		{log.ErrorLevel, "ERROR"},
		{log.FatalLevel, "CRITICAL"},
		{log.PanicLevel, "CRITICAL"},
	}

	for _, lt := range levelTests {
		tt = append(tt, test{
			description:      "[SyslogDestination] should write a log (no WaitGroup) level " + lt.level.String(),
			destination:      createSyslogDest(lt.level),
			queuedLog:        newQueuedLog(lt.level, "Message", "syslog message", 1, nil),
			expectedMessages: []string{lt.text + " syslog message"},
		})
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			c, pr, s := tc.destination()
			defer s.Close()
			go s.LoopWritingLogs()

			if tc.bypassSend {
				c <- tc.queuedLog
			} else {
				assert.Equal(t, true, s.Send(tc.queuedLog))
			}

			for _, expectedMessage := range tc.expectedMessages {
				msg, err := readNextMsg(pr)
				assert.NoError(t, err)
				assert.Equal(t, expectedMessage, msg)
			}

			if tc.queuedLog.WaitGroup != nil {
				done := make(chan struct{})
				go func() {
					defer close(done)
					tc.queuedLog.WaitGroup.Wait()
				}()
				_, err := chanutil.ReadWithDeadline(context.Background(), done, 5*time.Second)
				assert.ErrorIs(t, chanutil.ErrChannelClosed, err)
			}
		})
	}
}

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

// Benchmark "result" variables, reading/writing global variable prevents the loop from being optimised away.
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
			log.AppendTime(buf2, timeVal)
			if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
				t.Fatalf("Expected %s, got %s", buf1.String(), buf2.String())
			}
			buf1.Reset()
			buf2.Reset()
		}
		{
			utc := timeVal.UTC()
			buf1.Write(utc.AppendFormat(buf1.AvailableBuffer(), tFormat))
			log.AppendTime(buf2, utc)
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
