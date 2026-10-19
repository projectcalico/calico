// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.
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
	"errors"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	. "github.com/projectcalico/calico/lib/logrusr"
)

// mockLogFormatter counts formatter invocations and captures the last
// entry it saw, so tests can inspect what got emitted.
type mockLogFormatter struct {
	count int
	entry *log.Entry
}

func (s *mockLogFormatter) Format(e *log.Entry) ([]byte, error) {
	s.count++
	s.entry = e
	return nil, nil
}

func TestRateLimitedLogger_FirstAndIntervalLogging(t *testing.T) {
	cases := []struct {
		name         string
		expectedLvl  log.Level
		testLogLevel bool
		logfn        func(l *RateLimitedLogger)
	}{
		{"Debug", log.DebugLevel, true, func(l *RateLimitedLogger) { l.Debug("log", "now") }},
		{"Print", log.InfoLevel, false, func(l *RateLimitedLogger) { l.Print("log", "now") }},
		{"Info", log.InfoLevel, true, func(l *RateLimitedLogger) { l.Info("log", "now") }},
		{"Warn", log.WarnLevel, true, func(l *RateLimitedLogger) { l.Warn("log", "now") }},
		{"Warning", log.WarnLevel, true, func(l *RateLimitedLogger) { l.Warning("log", "now") }},
		{"Error", log.ErrorLevel, true, func(l *RateLimitedLogger) { l.Error("log", "now") }},
		{"Debugf", log.DebugLevel, true, func(l *RateLimitedLogger) { l.Debugf("log %s", "hello") }},
		{"Printf", log.InfoLevel, false, func(l *RateLimitedLogger) { l.Printf("log %s", "hello") }},
		{"Infof", log.InfoLevel, true, func(l *RateLimitedLogger) { l.Infof("log %s", "hello") }},
		{"Warnf", log.WarnLevel, true, func(l *RateLimitedLogger) { l.Warnf("log %s", "hello") }},
		{"Warningf", log.WarnLevel, true, func(l *RateLimitedLogger) { l.Warningf("log %s", "hello") }},
		{"Errorf", log.ErrorLevel, true, func(l *RateLimitedLogger) { l.Errorf("log %s", "hello") }},
		{"Debugln", log.DebugLevel, true, func(l *RateLimitedLogger) { l.Debugln("log", "now") }},
		{"Println", log.InfoLevel, false, func(l *RateLimitedLogger) { l.Println("log", "now") }},
		{"Infoln", log.InfoLevel, true, func(l *RateLimitedLogger) { l.Infoln("log", "now") }},
		{"Warnln", log.WarnLevel, true, func(l *RateLimitedLogger) { l.Warnln("log", "now") }},
		{"Warningln", log.WarnLevel, true, func(l *RateLimitedLogger) { l.Warningln("log", "now") }},
		{"Errorln", log.ErrorLevel, true, func(l *RateLimitedLogger) { l.Errorln("log", "now") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			counter := &mockLogFormatter{}
			logrusLogger := &log.Logger{
				Out:       os.Stderr,
				Formatter: counter,
				Hooks:     make(log.LevelHooks),
				Level:     log.DebugLevel,
			}
			logger := NewRateLimitedLogger(OptInterval(200*time.Millisecond), OptLogger(logrusLogger))
			logger = logger.WithError(errors.New("error"))
			logger = logger.WithField("a", 1)
			logger = logger.WithFields(log.Fields{"b": 2, "c": "3"})

			// When testing log levels, prove that a level below the
			// expected level does NOT start rate-limited logging (the
			// entry.count doesn't advance).
			if tc.testLogLevel {
				for i := tc.expectedLvl - 1; i > log.PanicLevel; i-- {
					logrusLogger.SetLevel(i)
					tc.logfn(logger)
				}
				logrusLogger.SetLevel(log.DebugLevel)
			}

			// First log is emitted.
			tc.logfn(logger.WithError(errors.New("error")))
			mustCount(t, counter, 1)
			mustHaveField(t, counter.entry, "a", 1)
			mustHaveField(t, counter.entry, "b", 2)
			mustHaveField(t, counter.entry, "c", "3")
			mustNotHaveField(t, counter.entry, "logsSkipped")
			mustHaveKey(t, counter.entry, "nextLog")
			mustHaveKey(t, counter.entry, "error")

			// Next two are skipped.
			tc.logfn(logger.WithField("a", 1))
			tc.logfn(logger.WithField("a", 1))
			mustCount(t, counter, 1)

			// After the interval, the next log emits with logsSkipped=2.
			time.Sleep(200 * time.Millisecond)
			tc.logfn(logger.WithFields(log.Fields{"b": 2, "c": "3"}))
			mustCount(t, counter, 2)
			mustHaveField(t, counter.entry, "a", 1)
			mustHaveField(t, counter.entry, "b", 2)
			mustHaveField(t, counter.entry, "c", "3")
			mustHaveField(t, counter.entry, "logsSkipped", 2)
			mustHaveKey(t, counter.entry, "nextLog")
			mustHaveKey(t, counter.entry, "error")

			// Force bypasses the interval.
			tc.logfn(logger.Force())
			mustCount(t, counter, 3)
			if counter.entry.Level != tc.expectedLvl {
				t.Errorf("entry level = %v, want %v", counter.entry.Level, tc.expectedLvl)
			}
			mustHaveField(t, counter.entry, "a", 1)
			mustHaveField(t, counter.entry, "b", 2)
			mustHaveField(t, counter.entry, "c", "3")
			mustNotHaveField(t, counter.entry, "logsSkipped")
			mustHaveKey(t, counter.entry, "nextLog")
			mustHaveKey(t, counter.entry, "error")

			// Burst behaviour: a fresh logger with burst=2 allows the
			// first two calls through without rate limiting.
			logger = NewRateLimitedLogger(
				OptInterval(200*time.Millisecond),
				OptLogger(logrusLogger),
				OptBurst(2),
			)
			tc.logfn(logger) // First log resets interval and burst.
			mustNotHaveKey(t, counter.entry, "nextLog")
			mustNotHaveKey(t, counter.entry, "logsSkipped")
			tc.logfn(logger) // First burst.
			mustNotHaveKey(t, counter.entry, "nextLog")
			mustNotHaveKey(t, counter.entry, "logsSkipped")
			tc.logfn(logger) // Second burst — starts the interval.
			mustHaveKey(t, counter.entry, "nextLog")
			mustNotHaveKey(t, counter.entry, "logsSkipped")
			tc.logfn(logger) // Skipped.
			tc.logfn(logger) // Skipped.
			mustCount(t, counter, 6)

			// After the interval, burst resets.
			time.Sleep(200 * time.Millisecond)
			tc.logfn(logger) // First log after interval — logsSkipped=2.
			mustNotHaveKey(t, counter.entry, "nextLog")
			mustHaveField(t, counter.entry, "logsSkipped", 2)
			tc.logfn(logger) // First burst.
			mustNotHaveKey(t, counter.entry, "nextLog")
			mustNotHaveKey(t, counter.entry, "logsSkipped")
			tc.logfn(logger) // Second burst.
			mustHaveKey(t, counter.entry, "nextLog")
			mustNotHaveKey(t, counter.entry, "logsSkipped")
			tc.logfn(logger) // Skipped.
			tc.logfn(logger) // Skipped.
			mustCount(t, counter, 9)
		})
	}
}

// ----- helpers -----

func mustCount(t *testing.T, m *mockLogFormatter, want int) {
	t.Helper()
	if m.count != want {
		t.Fatalf("formatter count = %d, want %d", m.count, want)
	}
}

func mustHaveField(t *testing.T, e *log.Entry, key string, want any) {
	t.Helper()
	got, ok := e.Data[key]
	if !ok {
		t.Fatalf("entry missing field %q; have %v", key, e.Data)
	}
	if got != want {
		t.Fatalf("entry[%q] = %v, want %v", key, got, want)
	}
}

func mustNotHaveField(t *testing.T, e *log.Entry, key string) {
	t.Helper()
	if _, ok := e.Data[key]; ok {
		t.Fatalf("entry should not have field %q; have %v", key, e.Data)
	}
}

func mustHaveKey(t *testing.T, e *log.Entry, key string) {
	t.Helper()
	if _, ok := e.Data[key]; !ok {
		t.Fatalf("entry missing key %q; have %v", key, e.Data)
	}
}

func mustNotHaveKey(t *testing.T, e *log.Entry, key string) {
	t.Helper()
	if _, ok := e.Data[key]; ok {
		t.Fatalf("entry should not have key %q; have %v", key, e.Data)
	}
}
