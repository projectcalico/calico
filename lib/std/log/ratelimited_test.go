// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
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
	"errors"
	"os"
	"testing"
	"time"

	"github.com/projectcalico/calico/lib/std/log"
	"github.com/projectcalico/calico/lib/std/testutils/assert"
)

func init() {
	assert.SetFailImmediately(true)
}

// A mock log formatter that simply serves to count log invocations.
type mockLogFormatter struct {
	count int
	entry log.Entry
}

func (s *mockLogFormatter) Format(e log.Entry) ([]byte, error) {
	s.count++
	s.entry = e
	return nil, nil
}

func TestFirstAndIntervalLogging(t *testing.T) {
	type entry struct {
		name         string
		level        log.Level
		testLogLevel bool
		logfn        func(logger *log.RateLimitedLogger)
	}
	newEntry := func(name string, level log.Level, testLogLevel bool, logfn func(logger *log.RateLimitedLogger)) entry {
		return entry{
			name:         name,
			level:        level,
			testLogLevel: testLogLevel,
			logfn:        logfn,
		}
	}
	entries := []entry{
		newEntry("Debug", log.DebugLevel, true, func(l *log.RateLimitedLogger) { l.Debug("log", "now") }),
		newEntry("Print", log.InfoLevel, false, func(l *log.RateLimitedLogger) { l.Print("log", "now") }),
		newEntry("Info", log.InfoLevel, true, func(l *log.RateLimitedLogger) { l.Info("log", "now") }),
		newEntry("Warn", log.WarnLevel, true, func(l *log.RateLimitedLogger) { l.Warn("log", "now") }),
		newEntry("Warning", log.WarnLevel, true, func(l *log.RateLimitedLogger) { l.Warning("log", "now") }),
		newEntry("Error", log.ErrorLevel, true, func(l *log.RateLimitedLogger) { l.Error("log", "now") }),
		newEntry("Debugf", log.DebugLevel, true, func(l *log.RateLimitedLogger) { l.Debugf("log %s", "hello") }),
		newEntry("Printf", log.InfoLevel, false, func(l *log.RateLimitedLogger) { l.Printf("log %s", "hello") }),
		newEntry("Infof", log.InfoLevel, true, func(l *log.RateLimitedLogger) { l.Infof("log %s", "hello") }),
		newEntry("Warnf", log.WarnLevel, true, func(l *log.RateLimitedLogger) { l.Warnf("log %s", "hello") }),
		newEntry("Warningf", log.WarnLevel, true, func(l *log.RateLimitedLogger) { l.Warningf("log %s", "hello") }),
		newEntry("Errorf", log.ErrorLevel, true, func(l *log.RateLimitedLogger) { l.Errorf("log %s", "hello") }),
		newEntry("Debugln", log.DebugLevel, true, func(l *log.RateLimitedLogger) { l.Debugln("log", "now") }),
		newEntry("Println", log.InfoLevel, false, func(l *log.RateLimitedLogger) { l.Println("log", "now") }),
		newEntry("Infoln", log.InfoLevel, true, func(l *log.RateLimitedLogger) { l.Infoln("log", "now") }),
		newEntry("Warnln", log.WarnLevel, true, func(l *log.RateLimitedLogger) { l.Warnln("log", "now") }),
		newEntry("Warningln", log.WarnLevel, true, func(l *log.RateLimitedLogger) { l.Warningln("log", "now") }),
		newEntry("Errorln", log.ErrorLevel, true, func(l *log.RateLimitedLogger) { l.Errorln("log", "now") }),
	}

	for _, entry := range entries {
		t.Run(entry.name, func(t *testing.T) {
			expectedLevel := entry.level
			testLogLevel := entry.testLogLevel
			logfn := entry.logfn

			counter := &mockLogFormatter{}

			logrusLogger := log.New(
				log.WithOutput(os.Stderr),
				log.WithFormatter(counter),
				log.WithLevel(log.DebugLevel),
			)

			logger := log.NewRateLimitedLogger(log.OptInterval(200*time.Millisecond), log.OptLogger(logrusLogger))
			logger = logger.WithError(errors.New("error"))
			logger = logger.WithField("a", 1)
			logger = logger.WithFields(log.Fields{"b": 2, "c": "3"})

			// If we are testing log levels then change the logging level to be lower than the expected level of the log and
			// check that we don't trigger the start of the rate limited logging (i.e. the log is not processed).
			if testLogLevel {
				for i := expectedLevel - 1; i > log.PanicLevel; i-- {
					logrusLogger.SetLevel(i)
					logfn(logger)
				}
				logrusLogger.SetLevel(log.DebugLevel)
			}

			// The first log will be written.
			logfn(logger.WithError(errors.New("error")))

			assert.Equal(t, counter.count, 1)
			assert.ContainsKeyWithComparable(t, counter.entry.Fields(), "a", 1)
			assert.ContainsKeyWithComparable(t, counter.entry.Fields(), "b", 2)
			assert.ContainsKeyWithComparable(t, counter.entry.Fields(), "c", "3")
			assert.NotContainKey(t, counter.entry.Fields(), "logsSkipped")
			assert.ContainsKey(t, counter.entry.Fields(), "nextLog")
			assert.ContainsKey(t, counter.entry.Fields(), "error")

			// The next two logs will be skipped.
			logfn(logger.WithField("a", 1))
			logfn(logger.WithField("a", 1))
			assert.Equal(t, counter.count, 1)

			// Wait for the logging interval.
			time.Sleep(200 * time.Millisecond)

			// The next log will be written.
			logfn(logger.WithFields(log.Fields{"b": 2, "c": "3"}))
			assert.Equal(t, counter.count, 2)
			assert.ContainsKeyWithComparable(t, counter.entry.Fields(), "a", 1)
			assert.ContainsKeyWithComparable(t, counter.entry.Fields(), "b", 2)
			assert.ContainsKeyWithComparable(t, counter.entry.Fields(), "c", "3")
			assert.ContainsKeyWithComparable(t, counter.entry.Fields(), "logsSkipped", 2)
			assert.ContainsKey(t, counter.entry.Fields(), "nextLog")
			assert.ContainsKey(t, counter.entry.Fields(), "error")

			// Force, so the next log will also be written.
			logfn(logger.Force())
			assert.Equal(t, counter.count, 3)
			assert.ContainsKeyWithComparable(t, counter.entry.Fields(), "a", 1)
			assert.ContainsKeyWithComparable(t, counter.entry.Fields(), "b", 2)
			assert.ContainsKeyWithComparable(t, counter.entry.Fields(), "c", "3")
			assert.NotContainKey(t, counter.entry.Fields(), "logsSkipped")
			assert.ContainsKey(t, counter.entry.Fields(), "nextLog")
			assert.ContainsKey(t, counter.entry.Fields(), "error")

			// Check burst.
			logger = log.NewRateLimitedLogger(
				log.OptInterval(200*time.Millisecond),
				log.OptLogger(logrusLogger),
				log.OptBurst(2),
			)
			logfn(logger) // First log, resets logging interval and burst count
			assert.NotContainKey(t, counter.entry.Fields(), "nextLog")
			assert.NotContainKey(t, counter.entry.Fields(), "logsSkipped")
			logfn(logger) // First burst
			assert.NotContainKey(t, counter.entry.Fields(), "nextLog")
			assert.NotContainKey(t, counter.entry.Fields(), "logsSkipped")
			logfn(logger) // Second burst
			assert.ContainsKey(t, counter.entry.Fields(), "nextLog")
			assert.NotContainKey(t, counter.entry.Fields(), "logsSkipped")
			logfn(logger) // Skipped
			logfn(logger) // Skipped
			assert.Equal(t, counter.count, 6)
			// Wait for logging interval.
			time.Sleep(200 * time.Millisecond)
			logfn(logger) // First log, resets logging interval and burst count
			assert.NotContainKey(t, counter.entry.Fields(), "nextLog")
			assert.ContainsKey(t, counter.entry.Fields(), "logsSkipped")
			assert.Equal(t, counter.entry.Fields()["logsSkipped"], 2)
			logfn(logger) // First burst
			assert.NotContainKey(t, counter.entry.Fields(), "nextLog")
			assert.NotContainKey(t, counter.entry.Fields(), "logsSkipped")
			logfn(logger) // Second burst
			assert.ContainsKey(t, counter.entry.Fields(), "nextLog")
			assert.NotContainKey(t, counter.entry.Fields(), "logsSkipped")
			logfn(logger) // Skipped
			logfn(logger) // Skipped
			assert.Equal(t, counter.count, 9)
		})
	}
}
