// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package logutils_test

import (
	"errors"
	"os"
	"time"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	. "github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

// A mock log formatter that simply serves to count log invocations.
type mockLogFormatter struct {
	count int
	entry *log.Entry
}

func (s *mockLogFormatter) Format(e *log.Entry) ([]byte, error) {
	s.count++
	s.entry = e
	return nil, nil
}

var _ = DescribeTable("First and Interval logging",
	func(expectedLevel log.Level, testLogLevel bool, logfn func(logger *RateLimitedLogger)) {
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

		// If we are testing log levels then change the logging level to be lower than the expected level of the log and
		// check that we don't trigger the start of the rate limited logging (i.e. the log is not processed).
		if testLogLevel {
			for i := expectedLevel - 1; i > log.PanicLevel; i-- {
				logrusLogger.SetLevel(i)
				logfn(logger)
			}
			logrusLogger.SetLevel(log.DebugLevel)
		}

		// First log will be written.
		logfn(logger.WithError(errors.New("error")))
		Expect(counter.count).To(Equal(1))
		Expect(counter.entry.Data).To(HaveKeyWithValue("a", 1))
		Expect(counter.entry.Data).To(HaveKeyWithValue("b", 2))
		Expect(counter.entry.Data).To(HaveKeyWithValue("c", "3"))
		Expect(counter.entry.Data).NotTo(HaveKey("logsSkipped"))
		Expect(counter.entry.Data).To(HaveKey("nextLog"))
		Expect(counter.entry.Data).To(HaveKey("error"))

		// Next two log will be skipped.
		logfn(logger.WithField("a", 1))
		logfn(logger.WithField("a", 1))
		Expect(counter.count).To(Equal(1))

		// Wait for logging interval.
		time.Sleep(200 * time.Millisecond)

		// Next log will be written.
		logfn(logger.WithFields(log.Fields{"b": 2, "c": "3"}))
		Expect(counter.count).To(Equal(2))
		Expect(counter.entry.Data).To(HaveKeyWithValue("a", 1))
		Expect(counter.entry.Data).To(HaveKeyWithValue("b", 2))
		Expect(counter.entry.Data).To(HaveKeyWithValue("c", "3"))
		Expect(counter.entry.Data).To(HaveKeyWithValue("logsSkipped", 2))
		Expect(counter.entry.Data).To(HaveKey("nextLog"))
		Expect(counter.entry.Data).To(HaveKey("error"))

		// Force, so next log will also be written.
		logfn(logger.Force())
		Expect(counter.count).To(Equal(3))
		Expect(counter.entry.Level).To(Equal(expectedLevel))
		Expect(counter.entry.Data).To(HaveKeyWithValue("a", 1))
		Expect(counter.entry.Data).To(HaveKeyWithValue("b", 2))
		Expect(counter.entry.Data).To(HaveKeyWithValue("c", "3"))
		Expect(counter.entry.Data).NotTo(HaveKey("logsSkipped"))
		Expect(counter.entry.Data).To(HaveKey("nextLog"))
		Expect(counter.entry.Data).To(HaveKey("error"))

		// Check burst.
		logger = NewRateLimitedLogger(
			OptInterval(200*time.Millisecond),
			OptLogger(logrusLogger),
			OptBurst(2),
		)
		logfn(logger) // First log, resets logging interval and burst count
		Expect(counter.entry.Data).NotTo(HaveKey("nextLog"))
		Expect(counter.entry.Data).NotTo(HaveKey("logsSkipped"))
		logfn(logger) // First burst
		Expect(counter.entry.Data).NotTo(HaveKey("nextLog"))
		Expect(counter.entry.Data).NotTo(HaveKey("logsSkipped"))
		logfn(logger) // Second burst
		Expect(counter.entry.Data).To(HaveKey("nextLog"))
		Expect(counter.entry.Data).NotTo(HaveKey("logsSkipped"))
		logfn(logger) // Skipped
		logfn(logger) // Skipped
		Expect(counter.count).To(Equal(6))
		// Wait for logging interval.
		time.Sleep(200 * time.Millisecond)
		logfn(logger) // First log, resets logging interval and burst count
		Expect(counter.entry.Data).NotTo(HaveKey("nextLog"))
		Expect(counter.entry.Data).To(HaveKeyWithValue("logsSkipped", 2))
		logfn(logger) // First burst
		Expect(counter.entry.Data).NotTo(HaveKey("nextLog"))
		Expect(counter.entry.Data).NotTo(HaveKey("logsSkipped"))
		logfn(logger) // Second burst
		Expect(counter.entry.Data).To(HaveKey("nextLog"))
		Expect(counter.entry.Data).NotTo(HaveKey("logsSkipped"))
		logfn(logger) // Skipped
		logfn(logger) // Skipped
		Expect(counter.count).To(Equal(9))
	},
	Entry("Debug", log.DebugLevel, true, func(l *RateLimitedLogger) { l.Debug("log", "now") }),
	Entry("Print", log.InfoLevel, false, func(l *RateLimitedLogger) { l.Print("log", "now") }),
	Entry("Info", log.InfoLevel, true, func(l *RateLimitedLogger) { l.Info("log", "now") }),
	Entry("Warn", log.WarnLevel, true, func(l *RateLimitedLogger) { l.Warn("log", "now") }),
	Entry("Warning", log.WarnLevel, true, func(l *RateLimitedLogger) { l.Warning("log", "now") }),
	Entry("Error", log.ErrorLevel, true, func(l *RateLimitedLogger) { l.Error("log", "now") }),
	Entry("Debugf", log.DebugLevel, true, func(l *RateLimitedLogger) { l.Debugf("log %s", "hello") }),
	Entry("Printf", log.InfoLevel, false, func(l *RateLimitedLogger) { l.Printf("log %s", "hello") }),
	Entry("Infof", log.InfoLevel, true, func(l *RateLimitedLogger) { l.Infof("log %s", "hello") }),
	Entry("Warnf", log.WarnLevel, true, func(l *RateLimitedLogger) { l.Warnf("log %s", "hello") }),
	Entry("Warningf", log.WarnLevel, true, func(l *RateLimitedLogger) { l.Warningf("log %s", "hello") }),
	Entry("Errorf", log.ErrorLevel, true, func(l *RateLimitedLogger) { l.Errorf("log %s", "hello") }),
	Entry("Debugln", log.DebugLevel, true, func(l *RateLimitedLogger) { l.Debugln("log", "now") }),
	Entry("Println", log.InfoLevel, false, func(l *RateLimitedLogger) { l.Println("log", "now") }),
	Entry("Infoln", log.InfoLevel, true, func(l *RateLimitedLogger) { l.Infoln("log", "now") }),
	Entry("Warnln", log.WarnLevel, true, func(l *RateLimitedLogger) { l.Warnln("log", "now") }),
	Entry("Warningln", log.WarnLevel, true, func(l *RateLimitedLogger) { l.Warningln("log", "now") }),
	Entry("Errorln", log.ErrorLevel, true, func(l *RateLimitedLogger) { l.Errorln("log", "now") }),
)
