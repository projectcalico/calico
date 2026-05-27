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

package log

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	fieldLogSkipped = "logsSkipped"
	fieldLogNextLog = "nextLog"
	defaultInterval = 5 * time.Minute
)

// NewRateLimitedLogger returns a Logger that throttles repeated emissions
// to at most one per interval (default 5 minutes). Derived loggers from
// WithField/WithFields/WithError share the throttle state with their
// parent so that adding fields does not reset the throttle. Use Force to
// bypass the throttle for a single emit.
//
// Fatal and Panic always emit — they are terminal, so the rate limit is
// bypassed.
//
// Typical use:
//
//	logger := log.NewRateLimitedLogger().WithField("key", myKey)
//	for !done {
//	    logger.Infof("Checking some stuff: %s", myStuff)
//	    done = doSomeStuff()
//	}
//	log.Force(logger).Info("Finished checking stuff")
func NewRateLimitedLogger(opts ...RateLimitedOption) Logger {
	r := &rateLimitedLogger{
		data: &intervalData{
			nextLog:  time.Now(),
			interval: defaultInterval,
		},
		entry: logrus.NewEntry(logrus.StandardLogger()),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// RateLimitedOption configures the Logger returned by NewRateLimitedLogger.
type RateLimitedOption func(*rateLimitedLogger)

// WithInterval sets the minimum interval between emitted logs.
// Default is 5 minutes.
func WithInterval(d time.Duration) RateLimitedOption {
	return func(r *rateLimitedLogger) { r.data.interval = d }
}

// WithBurst sets the number of logs that can be emitted in a row before
// throttling kicks in. Default is 0 (no burst — only one log per interval).
func WithBurst(n int) RateLimitedOption {
	return func(r *rateLimitedLogger) {
		r.data.burst = n
		r.data.remainingBurst = n
	}
}

// WithBaseLogger sets the underlying Logger used to emit. Default is the
// package default. Useful when the caller has a per-component Logger they
// want the rate-limited wrapper to inherit fields from.
func WithBaseLogger(l Logger) RateLimitedOption {
	return func(r *rateLimitedLogger) {
		if impl, ok := l.(*logrusLogger); ok {
			r.entry = impl.entry
		}
	}
}

// Force returns a Logger whose next emission bypasses the rate limit if
// l is a rate-limited logger; otherwise it returns l unchanged. Force
// does not bypass level filtering.
func Force(l Logger) Logger {
	if rl, ok := l.(*rateLimitedLogger); ok {
		return &rateLimitedLogger{data: rl.data, entry: rl.entry, force: true}
	}
	return l
}

type intervalData struct {
	nextLog        time.Time
	interval       time.Duration
	burst          int
	skipped        int
	lock           sync.Mutex
	remainingBurst int
}

type rateLimitedLogger struct {
	data  *intervalData
	force bool
	entry *logrus.Entry
}

func (r *rateLimitedLogger) logEntry() *logrus.Entry {
	now := time.Now()
	r.data.lock.Lock()
	defer r.data.lock.Unlock()

	var shouldLog, shouldReset bool
	if r.force || now.After(r.data.nextLog) {
		shouldLog = true
		shouldReset = true
	}
	if r.data.remainingBurst > 0 {
		shouldLog = true
		r.data.remainingBurst--
	}

	if !shouldLog {
		r.data.skipped++
		return nil
	}

	skipped := r.data.skipped
	if shouldReset {
		r.force = false
		r.data.nextLog = now.Add(r.data.interval)
		r.data.remainingBurst = r.data.burst
		r.data.skipped = 0
	}

	entry := r.entry
	if skipped > 0 || r.data.remainingBurst == 0 {
		fields := logrus.Fields{}
		if skipped > 0 {
			fields[fieldLogSkipped] = skipped
		}
		if r.data.remainingBurst == 0 {
			fields[fieldLogNextLog] = r.data.nextLog
		}
		entry = r.entry.WithFields(fields)
	}
	return entry
}

// WithError attaches an error to derived loggers.
func (r *rateLimitedLogger) WithError(err error) Logger {
	return &rateLimitedLogger{data: r.data, entry: r.entry.WithError(err)}
}

// WithField attaches a field to derived loggers.
func (r *rateLimitedLogger) WithField(key string, value any) Logger {
	return &rateLimitedLogger{data: r.data, entry: r.entry.WithField(key, value)}
}

// WithFields attaches fields to derived loggers.
func (r *rateLimitedLogger) WithFields(fields Fields) Logger {
	return &rateLimitedLogger{data: r.data, entry: r.entry.WithFields(logrus.Fields(fields))}
}

func (r *rateLimitedLogger) Trace(args ...any) {
	if r.level() >= logrus.TraceLevel {
		if e := r.logEntry(); e != nil {
			e.Trace(args...)
		}
	}
}

func (r *rateLimitedLogger) Tracef(format string, args ...any) {
	if r.level() >= logrus.TraceLevel {
		if e := r.logEntry(); e != nil {
			e.Tracef(format, args...)
		}
	}
}

func (r *rateLimitedLogger) Debug(args ...any) {
	if r.level() >= logrus.DebugLevel {
		if e := r.logEntry(); e != nil {
			e.Debug(args...)
		}
	}
}

func (r *rateLimitedLogger) Debugf(format string, args ...any) {
	if r.level() >= logrus.DebugLevel {
		if e := r.logEntry(); e != nil {
			e.Debugf(format, args...)
		}
	}
}

func (r *rateLimitedLogger) Info(args ...any) {
	if r.level() >= logrus.InfoLevel {
		if e := r.logEntry(); e != nil {
			e.Info(args...)
		}
	}
}

func (r *rateLimitedLogger) Infof(format string, args ...any) {
	if r.level() >= logrus.InfoLevel {
		if e := r.logEntry(); e != nil {
			e.Infof(format, args...)
		}
	}
}

func (r *rateLimitedLogger) Warn(args ...any) {
	if r.level() >= logrus.WarnLevel {
		if e := r.logEntry(); e != nil {
			e.Warn(args...)
		}
	}
}

func (r *rateLimitedLogger) Warnf(format string, args ...any) {
	if r.level() >= logrus.WarnLevel {
		if e := r.logEntry(); e != nil {
			e.Warnf(format, args...)
		}
	}
}

// Warning is an alias of Warn for API compatibility with logrus call sites.
func (r *rateLimitedLogger) Warning(args ...any) { r.Warn(args...) }

// Warningf is an alias of Warnf for API compatibility with logrus call sites.
func (r *rateLimitedLogger) Warningf(format string, args ...any) { r.Warnf(format, args...) }

func (r *rateLimitedLogger) Error(args ...any) {
	if r.level() >= logrus.ErrorLevel {
		if e := r.logEntry(); e != nil {
			e.Error(args...)
		}
	}
}

func (r *rateLimitedLogger) Errorf(format string, args ...any) {
	if r.level() >= logrus.ErrorLevel {
		if e := r.logEntry(); e != nil {
			e.Errorf(format, args...)
		}
	}
}

// Fatal emits and terminates the process. Always emits — rate limiting
// is bypassed because Fatal is terminal.
func (r *rateLimitedLogger) Fatal(args ...any) { r.entry.Fatal(args...) }

// Fatalf emits and terminates the process. Always emits.
func (r *rateLimitedLogger) Fatalf(format string, args ...any) { r.entry.Fatalf(format, args...) }

// Panic emits and panics. Always emits — rate limiting is bypassed
// because Panic is terminal.
func (r *rateLimitedLogger) Panic(args ...any) { r.entry.Panic(args...) }

// Panicf emits and panics. Always emits.
func (r *rateLimitedLogger) Panicf(format string, args ...any) { r.entry.Panicf(format, args...) }

// Print emits at Info level without applying level filtering; useful for
// callers that integrate with the standard library's log.Logger contract.
func (r *rateLimitedLogger) Print(args ...any) {
	if e := r.logEntry(); e != nil {
		e.Print(args...)
	}
}

// Printf emits at Info level without applying level filtering.
func (r *rateLimitedLogger) Printf(format string, args ...any) {
	if e := r.logEntry(); e != nil {
		e.Printf(format, args...)
	}
}

// Println emits at Info level without applying level filtering.
func (r *rateLimitedLogger) Println(args ...any) {
	if e := r.logEntry(); e != nil {
		e.Println(args...)
	}
}

// Debugln matches logrus's Println-style emit at Debug level.
func (r *rateLimitedLogger) Debugln(args ...any) {
	if r.level() >= logrus.DebugLevel {
		if e := r.logEntry(); e != nil {
			e.Debugln(args...)
		}
	}
}

// Infoln matches logrus's Println-style emit at Info level.
func (r *rateLimitedLogger) Infoln(args ...any) {
	if r.level() >= logrus.InfoLevel {
		if e := r.logEntry(); e != nil {
			e.Infoln(args...)
		}
	}
}

// Warnln matches logrus's Println-style emit at Warn level.
func (r *rateLimitedLogger) Warnln(args ...any) {
	if r.level() >= logrus.WarnLevel {
		if e := r.logEntry(); e != nil {
			e.Warnln(args...)
		}
	}
}

// Warningln is an alias of Warnln for API compatibility with logrus.
func (r *rateLimitedLogger) Warningln(args ...any) { r.Warnln(args...) }

// Errorln matches logrus's Println-style emit at Error level.
func (r *rateLimitedLogger) Errorln(args ...any) {
	if r.level() >= logrus.ErrorLevel {
		if e := r.logEntry(); e != nil {
			e.Errorln(args...)
		}
	}
}

// Fatalln emits and terminates the process. Always emits.
func (r *rateLimitedLogger) Fatalln(args ...any) { r.entry.Fatalln(args...) }

// Panicln emits and panics. Always emits.
func (r *rateLimitedLogger) Panicln(args ...any) { r.entry.Panicln(args...) }

// Level returns the underlying logger's level.
func (r *rateLimitedLogger) Level() Level {
	return Level(r.level())
}

// IsLevelEnabled reports whether the given level would be emitted.
func (r *rateLimitedLogger) IsLevelEnabled(level Level) bool {
	return logrus.Level(level) <= r.level()
}

// level returns the underlying logger's level via an atomic read, mirroring
// logrus's own non-exported helper.
func (r *rateLimitedLogger) level() logrus.Level {
	return logrus.Level(atomic.LoadUint32((*uint32)(&r.entry.Logger.Level)))
}
