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

// NewRateLimitedLogger returns a RateLimitedLogger.
//
// The first processed log always emits. Subsequent processed logs are
// throttled per the configured interval; logs that are throttled are
// counted and reported on the next emitted log. Force() can be used to
// guarantee a log is emitted at the end of a noisy loop.
//
// Methods are essentially the same as the Logger interface, except Panic
// and Fatal are not exposed because they don't make sense for rate-limited
// logging.
//
// Typical use:
//
//	logger := log.NewRateLimitedLogger().WithField("key", myKey)
//	for !done {
//	    logger.Infof("Checking some stuff: %s", myStuff)
//	    done = doSomeStuff()
//	}
//	logger.Force().Info("Finished checking stuff")
func NewRateLimitedLogger(opts ...RateLimitedOption) *RateLimitedLogger {
	r := &RateLimitedLogger{
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

// RateLimitedOption configures a RateLimitedLogger.
type RateLimitedOption func(*RateLimitedLogger)

// WithInterval sets the minimum interval between emitted logs.
// Default is 5 minutes.
func WithInterval(d time.Duration) RateLimitedOption {
	return func(r *RateLimitedLogger) { r.data.interval = d }
}

// WithBurst sets the number of logs that can be emitted in a row before
// throttling kicks in. Default is 0 (no burst — only one log per interval).
func WithBurst(n int) RateLimitedOption {
	return func(r *RateLimitedLogger) {
		r.data.burst = n
		r.data.remainingBurst = n
	}
}

// WithBaseLogger sets the underlying Logger used to emit. Default is the
// package default. Useful when the caller has a per-component Logger they
// want the rate-limited wrapper to inherit fields from.
func WithBaseLogger(l Logger) RateLimitedOption {
	return func(r *RateLimitedLogger) {
		if impl, ok := l.(*logrusLogger); ok {
			r.entry = impl.entry
		}
	}
}

type intervalData struct {
	nextLog        time.Time
	interval       time.Duration
	burst          int
	skipped        int
	lock           sync.Mutex
	remainingBurst int
}

// RateLimitedLogger throttles repeated log calls. Derived loggers (via
// WithField/WithFields/WithError) share the rate-limit state with their
// parent so that adding fields does not reset the throttle.
type RateLimitedLogger struct {
	data  *intervalData
	force bool
	entry *logrus.Entry
}

func (r *RateLimitedLogger) logEntry() *logrus.Entry {
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

// Force returns a derived logger whose next emission bypasses the rate limit.
// Does not bypass level filtering.
func (r *RateLimitedLogger) Force() *RateLimitedLogger {
	return &RateLimitedLogger{data: r.data, entry: r.entry, force: true}
}

// WithError attaches an error to derived loggers.
func (r *RateLimitedLogger) WithError(err error) *RateLimitedLogger {
	return &RateLimitedLogger{data: r.data, entry: r.entry.WithError(err)}
}

// WithField attaches a field to derived loggers.
func (r *RateLimitedLogger) WithField(key string, value any) *RateLimitedLogger {
	return &RateLimitedLogger{data: r.data, entry: r.entry.WithField(key, value)}
}

// WithFields attaches fields to derived loggers.
func (r *RateLimitedLogger) WithFields(fields Fields) *RateLimitedLogger {
	return &RateLimitedLogger{data: r.data, entry: r.entry.WithFields(logrus.Fields(fields))}
}

func (r *RateLimitedLogger) Debug(args ...any) {
	if r.level() >= logrus.DebugLevel {
		if e := r.logEntry(); e != nil {
			e.Debug(args...)
		}
	}
}

func (r *RateLimitedLogger) Debugf(format string, args ...any) {
	if r.level() >= logrus.DebugLevel {
		if e := r.logEntry(); e != nil {
			e.Debugf(format, args...)
		}
	}
}

func (r *RateLimitedLogger) Info(args ...any) {
	if r.level() >= logrus.InfoLevel {
		if e := r.logEntry(); e != nil {
			e.Info(args...)
		}
	}
}

func (r *RateLimitedLogger) Infof(format string, args ...any) {
	if r.level() >= logrus.InfoLevel {
		if e := r.logEntry(); e != nil {
			e.Infof(format, args...)
		}
	}
}

func (r *RateLimitedLogger) Warn(args ...any) {
	if r.level() >= logrus.WarnLevel {
		if e := r.logEntry(); e != nil {
			e.Warn(args...)
		}
	}
}

func (r *RateLimitedLogger) Warnf(format string, args ...any) {
	if r.level() >= logrus.WarnLevel {
		if e := r.logEntry(); e != nil {
			e.Warnf(format, args...)
		}
	}
}

// Warning is an alias of Warn for API compatibility with logrus call sites.
func (r *RateLimitedLogger) Warning(args ...any) { r.Warn(args...) }

// Warningf is an alias of Warnf for API compatibility with logrus call sites.
func (r *RateLimitedLogger) Warningf(format string, args ...any) { r.Warnf(format, args...) }

func (r *RateLimitedLogger) Error(args ...any) {
	if r.level() >= logrus.ErrorLevel {
		if e := r.logEntry(); e != nil {
			e.Error(args...)
		}
	}
}

func (r *RateLimitedLogger) Errorf(format string, args ...any) {
	if r.level() >= logrus.ErrorLevel {
		if e := r.logEntry(); e != nil {
			e.Errorf(format, args...)
		}
	}
}

// Print emits at Info level without applying level filtering; useful for
// callers that integrate with the standard library's log.Logger contract.
func (r *RateLimitedLogger) Print(args ...any) {
	if e := r.logEntry(); e != nil {
		e.Print(args...)
	}
}

// Printf emits at Info level without applying level filtering.
func (r *RateLimitedLogger) Printf(format string, args ...any) {
	if e := r.logEntry(); e != nil {
		e.Printf(format, args...)
	}
}

// Println emits at Info level without applying level filtering.
func (r *RateLimitedLogger) Println(args ...any) {
	if e := r.logEntry(); e != nil {
		e.Println(args...)
	}
}

// Debugln matches logrus's Println-style emit at Debug level.
func (r *RateLimitedLogger) Debugln(args ...any) {
	if r.level() >= logrus.DebugLevel {
		if e := r.logEntry(); e != nil {
			e.Debugln(args...)
		}
	}
}

// Infoln matches logrus's Println-style emit at Info level.
func (r *RateLimitedLogger) Infoln(args ...any) {
	if r.level() >= logrus.InfoLevel {
		if e := r.logEntry(); e != nil {
			e.Infoln(args...)
		}
	}
}

// Warnln matches logrus's Println-style emit at Warn level.
func (r *RateLimitedLogger) Warnln(args ...any) {
	if r.level() >= logrus.WarnLevel {
		if e := r.logEntry(); e != nil {
			e.Warnln(args...)
		}
	}
}

// Warningln is an alias of Warnln for API compatibility with logrus.
func (r *RateLimitedLogger) Warningln(args ...any) { r.Warnln(args...) }

// Errorln matches logrus's Println-style emit at Error level.
func (r *RateLimitedLogger) Errorln(args ...any) {
	if r.level() >= logrus.ErrorLevel {
		if e := r.logEntry(); e != nil {
			e.Errorln(args...)
		}
	}
}

// level returns the underlying logger's level via an atomic read, mirroring
// logrus's own non-exported helper.
func (r *RateLimitedLogger) level() logrus.Level {
	return logrus.Level(atomic.LoadUint32((*uint32)(&r.entry.Logger.Level)))
}
