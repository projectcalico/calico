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

package logutils

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	fieldLogSkipped = "logs-skipped"
	fieldLogNextLog = "next-log"
	defaultInterval = 5 * time.Minute
)

// NewRateLimitedLogger returns a RateLimitedLogger which can be used for rate limited logging.
//
// Methods are essentially the same as the logrus logging methods, but there is no Panic or Fatal log since these don't
// make much sense for rate limited logging.
//
// Log requests are only processed if allowed by the logging level. The first processed log will always be written.
// Subsequent processed logs will not be written within the configured time interval. Once the time interval has passed
// the next log will be written. The logs include additional fields specifying the number of skipped logs and the
// minimum time for the next expected log.  The Force() method can be used to ensure the log is written - this resets
// the time for the next log.
//
// Typical use might be as follows:
//
//	logger := NewRateLimitedLogger().WithField("key": "my-key")
//	for {
//	  logger.Infof("Checking some stuff: %s", myStuff)
//	  complete = doSomeStuff()
//	  if complete {
//	    break
//	  }
//	}
//
//	// Use force to ensure our final log is printed and it contains the summary info about the number of skipped logs.
//	logger.Force().Info("Finished checking stuff")
//
// The config is an optional parameter. If not specified, default values are used (see RateLimitedLoggerConfig for
// details about the default values).
func NewRateLimitedLogger(opts ...RateLimitedLoggerOpt) *RateLimitedLogger {
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

type RateLimitedLoggerOpt func(*RateLimitedLogger)

func OptInterval(d time.Duration) RateLimitedLoggerOpt {
	return func(r *RateLimitedLogger) {
		r.data.interval = d
	}
}

func OptLogger(l *logrus.Logger) RateLimitedLoggerOpt {
	return func(r *RateLimitedLogger) {
		r.entry = logrus.NewEntry(l)
	}
}

type intervalData struct {
	nextLog time.Time

	// Interval for logging.
	interval time.Duration

	// The number skipped since the last processed log.
	skipped int

	// Lock used to access to this data. This lock is never held while writing a log.
	lock sync.Mutex
}

type RateLimitedLogger struct {
	// Data shared between all loggers created from the "root" RateLimitedLogger.
	data *intervalData

	// Whether to force the next log to be processed.
	force bool

	// The logrus entry used for writing the log.
	entry *logrus.Entry
}

func (logger *RateLimitedLogger) logEntry() *logrus.Entry {
	now := time.Now()
	logger.data.lock.Lock()
	defer logger.data.lock.Unlock()
	if logger.force || now.Sub(logger.data.nextLog) >= 0 {
		nextLog := now.Add(logger.data.interval)
		entry := logger.entry.WithFields(logrus.Fields{
			fieldLogSkipped: logger.data.skipped,
			fieldLogNextLog: nextLog,
		})
		logger.force = false
		logger.data.nextLog = nextLog
		logger.data.skipped = 0
		return entry
	}
	logger.data.skipped++
	return nil
}

// Force forces the next log to be processed. Note that this does not force the log to be written since that is also
// dependent on the logging level.
func (logger *RateLimitedLogger) Force() *RateLimitedLogger {
	return &RateLimitedLogger{
		data:  logger.data,
		entry: logger.entry,
		force: true,
	}
}

// WithError adds an error as single field (using the key defined in ErrorKey) to the RateLimitedLogger.
func (logger *RateLimitedLogger) WithError(err error) *RateLimitedLogger {
	return &RateLimitedLogger{
		data:  logger.data,
		entry: logger.entry.WithError(err),
	}
}

// WithField adds a single field to the RateLimitedLogger.
func (logger *RateLimitedLogger) WithField(key string, value interface{}) *RateLimitedLogger {
	return &RateLimitedLogger{
		data:  logger.data,
		entry: logger.entry.WithField(key, value),
	}
}

// WithFields adds a map of fields to the RateLimitedLogger.
func (logger *RateLimitedLogger) WithFields(fields logrus.Fields) *RateLimitedLogger {
	return &RateLimitedLogger{
		data:  logger.data,
		entry: logger.entry.WithFields(fields),
	}
}

func (logger *RateLimitedLogger) Debug(args ...interface{}) {
	if logger.level() >= logrus.DebugLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Debug(args...)
		}
	}
}

func (logger *RateLimitedLogger) Print(args ...interface{}) {
	if entry := logger.logEntry(); entry != nil {
		entry.Print(args...)
	}
}

func (logger *RateLimitedLogger) Info(args ...interface{}) {
	if logger.level() >= logrus.InfoLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Info(args...)
		}
	}
}

func (logger *RateLimitedLogger) Warn(args ...interface{}) {
	if logger.level() >= logrus.WarnLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Warn(args...)
		}
	}
}

func (logger *RateLimitedLogger) Warning(args ...interface{}) {
	if logger.level() >= logrus.WarnLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Warning(args...)
		}
	}
}

func (logger *RateLimitedLogger) Error(args ...interface{}) {
	if logger.level() >= logrus.ErrorLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Error(args...)
		}
	}
}

func (logger *RateLimitedLogger) Debugf(format string, args ...interface{}) {
	if logger.level() >= logrus.DebugLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Debugf(format, args...)
		}
	}
}

func (logger *RateLimitedLogger) Infof(format string, args ...interface{}) {
	if logger.level() >= logrus.InfoLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Infof(format, args...)
		}
	}
}

func (logger *RateLimitedLogger) Printf(format string, args ...interface{}) {
	if entry := logger.logEntry(); entry != nil {
		entry.Printf(format, args...)
	}
}

func (logger *RateLimitedLogger) Warnf(format string, args ...interface{}) {
	if logger.level() >= logrus.WarnLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Warnf(format, args...)
		}
	}
}

func (logger *RateLimitedLogger) Warningf(format string, args ...interface{}) {
	if logger.level() >= logrus.WarnLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Warningf(format, args...)
		}
	}
}

func (logger *RateLimitedLogger) Errorf(format string, args ...interface{}) {
	if logger.level() >= logrus.ErrorLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Errorf(format, args...)
		}
	}
}

// Entry Println family functions

func (logger *RateLimitedLogger) Debugln(args ...interface{}) {
	if logger.level() >= logrus.DebugLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Debugln(args...)
		}
	}
}

func (logger *RateLimitedLogger) Infoln(args ...interface{}) {
	if logger.level() >= logrus.InfoLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Infoln(args...)
		}
	}
}

func (logger *RateLimitedLogger) Println(args ...interface{}) {
	if entry := logger.logEntry(); entry != nil {
		entry.Println(args...)
	}
}

func (logger *RateLimitedLogger) Warnln(args ...interface{}) {
	if logger.level() >= logrus.WarnLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Warnln(args...)
		}
	}
}

func (logger *RateLimitedLogger) Warningln(args ...interface{}) {
	if logger.level() >= logrus.WarnLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Warningln(args...)
		}
	}
}

func (logger *RateLimitedLogger) Errorln(args ...interface{}) {
	if logger.level() >= logrus.ErrorLevel {
		if entry := logger.logEntry(); entry != nil {
			entry.Errorln(args...)
		}
	}
}

// level returns the log level associated with the logger.  (copied from logrus since this is not a public method)
func (logger *RateLimitedLogger) level() logrus.Level {
	return logrus.Level(atomic.LoadUint32((*uint32)(&logger.entry.Logger.Level)))
}
