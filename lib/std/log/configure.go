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
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/sirupsen/logrus"
)

// Counter is the minimal interface used by the log package for incrementing
// log-health metrics. It is deliberately one method so any metric system
// (Prometheus, statsd, OpenTelemetry, a custom collector, a test fake) can
// satisfy it without lib/std/log depending on that system.
//
// prometheus.Counter satisfies this interface directly — its Inc method
// matches verbatim — so existing call sites pass *prometheus.Counter values
// unchanged.
type Counter interface {
	Inc()
}

// Options is the full configuration passed to Configure().
//
// A nil pointer for Screen, File, or Syslog disables that destination.
// Configure panics if called twice; pass everything you need in one call.
type Options struct {
	// Component is the prefix used in log lines (e.g. "felix", "typha").
	// Equivalent to a prior SetComponent call.
	Component string

	// Screen, File, Syslog control destinations. nil disables.
	Screen *ScreenConfig
	File   *FileConfig
	Syslog *SyslogConfig

	// DebugFilenameRegex restricts debug-level logs to source files whose
	// basename matches the regex. nil means "no restriction".
	DebugFilenameRegex *regexp.Regexp

	// DebugDisableLogDropping forces all logs to be queued even if the
	// destination's channel is full. Off by default.
	DebugDisableLogDropping bool

	// SingleThreaded disables the standard logger's internal mutex. Safe
	// only when all writes go through the background hook (typha pattern).
	SingleThreaded bool

	// Counters is optional metrics. Zero-value (nil counters) is fine.
	Counters Counters
}

// ScreenConfig controls the stdout destination.
type ScreenConfig struct {
	Level Level
}

// FileConfig controls the file destination. The parent directory is created
// if necessary. On Linux the file is opened with a rotation-aware writer; on
// other platforms with a plain os.OpenFile.
type FileConfig struct {
	Level Level
	Path  string
}

// SyslogConfig controls the syslog destination. Tag is the syslog program
// name (e.g. "calico-felix"). Syslog is Linux-only; on other platforms
// configuring it returns an error from Configure.
type SyslogConfig struct {
	Level Level
	Tag   string
}

// Counters carry counters that record logging health. Both fields are
// optional; nil values are silently absorbed.
type Counters struct {
	// DroppedLogs counts logs dropped because a destination's channel was full.
	DroppedLogs Counter
	// WriteErrors counts errors writing to any destination.
	WriteErrors Counter
}

// ErrAlreadyConfigured is returned (or panicked with) if Configure is called twice.
var ErrAlreadyConfigured = errors.New("log.Configure has already been called")

// Configure installs the full logging configuration. Must be called exactly
// once per process, at startup. Panics if called twice.
//
// Errors opening the file or connecting to syslog are returned as a joined
// error so the caller can log and continue (or treat as fatal). The logger
// remains in a working state regardless: any destinations that did open are
// active.
func Configure(opts Options) error {
	var (
		ran    bool
		runErr error
	)
	configureOnce.Do(func() {
		ran = true
		runErr = doConfigure(opts)
	})
	if !ran {
		panic(ErrAlreadyConfigured)
	}
	return runErr
}

// IsConfigured reports whether Configure has been called.
func IsConfigured() bool {
	stateMu.Lock()
	defer stateMu.Unlock()
	return configured
}

func doConfigure(opts Options) error {
	stateMu.Lock()
	if opts.Component != "" {
		currentComponent = opts.Component
	}
	currentFormatter = newFormatter(currentComponent)
	logrus.SetFormatter(currentFormatter)
	component := currentComponent
	stateMu.Unlock()

	// Resolve levels and pick the most verbose. logrus drops anything
	// less verbose globally before the hook even runs.
	var screenLevel, fileLevel, syslogLevel logrus.Level
	mostVerbose := logrus.PanicLevel
	if opts.Screen != nil {
		screenLevel = logrus.Level(opts.Screen.Level)
		if screenLevel > mostVerbose {
			mostVerbose = screenLevel
		}
	}
	if opts.File != nil {
		fileLevel = logrus.Level(opts.File.Level)
		if fileLevel > mostVerbose {
			mostVerbose = fileLevel
		}
	}
	if opts.Syslog != nil {
		syslogLevel = logrus.Level(opts.Syslog.Level)
		if syslogLevel > mostVerbose {
			mostVerbose = syslogLevel
		}
	}
	logrus.SetLevel(mostVerbose)

	var dests []*destination
	var errs []error

	if opts.Screen != nil {
		dests = append(dests, newStreamDestination(
			screenLevel,
			os.Stdout,
			make(chan queuedLog, logQueueSize),
			opts.DebugDisableLogDropping,
			opts.Counters.WriteErrors,
		))
	}

	if opts.File != nil && opts.File.Path != "" {
		fd, err := newFileDestination(
			fileLevel,
			opts.File.Path,
			opts.DebugDisableLogDropping,
			opts.Counters.WriteErrors,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("opening log file %q: %w", opts.File.Path, err))
		} else {
			dests = append(dests, fd)
		}
	}

	if opts.Syslog != nil && opts.Syslog.Tag != "" {
		sd, err := newSyslogDestinationForTag(
			syslogLevel,
			opts.Syslog.Tag,
			opts.DebugDisableLogDropping,
			opts.Counters.WriteErrors,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("connecting to syslog: %w", err))
		} else if sd != nil {
			dests = append(dests, sd)
		}
	}

	if len(dests) > 0 {
		hook := newBackgroundHook(
			filterLevels(mostVerbose),
			syslogLevel,
			component,
			dests,
			opts.DebugFilenameRegex,
			opts.Counters.DroppedLogs,
		)
		hook.start()
		logrus.AddHook(hook)
		// Disable logrus's single-output path. Logs now fan out via the hook.
		logrus.SetOutput(&nullWriter{})
	}

	if opts.SingleThreaded {
		logrus.StandardLogger().SetNoLock()
	}

	stateMu.Lock()
	configured = true
	stateMu.Unlock()

	return errors.Join(errs...)
}
