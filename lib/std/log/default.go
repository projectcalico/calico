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
	"io"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
)

// State held outside the Logger interface for the package-level API:
// the formatter (mutated by SetComponent / Configure), the default Logger
// backing the top-level functions, and the configure-once guard.
var (
	stateMu          sync.Mutex
	currentComponent string
	currentFormatter *formatter
	configureOnce    sync.Once
	configured       bool
)

var defaultLogger Logger = newLogrusLogger(logrus.NewEntry(logrus.StandardLogger()))

func init() {
	// Install the Calico formatter and direct logs to stdout. This is the
	// state any caller sees when they import the package; Configure() can
	// replace it.
	stateMu.Lock()
	defer stateMu.Unlock()
	currentFormatter = newFormatter("")
	logrus.SetFormatter(currentFormatter)
	logrus.SetOutput(os.Stdout)
	// We do our own caller walking in the formatter so logrus's own
	// detection is not needed.
	logrus.SetReportCaller(false)
}

// SetComponent sets the component prefix used in log output (e.g. "felix").
// Safe to call any time; the most recent value wins. Replaces the formatter
// with one carrying the new component.
func SetComponent(name string) {
	stateMu.Lock()
	defer stateMu.Unlock()
	if name == currentComponent {
		return
	}
	currentComponent = name
	currentFormatter = newFormatter(name)
	logrus.SetFormatter(currentFormatter)
}

// SetLevel sets the global log level. Safe to call any time, including before
// Configure (useful for early-startup adjustments from environment variables).
func SetLevel(level Level) {
	logrus.SetLevel(logrus.Level(level))
}

// SetOutput swaps the destination writer for the default logger. Useful in
// tests and for tools that don't go through Configure. After Configure is
// called, logs are emitted via the background hook to its destinations and
// SetOutput has no effect.
func SetOutput(w io.Writer) {
	logrus.SetOutput(w)
}

// Default returns the default Logger backing the top-level package functions.
// Prefer log.New("component") in code; Default is for cases that genuinely
// need a Logger value without a component.
func Default() Logger {
	return defaultLogger
}

// Top-level convenience functions. Each delegates to defaultLogger so call
// sites can use either `log.Info("msg")` or `log.New("comp").Info("msg")`.

func Trace(args ...any)                   { defaultLogger.Trace(args...) }
func Tracef(format string, args ...any)   { defaultLogger.Tracef(format, args...) }
func Debug(args ...any)                   { defaultLogger.Debug(args...) }
func Debugf(format string, args ...any)   { defaultLogger.Debugf(format, args...) }
func Info(args ...any)                    { defaultLogger.Info(args...) }
func Infof(format string, args ...any)    { defaultLogger.Infof(format, args...) }
func Warn(args ...any)                    { defaultLogger.Warn(args...) }
func Warnf(format string, args ...any)    { defaultLogger.Warnf(format, args...) }
func Warning(args ...any)                 { defaultLogger.Warning(args...) }
func Warningf(format string, args ...any) { defaultLogger.Warningf(format, args...) }
func Error(args ...any)                   { defaultLogger.Error(args...) }
func Errorf(format string, args ...any)   { defaultLogger.Errorf(format, args...) }
func Fatal(args ...any)                   { defaultLogger.Fatal(args...) }
func Fatalf(format string, args ...any)   { defaultLogger.Fatalf(format, args...) }
func Panic(args ...any)                   { defaultLogger.Panic(args...) }
func Panicf(format string, args ...any)   { defaultLogger.Panicf(format, args...) }

// Stdlib-shaped Print* aliases (emit at Info level).
func Print(args ...any)                 { defaultLogger.Print(args...) }
func Printf(format string, args ...any) { defaultLogger.Printf(format, args...) }
func Println(args ...any)               { defaultLogger.Println(args...) }

// logrus-shaped *ln aliases.
func Debugln(args ...any)   { defaultLogger.Debugln(args...) }
func Infoln(args ...any)    { defaultLogger.Infoln(args...) }
func Warnln(args ...any)    { defaultLogger.Warnln(args...) }
func Warningln(args ...any) { defaultLogger.Warningln(args...) }
func Errorln(args ...any)   { defaultLogger.Errorln(args...) }
func Fatalln(args ...any)   { defaultLogger.Fatalln(args...) }
func Panicln(args ...any)   { defaultLogger.Panicln(args...) }

// SetReportCaller is a no-op for compatibility with logrus call sites.
// lib/std/log walks the stack itself in the formatter so logrus's own
// caller detection is unnecessary; we always disable it. Callers that
// previously did `logrus.SetReportCaller(true)` no longer need to.
func SetReportCaller(bool) {}

func WithField(key string, value any) Logger { return defaultLogger.WithField(key, value) }
func WithFields(fields Fields) Logger        { return defaultLogger.WithFields(fields) }
func WithError(err error) Logger             { return defaultLogger.WithError(err) }

// IsLevelEnabled reports whether logs at the given level will be emitted.
func IsLevelEnabled(level Level) bool { return defaultLogger.IsLevelEnabled(level) }

// GetLevel returns the global log level.
func GetLevel() Level { return defaultLogger.Level() }
