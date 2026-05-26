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

// Package log is the Calico standard logging package. Callers depend only on
// the Logger interface defined here; the concrete implementation (currently
// logrus) is hidden.
//
// See DESIGN.md for the package contract, configuration model, and migration plan.
package log

import (
	"fmt"
	"strings"
)

// Logger is the primary interface for emitting log lines.
type Logger interface {
	Trace(args ...any)
	Tracef(format string, args ...any)
	Debug(args ...any)
	Debugf(format string, args ...any)
	Info(args ...any)
	Infof(format string, args ...any)
	Warn(args ...any)
	Warnf(format string, args ...any)
	// Warning is an alias of Warn for API compatibility with logrus call sites.
	Warning(args ...any)
	// Warningf is an alias of Warnf for API compatibility with logrus call sites.
	Warningf(format string, args ...any)
	Error(args ...any)
	Errorf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Panic(args ...any)
	Panicf(format string, args ...any)

	// Print/Printf/Println emit at Info level (stdlib-shaped API).
	Print(args ...any)
	Printf(format string, args ...any)
	Println(args ...any)

	// *ln variants match logrus's Println-style helpers.
	Debugln(args ...any)
	Infoln(args ...any)
	Warnln(args ...any)
	Warningln(args ...any)
	Errorln(args ...any)
	Fatalln(args ...any)
	Panicln(args ...any)

	// WithField returns a new Logger with the given field attached.
	WithField(key string, value any) Logger
	// WithFields returns a new Logger with the given fields attached.
	WithFields(fields Fields) Logger
	// WithError returns a new Logger with the error attached under a standard key.
	WithError(err error) Logger

	// Level returns the lowest severity this logger will emit.
	Level() Level
	// IsLevelEnabled reports whether logs at the given level will be emitted.
	IsLevelEnabled(level Level) bool
}

// Fields is a set of key/value pairs attached to a log line.
type Fields = map[string]any

// Level is a log severity level. Values intentionally match logrus.Level ordering
// so the internal implementation can cast between them; callers must not rely
// on that fact.
type Level uint32

const (
	PanicLevel Level = iota
	FatalLevel
	ErrorLevel
	WarnLevel
	InfoLevel
	DebugLevel
	TraceLevel
)

// String returns the lowercase name of the level.
func (l Level) String() string {
	switch l {
	case PanicLevel:
		return "panic"
	case FatalLevel:
		return "fatal"
	case ErrorLevel:
		return "error"
	case WarnLevel:
		return "warning"
	case InfoLevel:
		return "info"
	case DebugLevel:
		return "debug"
	case TraceLevel:
		return "trace"
	}
	return "unknown"
}

// ParseLevel parses a string into a Level. Accepts the same names used by logrus
// ("panic", "fatal", "error", "warn"/"warning", "info", "debug", "trace").
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(s) {
	case "panic":
		return PanicLevel, nil
	case "fatal":
		return FatalLevel, nil
	case "error":
		return ErrorLevel, nil
	case "warn", "warning":
		return WarnLevel, nil
	case "info":
		return InfoLevel, nil
	case "debug":
		return DebugLevel, nil
	case "trace":
		return TraceLevel, nil
	}
	return 0, fmt.Errorf("not a valid log level: %q", s)
}

// SafeParseLevel parses s as a Level. On parse failure it returns PanicLevel
// and logs a warning. Mirrors libcalico-go's SafeParseLogLevel for migration
// compatibility.
func SafeParseLevel(s string) Level {
	if s == "" {
		return PanicLevel
	}
	level, err := ParseLevel(s)
	if err != nil {
		WithField("level", s).Warn("Invalid log level, defaulting to panic")
		return PanicLevel
	}
	return level
}
