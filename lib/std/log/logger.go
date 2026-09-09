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

// Package log re-exports slog's Logger as the logging type callers depend
// on, so no caller takes a direct dependency on a concrete logging
// backend. A backend is plugged in as an slog.Handler — see lib/logrusr
// for the logrus one — and registered at process start via
// SetDefaultLogger; until then, package-level calls drop on the floor via
// the discarding default.
//
// Logger is an alias, not a distinct type, so a *slog.Logger from anywhere
// satisfies it and callers can hand ours to any slog-shaped API.
package log

import (
	"context"
	"log/slog"
	"sync/atomic"
)

// Logger is slog's logger. Variadic args follow slog's convention:
// alternating string keys and values, with Attr permitted as a single
// arg; odd dangling args and non-string keys are filed under "!BADKEY".
//
// Backends implement slog.Handler rather than this type — slog.Logger is
// a concrete shim over Handler, and Handler is the pluggable half.
type Logger = *slog.Logger

// Level is the severity of a log line, re-exported from slog so callers
// don't need to import slog directly.
type Level = slog.Level

// Level constants re-exported from slog.
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Attr is a structured key/value pair, re-exported from slog. Use it when
// you want typed attributes; otherwise pass key/value pairs to With /
// Info / ... directly.
type Attr = slog.Attr

// defaultLogger holds the Logger backing the package-level helpers. It is
// loaded atomically so SetDefaultLogger can swap it under concurrent
// readers — including any log calls that fire from init() scope before
// the backend has finished registering.
var defaultLogger atomic.Pointer[slog.Logger]

func init() {
	defaultLogger.Store(discard())
}

// discard returns a Logger that drops everything. slog.DiscardHandler
// reports Enabled false at every level, so callers gating on Enabled skip
// their argument preparation too.
func discard() Logger {
	return slog.New(slog.DiscardHandler)
}

// SetDefaultLogger installs the Logger that backs the package-level
// helpers (Info, Warn, Error, With, Enabled). Safe to call concurrently
// with logging calls — readers observe either the previous or the new
// Logger, never a torn value. A nil Logger restores the discarding
// default rather than panicking at the first log call.
func SetDefaultLogger(log Logger) {
	if log == nil {
		log = discard()
	}
	defaultLogger.Store(log)
}

// Default returns the Logger backing the package-level helpers.
func Default() Logger {
	return defaultLogger.Load()
}

func Debug(msg string, args ...any) {
	Default().Debug(msg, args...)
}

func Info(msg string, args ...any) {
	Default().Info(msg, args...)
}

func Warn(msg string, args ...any) {
	Default().Warn(msg, args...)
}

func Error(msg string, args ...any) {
	Default().Error(msg, args...)
}

func With(args ...any) Logger {
	return Default().With(args...)
}

func Enabled(ctx context.Context, level Level) bool {
	return Default().Enabled(ctx, level)
}
