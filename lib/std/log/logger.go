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

// Package log defines an slog-shaped Logger interface that callers depend
// on instead of taking a direct dependency on a concrete logging backend.
// A backend (e.g. lib/logrus) is registered at process start via
// SetDefaultLogger; until then, package-level calls drop on the floor
// via the no-op default.
package log

import (
	"context"
	"log/slog"
)

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

// Attr is a structured key/value pair, compatible with slog.Attr. Use it
// when you want typed attributes; otherwise pass key/value pairs to With
// / Info / ... directly.
type Attr = slog.Attr

var defaultLogger Logger

func init() {
	defaultLogger = &noOpLogger{}
}

// Logger is the slog-shaped logging interface. Variadic args follow slog's
// convention: alternating string keys and values, with Attr permitted as
// a single arg. Implementations should treat odd dangling args / non-string
// keys as slog does (filed under "!BADKEY").
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)

	// With returns a derived Logger that carries the given attributes on
	// every emitted line. The parent is not mutated.
	With(args ...any) Logger

	// Enabled reports whether a log line at the given level would be
	// emitted by this Logger. Callers use it to skip expensive argument
	// preparation for log lines that would be dropped.
	Enabled(ctx context.Context, level Level) bool
}

type noOpLogger struct{}

func (n *noOpLogger) Debug(msg string, args ...any) {
	return
}

func (n *noOpLogger) Info(msg string, args ...any) {
	return
}

func (n *noOpLogger) Warn(msg string, args ...any) {
	return
}

func (n *noOpLogger) Error(msg string, args ...any) {
	return
}

func (n *noOpLogger) With(args ...any) Logger {
	return n
}

func (n *noOpLogger) Enabled(ctx context.Context, level Level) bool {
	return false
}

func SetDefaultLogger(log Logger) {
	defaultLogger = log
}

func Info(msg string, args ...any) {
	defaultLogger.Info(msg, args...)
}
func Warn(msg string, args ...any) {
	defaultLogger.Warn(msg, args...)
}
func Error(msg string, args ...any) {
	defaultLogger.Error(msg, args...)
}

func With(args ...any) Logger {
	return defaultLogger.With(args...)
}

func Enabled(ctx context.Context, level Level) bool {
	return defaultLogger.Enabled(ctx, level)
}
