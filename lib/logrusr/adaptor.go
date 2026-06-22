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

// Package logrusr adapts a *logrus.Logger to the lib/std/log.Logger
// interface. The name follows the Go logr-ecosystem convention (zapr,
// klogr, glogr, logrusr) for "<library> adapted to a logger interface".
//
// Variadic args to Debug/Info/Warn/Error and With are parsed as slog-style
// key/value pairs and emitted as logrus fields; a slog.Attr may stand alone.
// A dangling value with no key (or a non-string, non-Attr arg) is filed
// under "!BADKEY", matching slog's convention.
package logrusr

import (
	"context"

	"github.com/sirupsen/logrus"

	log "github.com/projectcalico/calico/lib/std/log"
)

// New returns a log.Logger that emits through the given *logrus.Logger.
// The returned Logger and any loggers derived from it via With share the
// same base — SetLevel / SetOutput on the underlying logrus logger affect
// all of them.
func New(l *logrus.Logger) log.Logger {
	if l == nil {
		panic("logrusr.New: logger is nil")
	}
	return &adapter{base: l, entry: logrus.NewEntry(l)}
}

// adapter implements log.Logger over a *logrus.Entry. With returns a fresh
// adapter holding a derived entry; the original is never mutated.
type adapter struct {
	base  *logrus.Logger
	entry *logrus.Entry
}

func (a *adapter) Debug(msg string, args ...any) { a.emit(logrus.DebugLevel, msg, args) }
func (a *adapter) Info(msg string, args ...any)  { a.emit(logrus.InfoLevel, msg, args) }
func (a *adapter) Warn(msg string, args ...any)  { a.emit(logrus.WarnLevel, msg, args) }
func (a *adapter) Error(msg string, args ...any) { a.emit(logrus.ErrorLevel, msg, args) }

func (a *adapter) With(args ...any) log.Logger {
	if len(args) == 0 {
		return a
	}
	return &adapter{base: a.base, entry: a.entry.WithFields(argsToFields(args))}
}

func (a *adapter) Enabled(_ context.Context, level log.Level) bool {
	return a.base.IsLevelEnabled(slogToLogrusLevel(level))
}

// emit avoids building the fields map for log lines that would be dropped
// by the level filter.
func (a *adapter) emit(level logrus.Level, msg string, args []any) {
	if !a.base.IsLevelEnabled(level) {
		return
	}
	if len(args) == 0 {
		a.entry.Log(level, msg)
		return
	}
	a.entry.WithFields(argsToFields(args)).Log(level, msg)
}

// argsToFields parses slog-style key/value args into logrus.Fields.
func argsToFields(args []any) logrus.Fields {
	fields := make(logrus.Fields, len(args)/2+1)
	for i := 0; i < len(args); {
		switch k := args[i].(type) {
		case string:
			if i+1 < len(args) {
				fields[k] = args[i+1]
				i += 2
			} else {
				fields["!BADKEY"] = k
				i++
			}
		case log.Attr:
			fields[k.Key] = k.Value.Any()
			i++
		default:
			fields["!BADKEY"] = k
			i++
		}
	}
	return fields
}

// slogToLogrusLevel maps an slog.Level to the matching logrus.Level for
// IsLevelEnabled checks. Their numeric encodings don't line up — slog is
// signed (Debug=-4, Info=0, Warn=4, Error=8) and logrus is unsigned with
// the opposite ordering (Error=2, Warn=3, Info=4, Debug=5, Trace=6) — so
// a direct cast would silently produce wrong answers.
//
// slog has no named Trace level; by slog convention, anything finer than
// LevelDebug (e.g. LevelDebug-4) is "trace-ish". For Enabled queries we
// map sub-Debug levels to logrus.TraceLevel so existing logrus-Trace
// gating remains observable through the interface. The Logger interface
// itself does not expose a Trace emit method — to match slog.
func slogToLogrusLevel(level log.Level) logrus.Level {
	switch {
	case level >= log.LevelError:
		return logrus.ErrorLevel
	case level >= log.LevelWarn:
		return logrus.WarnLevel
	case level >= log.LevelInfo:
		return logrus.InfoLevel
	case level >= log.LevelDebug:
		return logrus.DebugLevel
	default:
		return logrus.TraceLevel
	}
}

var _ log.Logger = (*adapter)(nil)
