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

// Package logrusr adapts a *logrus.Logger to slog, so callers holding a
// lib/std/log.Logger (an *slog.Logger) emit through logrus. The name
// follows the Go logr-ecosystem convention (zapr, klogr, glogr, logrusr)
// for "<library> adapted to a logger interface".
//
// The adapter is an slog.Handler rather than a Logger: slog.Logger is a
// concrete shim that already parses variadic args into attributes — so
// key/value pairs, stand-alone slog.Attrs and slog's "!BADKEY" handling
// for dangling or non-string keys all come from slog itself, and this
// package only has to render the resulting attributes as logrus fields.
package logrusr

import (
	"context"
	"log/slog"

	"github.com/sirupsen/logrus"

	log "github.com/projectcalico/calico/lib/std/log"
)

// New returns a log.Logger that emits through the given *logrus.Logger.
// The returned Logger and any loggers derived from it via With or
// WithGroup share the same base — SetLevel / SetOutput on the underlying
// logrus logger affect all of them.
func New(l *logrus.Logger) log.Logger {
	if l == nil {
		panic("logrusr.New: logger is nil")
	}
	// The handler passes slog's call-site PC to the caller-stamping hook
	// through a private field, so it has to make sure that hook is there
	// to consume it — otherwise the field would reach the formatter and
	// show up in the output. Installing twice is a no-op.
	InstallCallerHook(l)
	return slog.New(&handler{base: l, entry: logrus.NewEntry(l)})
}

// handler implements slog.Handler over a *logrus.Entry. WithAttrs and
// WithGroup return a fresh handler holding a derived entry; the original
// is never mutated.
//
// base is kept alongside entry so level checks read the live logrus
// logger — a SetLevel after the handler is built is still honoured.
type handler struct {
	base  *logrus.Logger
	entry *logrus.Entry

	// prefix is the dotted concatenation of the groups opened by
	// WithGroup, e.g. "http.request.". logrus fields are flat, so groups
	// are flattened into the key rather than nested.
	prefix string
}

func (h *handler) Enabled(_ context.Context, level log.Level) bool {
	return h.base.IsLevelEnabled(slogToLogrusLevel(level))
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	level := slogToLogrusLevel(r.Level)
	entry := h.entry
	// slog captured the call site in r.PC. Hand it to the caller-stamping
	// hook in this package (see fieldCallerPC) so it can resolve that one
	// frame instead of walking the stack for the first non-logging one.
	// The field is consumed before the entry is rendered.
	if r.NumAttrs() > 0 || r.PC != 0 {
		// Dup once and fill in place. entry.WithFields would build a
		// second map on top of the one Dup already copies, which for a
		// bare message is the bulk of the per-line allocation.
		entry = entry.Dup()
		r.Attrs(func(a slog.Attr) bool {
			addAttr(entry.Data, h.prefix, a)
			return true
		})
		if r.PC != 0 {
			entry.Data[fieldCallerPC] = r.PC
		}
	}
	// We deliberately don't carry r.Time across. logrus stamps the entry
	// itself at emission, which is what every other logrus caller in this
	// repo gets; honouring the record's time would need a second
	// Entry.Dup (and so a second field-map copy) per line, to shave a
	// sub-microsecond skew and leave this one logger's timestamps derived
	// differently from the rest of the stream.
	entry.Log(level, r.Message)
	return nil
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	fields := make(logrus.Fields, len(attrs))
	for _, a := range attrs {
		addAttr(fields, h.prefix, a)
	}
	return &handler{base: h.base, entry: h.entry.WithFields(fields), prefix: h.prefix}
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &handler{base: h.base, entry: h.entry, prefix: h.prefix + name + "."}
}

// addAttr renders one slog.Attr into logrus fields under the given key
// prefix, following the slog.Handler contract: a LogValuer is resolved
// first, an empty Attr is dropped, a group contributes its members under
// "<prefix><group key>." (or under the prefix unchanged if its key is
// empty), and an empty group is dropped along with its key.
func addAttr(fields logrus.Fields, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() != slog.KindGroup {
		fields[prefix+a.Key] = a.Value.Any()
		return
	}
	members := a.Value.Group()
	if len(members) == 0 {
		return
	}
	if a.Key != "" {
		prefix += a.Key + "."
	}
	for _, m := range members {
		addAttr(fields, prefix, m)
	}
}

// slogToLogrusLevel maps an slog.Level to the matching logrus.Level for
// IsLevelEnabled checks and emission. Their numeric encodings don't line
// up — slog is signed (Debug=-4, Info=0, Warn=4, Error=8) and logrus is
// unsigned with the opposite ordering (Error=2, Warn=3, Info=4, Debug=5,
// Trace=6) — so a direct cast would silently produce wrong answers.
//
// slog has no named Trace level; by slog convention, anything finer than
// LevelDebug (e.g. LevelDebug-4) is "trace-ish". We map sub-Debug levels
// to logrus.TraceLevel so existing logrus-Trace gating remains observable
// through slog. slog.Logger itself exposes no Trace emit method.
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

var _ slog.Handler = (*handler)(nil)
