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

package logrusr_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/logrusr"
	log "github.com/projectcalico/calico/lib/std/log"
)

// Benchmarks for the logrus-backed log.Logger. These deliberately use only
// the surface that both the old hand-rolled log.Logger interface and the
// slog.Logger that replaced it share — Debug/Info/With/Enabled — so the
// same file compiles on either side of the slog migration and the two can
// be compared directly with benchstat:
//
//	go test -run XXX -bench 'Adapter|PackageLevel' -benchmem -count 10 ./lib/logrusr/ > new.txt
//	git stash && ... > old.txt && benchstat old.txt new.txt
//
// The CallerHook variants matter most: caller attribution walks the stack
// per line, and routing through slog puts two more frames between the call
// site and the walk.

// newBenchLogger builds a logger writing into a null sink. callerHook
// selects whether the stack-walking caller attribution is installed, which
// production configures via ConfigureFormatter but which roughly doubles
// the cost of a log line.
func newBenchLogger(level logrus.Level, callerHook bool) log.Logger {
	base := logrus.New()
	base.SetLevel(level)
	base.SetFormatter(&logrusr.Formatter{})
	base.SetOutput(&logrusr.NullWriter{})
	if callerHook {
		logrusr.InstallCallerHook(base)
	}
	return logrusr.New(base)
}

func BenchmarkAdapterInfoNoArgs(b *testing.B) {
	l := newBenchLogger(logrus.DebugLevel, false)
	b.ReportAllocs()
	for b.Loop() {
		l.Info("Test log")
	}
}

func BenchmarkAdapterInfoKeyValues(b *testing.B) {
	// The hot path: slog parses these varargs into attributes, then the
	// handler renders them as logrus fields.
	l := newBenchLogger(logrus.DebugLevel, false)
	b.ReportAllocs()
	for b.Loop() {
		l.Info("Test log", "a", "b", "c", "d", "e", "f", "g", "h")
	}
}

func BenchmarkAdapterInfoAttrs(b *testing.B) {
	// Typed attributes skip slog's any-boxing of keys and values.
	l := newBenchLogger(logrus.DebugLevel, false)
	b.ReportAllocs()
	for b.Loop() {
		l.Info("Test log",
			slog.String("a", "b"), slog.String("c", "d"),
			slog.String("e", "f"), slog.String("g", "h"))
	}
}

func BenchmarkAdapterWith(b *testing.B) {
	// Deriving a logger, e.g. once per request in httpmachinery.
	l := newBenchLogger(logrus.DebugLevel, false)
	b.ReportAllocs()
	for b.Loop() {
		_ = l.With("requestID", "abc-123")
	}
}

func BenchmarkAdapterDerivedInfo(b *testing.B) {
	// Emitting from an already-derived logger — the common shape for
	// per-request and per-component loggers.
	l := newBenchLogger(logrus.DebugLevel, false).With("a", "b", "c", "d")
	b.ReportAllocs()
	for b.Loop() {
		l.Info("Test log")
	}
}

func BenchmarkAdapterDisabled(b *testing.B) {
	// A line dropped by the level filter. This should stay close to free:
	// slog.Logger asks the handler's Enabled before building the record,
	// so no attributes are ever materialised.
	l := newBenchLogger(logrus.WarnLevel, false)
	b.ReportAllocs()
	for b.Loop() {
		l.Debug("Test log", "a", "b", "c", "d", "e", "f", "g", "h")
	}
}

func BenchmarkAdapterEnabled(b *testing.B) {
	l := newBenchLogger(logrus.InfoLevel, false)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		_ = l.Enabled(ctx, log.LevelDebug)
	}
}

func BenchmarkAdapterInfoCallerHook(b *testing.B) {
	// Caller attribution walks the stack once per line, skipping logrus,
	// logrusr, log/slog and lib/std/log frames.
	l := newBenchLogger(logrus.DebugLevel, true)
	b.ReportAllocs()
	for b.Loop() {
		l.Info("Test log")
	}
}

func BenchmarkAdapterInfoKeyValuesCallerHook(b *testing.B) {
	l := newBenchLogger(logrus.DebugLevel, true)
	b.ReportAllocs()
	for b.Loop() {
		l.Info("Test log", "a", "b", "c", "d", "e", "f", "g", "h")
	}
}

func BenchmarkPackageLevelInfo(b *testing.B) {
	// Through the lib/std/log package helpers, which add an atomic load of
	// the default logger plus one more frame for the caller walk.
	log.SetDefaultLogger(newBenchLogger(logrus.DebugLevel, true))
	b.Cleanup(func() { log.SetDefaultLogger(nil) })
	b.ReportAllocs()
	for b.Loop() {
		log.Info("Test log", "a", "b", "c", "d")
	}
}
