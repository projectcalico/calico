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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/logrusr"
	log "github.com/projectcalico/calico/lib/std/log"
)

// newAdapter returns an adapter whose underlying logrus logger writes into
// a buffer, with a deterministic key-sorted text formatter so assertions
// about emitted fields are stable.
func newAdapter(t *testing.T, level logrus.Level) (log.Logger, *bytes.Buffer) {
	t.Helper()
	base := logrus.New()
	base.SetLevel(level)
	base.SetFormatter(&logrus.TextFormatter{
		DisableTimestamp: true,
		DisableColors:    true,
		DisableQuote:     true,
	})
	buf := &bytes.Buffer{}
	base.SetOutput(buf)
	return logrusr.New(base), buf
}

func TestStringKeyValuePairs(t *testing.T) {
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.Info("login", "user", "alice", "count", 7)

	out := buf.String()
	for _, want := range []string{"msg=login", "user=alice", "count=7", "level=info"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in: %s", want, out)
		}
	}
}

func TestSlogAttrSupported(t *testing.T) {
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.Info("hit", slog.Int("status", 200), slog.String("route", "/flows"))

	out := buf.String()
	if !strings.Contains(out, "status=200") || !strings.Contains(out, "route=/flows") {
		t.Errorf("slog.Attr fields not emitted: %s", out)
	}
}

func TestDanglingKeyGetsBadKey(t *testing.T) {
	l, buf := newAdapter(t, logrus.DebugLevel)
	// "user" has no following value — slog's convention is to file the
	// dangling key under "!BADKEY".
	l.Info("oops", "user")

	if !strings.Contains(buf.String(), "!BADKEY=user") {
		t.Errorf("expected !BADKEY=user in: %s", buf.String())
	}
}

func TestNonStringKeyGetsBadKey(t *testing.T) {
	l, buf := newAdapter(t, logrus.DebugLevel)
	// First positional arg is an int, not a string or slog.Attr — file
	// under !BADKEY.
	l.Info("oops", 42)

	if !strings.Contains(buf.String(), "!BADKEY=42") {
		t.Errorf("expected !BADKEY=42 in: %s", buf.String())
	}
}

func TestWithCarriesFields(t *testing.T) {
	l, buf := newAdapter(t, logrus.DebugLevel)
	derived := l.With("requestID", "abc-123")
	derived.Info("incoming")

	if !strings.Contains(buf.String(), "requestID=abc-123") {
		t.Errorf("derived logger lost field: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "msg=incoming") {
		t.Errorf("derived logger lost message: %s", buf.String())
	}
}

func TestWithErrorAttribute(t *testing.T) {
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.Error("failed", "error", errors.New("boom"))

	out := buf.String()
	if !strings.Contains(out, "error=boom") {
		t.Errorf("expected error=boom in: %s", out)
	}
	if !strings.Contains(out, "level=error") {
		t.Errorf("expected level=error in: %s", out)
	}
}

func TestEnabledLevelMapping(t *testing.T) {
	// Each case sets the underlying logrus level, then asks the adapter
	// via the lib/std/log interface whether a given slog-level line would
	// be emitted.
	cases := []struct {
		name        string
		logrusLevel logrus.Level
		queryLevel  log.Level
		want        bool
	}{
		// At InfoLevel: info+warn+error enabled, debug disabled.
		{"info-enabled-at-info", logrus.InfoLevel, log.LevelInfo, true},
		{"warn-enabled-at-info", logrus.InfoLevel, log.LevelWarn, true},
		{"error-enabled-at-info", logrus.InfoLevel, log.LevelError, true},
		{"debug-disabled-at-info", logrus.InfoLevel, log.LevelDebug, false},

		// At DebugLevel: debug enabled, trace (sub-Debug) still disabled.
		{"debug-enabled-at-debug", logrus.DebugLevel, log.LevelDebug, true},
		{"trace-disabled-at-debug", logrus.DebugLevel, log.LevelDebug - 4, false},

		// At TraceLevel: sub-Debug levels become observable. This is the
		// behaviour Shaun asked for in PR #12968 — existing logrus-Trace
		// gating remains queryable through the new interface.
		{"trace-enabled-at-trace", logrus.TraceLevel, log.LevelDebug - 4, true},
		{"debug-enabled-at-trace", logrus.TraceLevel, log.LevelDebug, true},

		// At WarnLevel: only warn and error.
		{"info-disabled-at-warn", logrus.WarnLevel, log.LevelInfo, false},
		{"warn-enabled-at-warn", logrus.WarnLevel, log.LevelWarn, true},
		{"error-enabled-at-warn", logrus.WarnLevel, log.LevelError, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, _ := newAdapter(t, c.logrusLevel)
			if got := l.Enabled(context.Background(), c.queryLevel); got != c.want {
				t.Errorf("Enabled(%v) at logrus=%v = %v, want %v", c.queryLevel, c.logrusLevel, got, c.want)
			}
		})
	}
}

func TestLevelFilterDropsLine(t *testing.T) {
	// At WarnLevel, Info lines should be dropped without producing output.
	l, buf := newAdapter(t, logrus.WarnLevel)
	l.Info("should-be-dropped")
	l.Warn("should-appear")

	out := buf.String()
	if strings.Contains(out, "should-be-dropped") {
		t.Errorf("info line emitted when level=warn: %s", out)
	}
	if !strings.Contains(out, "should-appear") {
		t.Errorf("warn line missing: %s", out)
	}
}

func TestNewPanicsOnNil(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("New(nil) should have panicked")
		}
	}()
	logrusr.New(nil)
}
