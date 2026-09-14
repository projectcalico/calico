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
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/logrusr"
)

// These cover the slog.Handler contract that the old log.Logger interface
// had no equivalent for: groups, group-valued attributes, LogValuer
// resolution and empty-attribute handling.

func TestWithGroupPrefixesKeys(t *testing.T) {
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.WithGroup("http").Info("hit", "code", 200)

	if !strings.Contains(buf.String(), "http.code=200") {
		t.Errorf("expected http.code=200 in: %s", buf.String())
	}
}

func TestWithGroupNests(t *testing.T) {
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.WithGroup("http").WithGroup("request").With("id", "abc").Info("hit")

	if !strings.Contains(buf.String(), "http.request.id=abc") {
		t.Errorf("expected http.request.id=abc in: %s", buf.String())
	}
}

func TestWithGroupDoesNotPrefixEarlierAttrs(t *testing.T) {
	// Attributes attached before a group is opened stay unprefixed —
	// only what follows the WithGroup lands inside it.
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.With("requestID", "abc").WithGroup("http").Info("hit", "code", 200)

	out := buf.String()
	if !strings.Contains(out, "requestID=abc") {
		t.Errorf("pre-group attr should be unprefixed, got: %s", out)
	}
	if !strings.Contains(out, "http.code=200") {
		t.Errorf("post-group attr should be prefixed, got: %s", out)
	}
}

func TestEmptyGroupNameIgnored(t *testing.T) {
	// slog.Handler contract: WithGroup("") is a no-op.
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.WithGroup("").Info("hit", "code", 200)

	if !strings.Contains(buf.String(), "code=200") {
		t.Errorf("empty group name should not prefix, got: %s", buf.String())
	}
}

func TestGroupValuedAttrFlattened(t *testing.T) {
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.Info("hit", slog.Group("http", slog.Int("code", 200), slog.String("method", "GET")))

	out := buf.String()
	if !strings.Contains(out, "http.code=200") || !strings.Contains(out, "http.method=GET") {
		t.Errorf("group attr not flattened: %s", out)
	}
}

func TestGroupValuedAttrWithEmptyKeyInlined(t *testing.T) {
	// slog.Handler contract: a group with an empty key contributes its
	// members directly, with no prefix of its own.
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.Info("hit", slog.Group("", slog.Int("code", 200)))

	if !strings.Contains(buf.String(), "code=200") {
		t.Errorf("empty-keyed group should inline its members: %s", buf.String())
	}
}

func TestEmptyGroupDropped(t *testing.T) {
	// slog.Handler contract: a group with no members is dropped, key and
	// all — it must not surface as an empty field.
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.Info("hit", slog.Group("empty"), slog.Int("code", 200))

	out := buf.String()
	if strings.Contains(out, "empty") {
		t.Errorf("empty group should be dropped entirely: %s", out)
	}
	if !strings.Contains(out, "code=200") {
		t.Errorf("sibling attr lost: %s", out)
	}
}

func TestEmptyAttrDropped(t *testing.T) {
	// slog.Handler contract: an Attr{} with no key and no value is dropped.
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.Info("hit", slog.Attr{}, slog.Int("code", 200))

	out := buf.String()
	if !strings.Contains(out, "code=200") {
		t.Errorf("sibling attr lost: %s", out)
	}
	if strings.Contains(out, "!BADKEY") {
		t.Errorf("empty attr should be dropped, not flagged: %s", out)
	}
}

// resolvable reports a different value than its own String, so a test can
// tell whether the handler called Resolve or just stringified it.
type resolvable struct{}

func (resolvable) LogValue() slog.Value { return slog.StringValue("resolved") }

func TestLogValuerResolved(t *testing.T) {
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.Info("hit", "token", resolvable{})

	if !strings.Contains(buf.String(), "token=resolved") {
		t.Errorf("LogValuer not resolved: %s", buf.String())
	}
}

// captureFormatter records the entry fields a test wants to assert on
// without going through text rendering.
type captureFormatter struct {
	caller string
	line   int
	data   logrus.Fields
}

func (c *captureFormatter) Format(e *logrus.Entry) ([]byte, error) {
	c.data = e.Data
	if e.Caller != nil {
		c.caller = e.Caller.File
		c.line = e.Caller.Line
	}
	return nil, nil
}

func TestCallerResolvesThroughSlog(t *testing.T) {
	// The caller hook walks the stack past logrus, logrusr and log/slog.
	// Without the log/slog entry in that skip list the reported caller is
	// slog's own logger shim instead of the line below.
	base := logrus.New()
	base.SetLevel(logrus.DebugLevel)
	capture := &captureFormatter{}
	base.SetFormatter(capture)
	base.SetOutput(&logrusr.NullWriter{})
	logrusr.InstallCallerHook(base)

	logrusr.New(base).Info("hit")

	if !strings.HasSuffix(capture.caller, "handler_test.go") {
		t.Errorf("caller should be this test file, got %q:%d", capture.caller, capture.line)
	}
}

func TestCallerPCFieldNeverReachesOutput(t *testing.T) {
	// The handler smuggles slog's call-site PC to the caller hook through
	// a private entry field. The hook has to consume it before any
	// formatter runs — including a stock logrus formatter that knows
	// nothing about it.
	l, buf := newAdapter(t, logrus.DebugLevel)
	l.With("requestID", "abc").Info("hit", "code", 200)

	out := buf.String()
	if strings.Contains(out, "caller_pc") || strings.Contains(out, "__") {
		t.Errorf("internal field leaked into output: %s", out)
	}
	if !strings.Contains(out, "code=200") || !strings.Contains(out, "requestID=abc") {
		t.Errorf("real fields lost: %s", out)
	}
}

func TestCallerResolvesWithoutHook(t *testing.T) {
	// GetFileInfo is also reachable without the hook (a formatter running
	// on an entry nothing stamped); it must resolve the same call site.
	base := logrus.New()
	base.SetLevel(logrus.DebugLevel)
	capture := &captureFormatter{}
	base.SetFormatter(capture)
	base.SetOutput(&logrusr.NullWriter{})

	l := logrusr.New(base)
	base.Hooks = make(logrus.LevelHooks) // drop the hook New installed
	l.Info("hit")

	file, line := logrusr.GetFileInfo(&logrus.Entry{Data: capture.data})
	if !strings.HasSuffix(file, "handler_test.go") || line == 0 {
		t.Errorf("caller should be this test file, got %q:%d", file, line)
	}
}

func TestZeroPCFallsBackToStackWalk(t *testing.T) {
	// A Record built without a PC (slog's own methods always set one, but
	// a wrapping handler may not) has no call site to carry, so caller
	// attribution falls back to walking the stack past logrus, logrusr
	// and log/slog. Without log/slog in that skip list this reports
	// slog's internals instead of a real frame.
	base := logrus.New()
	base.SetLevel(logrus.DebugLevel)
	capture := &captureFormatter{}
	base.SetFormatter(capture)
	base.SetOutput(&logrusr.NullWriter{})

	h := logrusr.New(base).Handler()
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "hit", 0)
	if err := h.Handle(context.Background(), rec); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if strings.Contains(capture.caller, "slog") || capture.caller == logrusr.FileNameUnknown {
		t.Errorf("fallback should skip slog frames, got %q:%d", capture.caller, capture.line)
	}
}
