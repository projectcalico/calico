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

package log_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	log "github.com/projectcalico/calico/lib/std/log"
)

// captureOutput swaps the package output to a bytes.Buffer for the duration
// of the test and returns a function to read what was logged. Tests live in
// package log_test so that caller detection correctly treats this file as
// user code.
func captureOutput(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	log.SetLevel(log.DebugLevel)
	log.SetComponent("")
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetOutput(io.Discard)
		log.SetOutput(os.Stdout)
	})
	return func() string { return buf.String() }
}

func TestFormatterMatchesLegacyShape(t *testing.T) {
	read := captureOutput(t)
	log.Info("hello")
	out := read()
	re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \[INFO\]\[\d+\] log_test\.go \d+: hello\n$`)
	if !re.MatchString(out) {
		t.Fatalf("log line did not match expected format:\nout: %q\nre:  %s", out, re.String())
	}
}

func TestWithFieldEmitsSortedKVs(t *testing.T) {
	read := captureOutput(t)
	log.WithFields(log.Fields{"b": 2, "a": "one", "c": errors.New("boom")}).Info("msg")
	out := read()
	if !strings.Contains(out, ` a="one" b=2 c=boom`) {
		t.Fatalf("fields not in sorted order or wrong rendering: %q", out)
	}
}

func TestNewComponentPrefixesFilename(t *testing.T) {
	read := captureOutput(t)
	log.New("calc").Info("hi")
	out := read()
	if !strings.Contains(out, " calc/log_test.go ") {
		t.Fatalf("expected component prefix on file name, got: %q", out)
	}
}

func TestCallerSkipsWrapper(t *testing.T) {
	read := captureOutput(t)
	log.New("test-comp").WithField("k", "v").Info("through wrapper")
	out := read()
	if strings.Contains(out, "impl_logrus.go") || strings.Contains(out, "default.go") {
		t.Fatalf("formatter reported wrapper as caller: %q", out)
	}
	if !strings.Contains(out, "log_test.go") {
		t.Fatalf("formatter did not report user file as caller: %q", out)
	}
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want log.Level
	}{
		{"panic", log.PanicLevel},
		{"fatal", log.FatalLevel},
		{"error", log.ErrorLevel},
		{"warn", log.WarnLevel},
		{"warning", log.WarnLevel},
		{"info", log.InfoLevel},
		{"debug", log.DebugLevel},
		{"trace", log.TraceLevel},
		{"INFO", log.InfoLevel},
	}
	for _, c := range cases {
		got, err := log.ParseLevel(c.in)
		if err != nil {
			t.Errorf("ParseLevel(%q) errored: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseLevel(%q) = %d, want %d", c.in, got, c.want)
		}
	}
	if _, err := log.ParseLevel("nope"); err == nil {
		t.Errorf("ParseLevel('nope') should have errored")
	}
}

func TestRateLimitedLoggerThrottles(t *testing.T) {
	read := captureOutput(t)
	rl := log.NewRateLimitedLogger(log.WithInterval(time.Hour))
	rl.Info("first")
	rl.Info("second")
	rl.Info("third")
	out := read()
	if strings.Count(out, "first") != 1 {
		t.Errorf("first log should have emitted once:\n%s", out)
	}
	if strings.Contains(out, "second") || strings.Contains(out, "third") {
		t.Errorf("throttled logs should not have emitted:\n%s", out)
	}
}

func TestRateLimitedLoggerForceBypasses(t *testing.T) {
	read := captureOutput(t)
	rl := log.NewRateLimitedLogger(log.WithInterval(time.Hour))
	rl.Info("first")
	rl.Info("throttled")
	log.Force(rl).Info("forced")
	out := read()
	if !strings.Contains(out, "first") || !strings.Contains(out, "forced") {
		t.Fatalf("first and forced should both appear:\n%s", out)
	}
	if strings.Contains(out, "throttled") {
		t.Fatalf("throttled message should not appear:\n%s", out)
	}
}

func TestIsSensitiveParam(t *testing.T) {
	for _, name := range []string{"Password", "API_TOKEN", "etcdKey", "AuthSecret", "kubeconfig"} {
		if !log.IsSensitiveParam(name) {
			t.Errorf("IsSensitiveParam(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"CertFile", "EtcdKeyFile", "KubeconfigPath", "Endpoints", "LogLevel"} {
		if log.IsSensitiveParam(name) {
			t.Errorf("IsSensitiveParam(%q) = true, want false", name)
		}
	}
}

func TestRedactURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://user:secret@host.example/path", "https://user:xxxxx@host.example/path"},
		{"https://host.example/path?token=abcdef", "https://host.example/path"},
		{"https://host.example/p#frag", "https://host.example/p"},
	}
	for _, c := range cases {
		if got := log.RedactURL(c.in); got != c.want {
			t.Errorf("RedactURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
