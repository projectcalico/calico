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
	"strings"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
)

// testingTBWriter adapts a testing.TB into an io.Writer so log output flows
// into `go test`'s per-test buffer (and shows up only when the test fails
// or runs with -v).
type testingTBWriter struct {
	tb testing.TB
}

func (w testingTBWriter) Write(p []byte) (int, error) {
	w.tb.Helper()
	w.tb.Log(strings.TrimRight(string(p), "\r\n"))
	return len(p), nil
}

var testFormatterOnce sync.Once

// RedirectTo configures the log package to write to the given testing.TB.
// Intended to be called from a test's setup; registers a t.Cleanup() to
// restore the previous output writer when the test ends.
//
// The "test" formatter is installed once per process to avoid clobbering the
// production formatter between tests; the output writer is what gets swapped
// per test.
func RedirectTo(tb testing.TB) {
	testFormatterOnce.Do(func() {
		logrus.SetFormatter(newFormatter("test"))
	})
	old := logrus.StandardLogger().Out
	logrus.SetOutput(testingTBWriter{tb: tb})
	tb.Cleanup(func() {
		logrus.SetOutput(old)
	})
}
