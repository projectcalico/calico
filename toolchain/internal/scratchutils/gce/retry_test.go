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

package gce

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/googleapi"
)

func TestIsTransient(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"http2 connection lost", fmt.Errorf("Post ...: %w", errors.New("http2: client connection lost")), true},
		{"connection reset", errors.New("read tcp: connection reset by peer"), true},
		{"googleapi 503", &googleapi.Error{Code: 503}, true},
		{"googleapi 429", &googleapi.Error{Code: 429}, true},
		{"googleapi 404 (permanent)", &googleapi.Error{Code: 404}, false},
		{"net timeout", timeoutErr{}, true},
		{"plain permanent", errors.New("instance not found"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransient(tc.err); got != tc.want {
				t.Fatalf("isTransient(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRetry(t *testing.T) {
	orig := retryBackoff
	retryBackoff = time.Millisecond
	defer func() { retryBackoff = orig }()

	transient := errors.New("http2: client connection lost")

	t.Run("succeeds immediately", func(t *testing.T) {
		calls := 0
		err := retry(context.Background(), "op", func() error { calls++; return nil })
		if err != nil || calls != 1 {
			t.Fatalf("err=%v calls=%d, want nil/1", err, calls)
		}
	})

	t.Run("permanent error returns at once", func(t *testing.T) {
		calls := 0
		permanent := errors.New("not found")
		err := retry(context.Background(), "op", func() error { calls++; return permanent })
		if !errors.Is(err, permanent) || calls != 1 {
			t.Fatalf("err=%v calls=%d, want permanent/1", err, calls)
		}
	})

	t.Run("transient then success", func(t *testing.T) {
		calls := 0
		err := retry(context.Background(), "op", func() error {
			calls++
			if calls < 3 {
				return transient
			}
			return nil
		})
		if err != nil || calls != 3 {
			t.Fatalf("err=%v calls=%d, want nil/3", err, calls)
		}
	})

	t.Run("gives up after all attempts", func(t *testing.T) {
		calls := 0
		err := retry(context.Background(), "op", func() error { calls++; return transient })
		if !errors.Is(err, transient) || calls != 4 {
			t.Fatalf("err=%v calls=%d, want transient/4", err, calls)
		}
	})

	t.Run("honours context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		err := retry(ctx, "op", func() error { calls++; return transient })
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v, want context.Canceled", err)
		}
	})
}

// timeoutErr is a net.Error that reports a timeout, for the isTransient table.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o deadline" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

// The callers pass their whole message as what ("get instance vm-1"), so an error
// returned bare would leave a 404 with nothing identifying the call. This applies
// to the permanent path especially -- that is the common failure.
func TestRetryWrapsEveryErrorWithWhat(t *testing.T) {
	old := retryBackoff
	retryBackoff = time.Millisecond
	defer func() { retryBackoff = old }()

	t.Run("permanent", func(t *testing.T) {
		err := retry(context.Background(), "get instance vm-1", func() error {
			return errors.New("googleapi: Error 404: not found")
		})
		if err == nil || !strings.Contains(err.Error(), "get instance vm-1") {
			t.Fatalf("want the call named, got: %v", err)
		}
	})

	t.Run("exhausted", func(t *testing.T) {
		err := retry(context.Background(), "set metadata on vm-1", func() error {
			return errors.New("http2: client connection lost")
		})
		if err == nil || !strings.Contains(err.Error(), "set metadata on vm-1") {
			t.Fatalf("want the call named, got: %v", err)
		}
	})

	t.Run("context cancelled keeps both the deadline and the last failure", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		err := retry(ctx, "wait op op-9", func() error {
			return errors.New("http2: client connection lost")
		})
		if err == nil {
			t.Fatal("want error")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("errors.Is(DeadlineExceeded) must still hold: %v", err)
		}
		for _, want := range []string{"wait op op-9", "http2: client connection lost"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error should mention %q, got: %v", want, err)
			}
		}
	})
}

// errNotReady exists so a field GCE populates asynchronously (an external IP on a
// freshly created VM) is retried rather than reported as a terminal failure.
func TestErrNotReadyIsTransient(t *testing.T) {
	if !isTransient(errNotReady) {
		t.Error("bare errNotReady must be transient")
	}
	if !isTransient(fmt.Errorf("external IP of vm-1: %w", errNotReady)) {
		t.Error("wrapped errNotReady must be transient")
	}
	if isTransient(errors.New("not ready yet")) {
		t.Error("an unrelated error with the same text must not be transient")
	}
}
