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
	"time"

	"google.golang.org/api/googleapi"
)

// retryBackoff is the first inter-attempt delay (doubled each retry). A package
// var so tests can shrink it.
var retryBackoff = time.Second

// retry runs fn with exponential backoff on transient errors -- GCE control-plane
// calls occasionally drop the HTTP/2 connection or return a 429/5xx. Permanent
// errors return at once. Every error is wrapped with what, including those, or a
// 404 would arrive with nothing identifying the call.
func retry(ctx context.Context, what string, fn func() error) error {
	const attempts = 4
	backoff := retryBackoff
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if !isTransient(err) {
			return fmt.Errorf("%s: %w", what, err)
		}
		if i == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			// Name the last failure: a bare deadline says nothing about why.
			return fmt.Errorf("%s: %w (last attempt: %v)", what, ctx.Err(), err)
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return fmt.Errorf("%s: giving up after %d attempts: %w", what, attempts, err)
}

// errNotReady marks a condition that simply has not happened yet -- a field GCE
// populates asynchronously. Retrying is the whole point, so it counts as transient.
var errNotReady = errors.New("not ready yet")

// isTransient reports whether err is worth retrying: a rate-limit/server error
// from the API, a network timeout, or one of the transport-level drops that
// surface as a plain error string (the HTTP/2 connection-lost flake among them).
func isTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errNotReady) {
		return true
	}
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		switch gerr.Code {
		case 429, 500, 502, 503, 504:
			return true
		}
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return true
	}
	msg := err.Error()
	for _, m := range []string{
		"http2: client connection lost",
		"connection reset",
		"connection refused",
		"unexpected EOF",
		"i/o timeout",
		"TLS handshake",
		"server closed idle connection",
		"broken pipe",
	} {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}
