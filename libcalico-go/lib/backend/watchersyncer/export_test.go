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

package watchersyncer

import "time"

// TestWatcherCache is a small exported wrapper around watcherCache for unit
// tests in the watchersyncer_test package. It avoids exposing internals in the
// main package API while still allowing direct white-box testing of behaviour
// that is awkward to exercise through the full syncer state machine.
type TestWatcherCache struct {
	*watcherCache
}

// NewTestWatcherCache returns a minimally-initialised watcherCache suitable for
// direct method-level testing. The cache is not wired up to a client or result
// channel, so only tests that exercise methods without starting the run loop
// should use this.
func NewTestWatcherCache(r ResourceType) *TestWatcherCache {
	return &TestWatcherCache{watcherCache: newWatcherCache(nil, r, nil, 0)}
}

// SetMissingAPIBackoff directly sets the missing-API backoff for tests.
func (wc *TestWatcherCache) SetMissingAPIBackoff(d time.Duration) {
	wc.missingAPIBackoff = d
}

// MissingAPIBackoff returns the current missing-API backoff for tests.
func (wc *TestWatcherCache) MissingAPIBackoff() time.Duration {
	return wc.missingAPIBackoff
}

// MarkInstalled invokes markInstalled so tests can verify reset semantics.
func (wc *TestWatcherCache) MarkInstalled() {
	wc.markInstalled()
}
