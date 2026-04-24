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

// Package backoff provides small helpers for exponential backoff loops.
//
// Calico historically had several hand-rolled exponential backoff
// implementations in its retry loops. This package consolidates them on a
// single, resettable type so callers can reuse the policy without re-writing
// the doubling/capping logic each time.
package backoff

import "time"

// Exp is a single-goroutine exponential backoff generator. Next() returns the
// next delay: Initial on the first call, then doubling up to Max. Reset()
// returns the generator to its initial state so the same struct can be reused
// across long-lived recovery loops (e.g. a watcher that fails, recovers, and
// later fails again).
//
// Exp is not safe for concurrent use; callers typically own one Exp per retry
// loop. If Initial > Max, the first Next() is clamped to Max. Next() uses
// saturating multiplication so the cap is honored even if Max is set close to
// the time.Duration (int64) limit.
type Exp struct {
	// Initial is the delay returned by the first call to Next() after
	// construction or Reset(). Must be positive.
	Initial time.Duration

	// Max caps the delay. Subsequent calls to Next() saturate at Max.
	Max time.Duration

	current time.Duration
}

// Next returns the next delay and advances internal state.
func (b *Exp) Next() time.Duration {
	if b.current == 0 {
		b.current = b.Initial
		if b.current > b.Max {
			b.current = b.Max
		}
	} else if b.current > b.Max/2 {
		b.current = b.Max
	} else {
		b.current *= 2
	}
	return b.current
}

// Reset clears the internal state so the next call to Next() returns Initial.
func (b *Exp) Reset() {
	b.current = 0
}
