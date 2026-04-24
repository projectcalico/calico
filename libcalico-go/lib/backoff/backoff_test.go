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

package backoff_test

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/backoff"
)

func TestExpBackoff(t *testing.T) {
	t.Run("starts at initial then doubles up to max", func(t *testing.T) {
		b := &backoff.Exp{Initial: 5 * time.Second, Max: 30 * time.Second}
		require.Equal(t, 5*time.Second, b.Next())
		require.Equal(t, 10*time.Second, b.Next())
		require.Equal(t, 20*time.Second, b.Next())
		require.Equal(t, 30*time.Second, b.Next())
		require.Equal(t, 30*time.Second, b.Next(), "saturates at max")
	})

	t.Run("Reset returns generator to initial state", func(t *testing.T) {
		b := &backoff.Exp{Initial: 100 * time.Millisecond, Max: 1 * time.Second}
		for range 5 {
			b.Next()
		}
		require.Equal(t, 1*time.Second, b.Next(), "saturated at max before reset")
		b.Reset()
		require.Equal(t, 100*time.Millisecond, b.Next(), "returns to initial after Reset")
		require.Equal(t, 200*time.Millisecond, b.Next(), "continues doubling")
	})

	t.Run("clamps initial to max when misconfigured", func(t *testing.T) {
		b := &backoff.Exp{Initial: 1 * time.Hour, Max: 5 * time.Second}
		require.Equal(t, 5*time.Second, b.Next(), "initial > max clamps on first call")
		require.Equal(t, 5*time.Second, b.Next(), "stays at max")
	})

	t.Run("saturating multiply does not overflow near int64 limit", func(t *testing.T) {
		// With a huge Max, the current value could overflow int64 if we doubled
		// before the cap check. The saturate-double guard prevents that.
		huge := time.Duration(math.MaxInt64 / 4)
		b := &backoff.Exp{Initial: huge, Max: time.Duration(math.MaxInt64)}
		for range 100 {
			d := b.Next()
			require.Greater(t, d, time.Duration(0), "delay must stay positive (no overflow)")
		}
	})

	t.Run("Initial equal to Max never grows", func(t *testing.T) {
		b := &backoff.Exp{Initial: 5 * time.Second, Max: 5 * time.Second}
		for i := range 10 {
			require.Equal(t, 5*time.Second, b.Next(), "call %d should return Max", i)
		}
	})

	t.Run("Reset before any Next is a safe no-op", func(t *testing.T) {
		b := &backoff.Exp{Initial: 1 * time.Second, Max: 10 * time.Second}
		require.NotPanics(t, b.Reset)
		require.Equal(t, 1*time.Second, b.Next(), "Next() after Reset returns Initial")
	})

	t.Run("produces a deterministic sequence", func(t *testing.T) {
		b := &backoff.Exp{Initial: 5 * time.Second, Max: 30 * time.Second}
		want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
		got := make([]time.Duration, 0, len(want))
		for range len(want) {
			got = append(got, b.Next())
		}
		require.Equal(t, want, got)
	})

	t.Run("Next panics on zero or negative Initial", func(t *testing.T) {
		require.PanicsWithValue(t, "backoff.Exp: Initial must be positive", func() {
			(&backoff.Exp{Initial: 0, Max: time.Second}).Next()
		})
		require.PanicsWithValue(t, "backoff.Exp: Initial must be positive", func() {
			(&backoff.Exp{Initial: -1 * time.Second, Max: time.Second}).Next()
		})
	})

	t.Run("Next panics on zero or negative Max", func(t *testing.T) {
		require.PanicsWithValue(t, "backoff.Exp: Max must be positive", func() {
			(&backoff.Exp{Initial: time.Second, Max: 0}).Next()
		})
		require.PanicsWithValue(t, "backoff.Exp: Max must be positive", func() {
			(&backoff.Exp{Initial: time.Second, Max: -1 * time.Second}).Next()
		})
	})
}

func TestNew(t *testing.T) {
	t.Run("returns a usable Exp", func(t *testing.T) {
		b := backoff.New(5*time.Second, 30*time.Second)
		require.Equal(t, 5*time.Second, b.Next())
		require.Equal(t, 10*time.Second, b.Next())
	})

	t.Run("panics on zero or negative initial", func(t *testing.T) {
		require.PanicsWithValue(t, "backoff.New: initial must be positive", func() {
			backoff.New(0, time.Second)
		})
		require.PanicsWithValue(t, "backoff.New: initial must be positive", func() {
			backoff.New(-1*time.Second, time.Second)
		})
	})

	t.Run("panics on zero or negative max", func(t *testing.T) {
		require.PanicsWithValue(t, "backoff.New: max must be positive", func() {
			backoff.New(time.Second, 0)
		})
		require.PanicsWithValue(t, "backoff.New: max must be positive", func() {
			backoff.New(time.Second, -1*time.Second)
		})
	})
}
