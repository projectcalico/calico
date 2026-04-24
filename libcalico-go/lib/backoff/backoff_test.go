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
}
