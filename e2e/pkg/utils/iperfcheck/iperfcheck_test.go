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

package iperfcheck

import "testing"

// Every attempt falling short still has to report the best of them, or a
// re-measured baseline would tell the caller less than a single sample did.
func TestBestResultKeepsTheHighestSample(t *testing.T) {
	low, high := &Result{AverageRate: 7.3e7}, &Result{AverageRate: 7.9e7}

	if got := bestResult(nil, low); got != low {
		t.Errorf("first sample should be kept, got %v", got)
	}
	if got := bestResult(low, high); got != high {
		t.Errorf("higher sample should replace the incumbent, got %.0f", got.AverageRate)
	}
	if got := bestResult(high, low); got != high {
		t.Errorf("lower sample should not displace the incumbent, got %.0f", got.AverageRate)
	}
}

func TestWithMinRateSetsTheFloor(t *testing.T) {
	cfg := &measureConfig{}
	WithMinRate(8e7)(cfg)
	if cfg.minRate != 8e7 {
		t.Errorf("minRate = %.0f, want 8e7", cfg.minRate)
	}
	// Unset means every completed measurement is an answer, which is what the
	// callers that do not pass a floor rely on.
	if (&measureConfig{}).minRate != 0 {
		t.Error("minRate should default to 0")
	}
}
