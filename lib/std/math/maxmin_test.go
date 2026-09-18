// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package math

import (
	"testing"
)

func TestMinInt(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{0, 0, 0},
		{-1, 1, -1},
		{5, 5, 5},
	}
	for _, tt := range tests {
		if got := MinInt(tt.a, tt.b); got != tt.want {
			t.Errorf("MinInt(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestMinIntGtZero(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{0, 5, 5},
		{5, 0, 5},
		{0, 0, 0},
		{-1, 5, 0},
		{-1, -2, 0},
		{-1, 0, 0},
	}
	for _, tt := range tests {
		if got := MinIntGtZero(tt.a, tt.b); got != tt.want {
			t.Errorf("MinIntGtZero(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestMaxIntGtZero(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 2},
		{2, 1, 2},
		{0, 5, 5},
		{5, 0, 5},
		{0, 0, 0},
		{-1, 5, 5},
		{-1, -2, 0},
		{-1, 0, 0},
	}
	for _, tt := range tests {
		if got := MaxIntGtZero(tt.a, tt.b); got != tt.want {
			t.Errorf("MaxIntGtZero(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestMinFloat64GtZero(t *testing.T) {
	tests := []struct {
		a, b, want float64
	}{
		{1.0, 2.0, 1.0},
		{2.0, 1.0, 1.0},
		{0, 5.5, 5.5},
		{5.5, 0, 5.5},
		{0, 0, 0},
		{-1.0, 5.0, 0},
		{-1.0, -2.0, 0},
	}
	for _, tt := range tests {
		if got := MinFloat64GtZero(tt.a, tt.b); got != tt.want {
			t.Errorf("MinFloat64GtZero(%f, %f) = %f, want %f", tt.a, tt.b, got, tt.want)
		}
	}
}
