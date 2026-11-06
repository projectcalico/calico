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
	"math"
	"math/big"
	"testing"
)

func TestRatio(t *testing.T) {
	tests := []struct {
		name  string
		used  *big.Int
		total *big.Int
		want  float64
	}{
		{"half", big.NewInt(50), big.NewInt(100), 0.5},
		{"full", big.NewInt(100), big.NewInt(100), 1.0},
		{"empty", big.NewInt(0), big.NewInt(100), 0.0},
		{"nil used", nil, big.NewInt(100), 0.0},
		{"nil total", big.NewInt(50), nil, 0.0},
		{"both nil", nil, nil, 0.0},
		{"zero total", big.NewInt(50), big.NewInt(0), 0.0},
		{"negative total", big.NewInt(50), big.NewInt(-1), 0.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Ratio(tt.used, tt.total); got != tt.want {
				t.Errorf("Ratio() = %f, want %f", got, tt.want)
			}
		})
	}
}

func TestRatioOf(t *testing.T) {
	if got := RatioOf(25, big.NewInt(100)); got != 0.25 {
		t.Errorf("RatioOf(25, 100) = %f, want 0.25", got)
	}
}

func TestClampToInt(t *testing.T) {
	tests := []struct {
		name string
		n    *big.Int
		want int
	}{
		{"nil", nil, 0},
		{"zero", big.NewInt(0), 0},
		{"positive", big.NewInt(42), 42},
		{"negative", big.NewInt(-42), -42},
		{"max int", big.NewInt(math.MaxInt64), math.MaxInt},
		{"overflow", new(big.Int).Add(big.NewInt(math.MaxInt64), big.NewInt(1)), math.MaxInt},
		{"min int", big.NewInt(math.MinInt64), math.MinInt},
		{"underflow", new(big.Int).Sub(big.NewInt(math.MinInt64), big.NewInt(1)), math.MinInt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClampToInt(tt.n); got != tt.want {
				t.Errorf("ClampToInt() = %d, want %d", got, tt.want)
			}
		})
	}
}
