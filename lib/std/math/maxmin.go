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

import "cmp"

// MinGtZero returns the min of a and b, treating values <= 0 as absent.
// Returns 0 iff both values <= 0.
func MinGtZero[T cmp.Ordered](a, b T) T {
	var zero T
	switch {
	case a <= zero && b <= zero:
		return zero
	case a <= zero:
		return b
	case b <= zero:
		return a
	default:
		return min(a, b)
	}
}

// MaxGtZero returns the max of a and b, treating values <= 0 as absent.
// Returns 0 iff both values <= 0.
func MaxGtZero[T cmp.Ordered](a, b T) T {
	var zero T
	switch {
	case a <= zero && b <= zero:
		return zero
	case a <= zero:
		return b
	case b <= zero:
		return a
	default:
		return max(a, b)
	}
}
