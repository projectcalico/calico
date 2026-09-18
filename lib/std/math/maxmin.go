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

// MinInt returns the min value of a or b.
func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MinIntGtZero returns the min of a and b, but ignoring values less than or equal to 0.
// Returns 0 iff both values <= 0.
func MinIntGtZero(a, b int) int {
	var rc int
	if a == 0 {
		rc = b
	} else if b == 0 {
		rc = a
	} else if a < b {
		rc = a
	} else {
		rc = b
	}
	if rc < 0 {
		return 0
	}
	return rc
}

// MaxIntGtZero returns the max of a and b, but ignoring values less than or equal to 0.
// Returns 0 iff both values <= 0.
func MaxIntGtZero(a, b int) int {
	var rc int
	if a == 0 {
		rc = b
	} else if b == 0 {
		rc = a
	} else if a > b {
		rc = a
	} else {
		rc = b
	}
	if rc < 0 {
		return 0
	}
	return rc
}

// MinFloat64GtZero returns the min of a and b, but ignoring values less than or equal to 0.
// Returns 0 iff both values <= 0.
func MinFloat64GtZero(a, b float64) float64 {
	var rc float64
	if a == 0 {
		rc = b
	} else if b == 0 {
		rc = a
	} else if a < b {
		rc = a
	} else {
		rc = b
	}
	if rc < 0 {
		return 0
	}
	return rc
}
