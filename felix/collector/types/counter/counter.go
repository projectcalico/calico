// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

package counter

import "fmt"

// Counter stores the absolute and delta values for an incrementing attribute.
type Counter struct {
	absolute int
	delta    int
}

func New(value int) *Counter {
	return &Counter{value, value}
}

// Value returns the absolute count.
func (c *Counter) Absolute() int {
	return c.absolute
}

// Delta returns the delta count (i.e. the count since the last call to `ResetDeltas()`).
func (c *Counter) Delta() int {
	return c.delta
}

// Set the absolute value, and adjust the delta accordingly.
func (c *Counter) Set(absolute int) bool {
	if c.absolute == absolute {
		return false
	}

	d := absolute - c.absolute
	if d < 0 {
		// There has been a reset event. Best we can do is assume the counters were
		// reset and therefore our delta counts should be incremented by the new
		// values.
		c.delta += absolute
	} else {
		// The counters are higher than before so assuming there has been no intermediate
		// reset event, increment our deltas by the deltas of the new and previous counts.
		c.delta += d
	}
	c.absolute = absolute
	return true
}

// Increase absolute and delta values by supplied delta.
func (c *Counter) Increase(delta int) bool {
	c.delta += delta
	c.absolute += delta
	return delta != 0
}

func (c *Counter) ResetAndSet(absolute int) {
	c.delta = absolute
	c.absolute = absolute
}

// Reset sets the absolute and delta values to zero.
func (c *Counter) Reset() {
	c.delta = 0
	c.absolute = 0
}

// ResetDeltas sets the delta value to zero. Absolute counters are left unchanged.
func (c *Counter) ResetDelta() {
	c.delta = 0
}

func (c *Counter) String() string {
	return fmt.Sprintf("absolute=%v delta=%v", c.absolute, c.delta)
}
