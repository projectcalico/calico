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

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Counter", func() {
	It("should initialize correctly", func() {
		c := New(10000)
		Expect(c.Delta()).To(Equal(10000))
		Expect(c.Absolute()).To(Equal(10000))
	})
	It("should handle delta resets", func() {
		c := New(10000)
		c.ResetDelta()
		Expect(c.Delta()).To(Equal(0))
		Expect(c.Absolute()).To(Equal(10000))
	})
	It("should handle setting to a larger value", func() {
		c := New(10000)
		c.ResetDelta()
		c.Set(11000)
		Expect(c.Delta()).To(Equal(1000))
		Expect(c.Absolute()).To(Equal(11000))
	})
	It("should handle setting to a smaller value", func() {
		c := New(10000)
		c.ResetDelta()
		c.Set(9000)
		// Assumption here is counter has been reset, so best delta and absolute are the new lower value.
		Expect(c.Delta()).To(Equal(9000))
		Expect(c.Absolute()).To(Equal(9000))
	})
	It("should handle a delta increase", func() {
		c := New(10000)
		c.ResetDelta()
		c.Increase(500)
		Expect(c.Delta()).To(Equal(500))
		Expect(c.Absolute()).To(Equal(10500))
	})
	It("should stringify correctly", func() {
		c := New(10000)
		c.ResetDelta()
		c.Increase(500)
		Expect(c.String()).To(Equal("absolute=10500 delta=500"))
	})
})
