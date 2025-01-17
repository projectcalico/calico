// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.

package counter

import (
	. "github.com/onsi/ginkgo"
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
