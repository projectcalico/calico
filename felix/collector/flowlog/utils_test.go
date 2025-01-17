// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.

package flowlog

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Flow log util function tests", func() {
	Context("stringToLabels", func() {
		It("generates labels map from flowlog label string", func() {
			By("valid input")
			labelStr := "[name=wl-host1-0-idx1]" // as read from cloudwatch
			labelMap := stringToLabels(labelStr)
			Expect(labelMap["name"]).Should(Equal("wl-host1-0-idx1"))

			By("multiple keys in multiple input")
			labelStr = "[host-endpoint=true,name=host2-eth0]" // as read from cloudwatch
			labelMap = stringToLabels(labelStr)
			Expect(labelMap["host-endpoint"]).Should(Equal("true"))
			Expect(labelMap["name"]).Should(Equal("host2-eth0"))

			By("empty label string")
			labelStr = "[]" // as read from cloudwatch
			labelMap = stringToLabels(labelStr)
			Expect(len(labelMap)).Should(Equal(0))

			By("non-included label string")
			labelStr = "-" // as read from cloudwatch
			labelMap = stringToLabels(labelStr)
			Expect(labelMap).To(BeNil())
		})
	})

	Context("labelsToString", func() {
		It("generates labels map from flowlog label string", func() {
			By("valid input")
			labelMap := map[string]string{"name": "wl-host1-0-idx1"}
			labelStr := labelsToString(labelMap)
			Expect(labelStr).Should(Equal("[name=wl-host1-0-idx1]"))

			By("empty label map")
			labelMap = map[string]string{}
			labelStr = labelsToString(labelMap)
			Expect(labelStr).Should(Equal("[]"))

			By("non-included label")
			labelMap = nil
			labelStr = labelsToString(labelMap)
			Expect(labelStr).Should(Equal("-"))
		})
	})
})
