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

package flowlog

import (
	. "github.com/onsi/ginkgo/v2"
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
