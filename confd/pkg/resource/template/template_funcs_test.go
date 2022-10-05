package template

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Template", func() {
	Describe("to validate hashToIPv4 method,", func() {
		It("It should validate router_id from the invalid range", func() {
			expectedRouterId := "207.94.5.27"
			nodeName := "Testrobin123"
			actualRouterId := hashToIPv4(nodeName) //invalid router_id 239.94.5.27
			Expect(expectedRouterId).To(Equal(actualRouterId))
		})
		It("It should validate router_id from the valid range", func() {
			expectedRouterId := "109.174.215.226"
			nodeName := "nodeTest"
			actualRouterId := hashToIPv4(nodeName)
			Expect(expectedRouterId).To(Equal(actualRouterId))
		})
	})
})
