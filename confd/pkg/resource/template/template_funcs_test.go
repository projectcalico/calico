package template

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Template", func() {
	Describe("validate hashToIPv4 method,", func() {
		It("should get valid multicast ip address", func() {
			expectedRouterId := "207.94.5.27"
			nodeName := "Testrobin123"
			actualRouterId := hashToIPv4(nodeName)
			Expect(expectedRouterId).To(Equal(actualRouterId))
		})
		It("should get valid ip address", func() {
			expectedRouterId := "109.174.215.226"
			nodeName := "nodeTest"
			actualRouterId := hashToIPv4(nodeName)
			Expect(expectedRouterId).To(Equal(actualRouterId))
		})
	})
})
