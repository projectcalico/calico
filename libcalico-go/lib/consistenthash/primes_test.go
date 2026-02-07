package consistenthash_test

import (
	. "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/consistenthash"
)

var _ = DescribeTable("RulesAPIToBackend",
	func(input int, expected int) {
		gomega.Expect(consistenthash.NextPrimeUint16(input)).To(gomega.BeEquivalentTo(expected))
	},
	Entry("Negative number should return 2", -1, 2),
	Entry("0 should return 2", 0, 2),
	Entry("Numbers should get the closest prime (1/2)", 31742, 31751),
	Entry("Numbers should get the closest prime (2/2)", 31740, 31741),
)
