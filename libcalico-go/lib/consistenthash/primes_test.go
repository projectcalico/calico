package consistenthash_test

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/libcalico-go/lib/consistenthash"
)

var _ = DescribeTable("RulesAPIToBackend",
	func(input int, expected int) {
		Expect(consistenthash.NearestPrimeUint16(input)).To(ConsistOf(expected))
	},
	Entry("Negative number should return 2", -1, 2),
	Entry("0 should return 2", 0, 2),
	Entry("Numbers higher than 65521 should return 65521", 65525, 65521),
	Entry("Numbers should get the closest prime (1/2)", 31742, 31741),
	Entry("Numbers shoudl get the closest prime (2/2)", 31740, 31741),
)
