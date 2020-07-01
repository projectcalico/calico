package stringutils_test

import (
	. "github.com/projectcalico/felix/stringutils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("ParseKeyValueList tests",
	func(input string, expectedErr bool, expected map[string]string) {
		values, err := ParseKeyValueList(input)
		By("map")
		Expect(*values).To(Equal(expected))
		By("error")
		Expect(expectedErr).To(Equal(err != nil))
	},
	Entry("Empty", "   ", false, map[string]string{}),
	Entry("Single value", "key=value", false, map[string]string{
		"key": "value",
	}),
	Entry("A faulty entry", "key=value, none", true, map[string]string{
		"key": "value",
	}),
	Entry("An empty entry", "key=value, none=", true, map[string]string{
		"key": "value",
	}),
	Entry("Values with spaces", "key=   ,  v2= x ", false, map[string]string{
		"key": "   ",
		"v2": " x ",
	}),
	Entry("Value with an equal sign (=)", "key=key = value,v2=7", false, map[string]string{
		"key": "key = value",
		"v2": "7",
	}),
)
