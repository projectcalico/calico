package stringutils_test

import (
	. "github.com/projectcalico/felix/stringutils"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("ParseKeyValueList tests",
	func(input string, expected map[string]string) {
		values, err := ParseKeyValueList(input)
		if expected == nil {
			// An error is expected
			Expect(err).To(Not(BeNil()))
			Expect(values).To(BeNil())
		} else {
			Expect(err).To(BeNil())
			Expect(values).To(Equal(expected))
		}
	},
	Entry("Empty", "   ", map[string]string{}),
	Entry("Single value", "key=value", map[string]string{
		"key": "value",
	}),
	Entry("A faulty entry", "key=value, none", nil),
	Entry("An empty entry", "key=value, none=", nil),
	Entry("Values with spaces", "key=   ,  v2= x ", map[string]string{
		"key": "   ",
		"v2":  " x ",
	}),
	Entry("Value with an equal sign (=)", "key=key = value,v2=7", map[string]string{
		"key": "key = value",
		"v2":  "7",
	}),
	Entry("Empty item, tailing ','", ",  key=value,", map[string]string{
		"key": "value",
	}),
)
