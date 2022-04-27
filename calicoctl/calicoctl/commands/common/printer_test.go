package common

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var nilSlice []int
var nilMap map[string]string

var _ = DescribeTable("Testing joinAndTruncate",
	func(items interface{}, separator string, maxLength int, expected string) {
		result := joinAndTruncate(items, separator, maxLength)
		Expect(result).To(Equal(expected))
	},
	Entry("nil interface", interface{}(nil), ",", 0, ""),
	Entry("nil map", nilMap, ",", 0, ""),
	Entry("empty map", make(map[string]string), ",", 0, ""),
	Entry("map with one kv", map[string]string{"a": "b"}, ",", 0, "a=b"),
	Entry("map with several kv", map[string]string{"a": "b", "b": "c", "go": "gopher"}, ",", 0, "a=b,b=c,go=gopher"),
	Entry("map with several kv, truncate", map[string]string{"giraffe": "praying mantis", "bird": "felix", "go": "gopher", "elephant": "hippo"}, ",", 15,
		"bird=felix,e..."),
	Entry("map with non string", map[string]int{"a": 1}, ",", 0, "a=1"),
	Entry("map with non string", map[string]int{"a": -1}, ",", 0, "a=-1"),
	Entry("map with non string", map[int]int{123: 1}, ",", 0, "123=1"),
	Entry("map with non string, truncated", map[int]int{123: 4567}, ",", 3, "..."),

	Entry("nil slice", nilSlice, ",", 0, ""),
	Entry("empty slice", []int{}, ",", 0, ""),
	Entry("slice with one value", []int{1}, ",", 0, "1"),
	Entry("slice with multiple value", []string{"one", "two", "three", "four"}, ",", 0, "one,two,three,four"),
	Entry("slice with multiple value different separator", []string{"one", "two", "three", "four"}, "-", 0, "one-two-three-four"),
	Entry("slice with multiple value, truncate", []string{"otorhinolaryngological", "psychophysicotherapeutics", "hepaticocholangiogastrostomy"}, ",", 10,
		"otorhin..."),
	Entry("slice truncate", []int{12345, 67890}, ",", 6, "123..."),
	Entry("slice truncate", []int{1234567}, ",", 6, "123..."),
	Entry("slice no truncate", []int{123456}, ",", 6, "123456"),
	Entry("string", "HelloWorld", ",", 0, "HelloWorld"),
)
