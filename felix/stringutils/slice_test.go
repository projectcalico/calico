// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package stringutils_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/stringutils"
)

var _ = DescribeTable("Slice tests",
	func(slice []string, val string, contains bool) {
		By("checking FirstIndexInSlice")
		res := FirstIndexInSlice(slice, val)
		if contains {
			Expect(res).NotTo(Equal(-1))
		} else {
			Expect(res).NotTo(Equal(1))
		}

		By("checking InSlice")
		res2 := InSlice(slice, val)
		if contains {
			Expect(res2).To(BeTrue())
		} else {
			Expect(res2).To(BeFalse())
		}

		By("checking RemoveValue")
		res3 := RemoveValue(slice, val)
		if contains {
			Expect(res3).To(HaveLen(len(slice) - 1))
		} else {
			Expect(res3).To(Equal(slice))
		}
	},
	Entry("nil array", []string(nil), "test", false),
	Entry("Empty array", []string{}, "", false),
	Entry("Empty string match", []string{""}, "", true),
	Entry("Empty strings match", []string{"", ""}, "", true),
	Entry("Empty string and another string match", []string{"", "a"}, "a", true),
	Entry("Non empty strings no matches", []string{"a", "b"}, "c", false),
)
