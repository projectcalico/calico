package utils_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
)

var _ = Describe("utils", func() {
	DescribeTable("Mesos Labels", func(raw, sanitized string) {
		result := utils.SanitizeMesosLabel(raw)
		Expect(result).To(Equal(sanitized))
	},
		Entry("valid", "k", "k"),
		Entry("dashes", "-my-val", "my-val"),
		Entry("double periods", "$my..val", "my.val"),
		Entry("special chars", "m$y.val", "m-y.val"),
		Entry("slashes", "//my/val/", "my.val"),
		Entry("mix of special chars",
			"some_val-with.lots*of^weird#characters", "some_val-with.lots-of-weird-characters"),
	)
})
