package utils_test

import (
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
)

var _ = Describe("utils", func() {
	table.DescribeTable("Mesos Labels", func(raw, sanitized string) {
		result := utils.SanitizeMesosLabel(raw)
		Expect(result).To(Equal(sanitized))
	},
		table.Entry("valid", "k", "k"),
		table.Entry("dashes", "-my-val", "my-val"),
		table.Entry("double periods", "$my..val", "my.val"),
		table.Entry("special chars", "m$y.val", "m-y.val"),
		table.Entry("slashes", "//my/val/", "my.val"),
		table.Entry("mix of special chars",
			"some_val-with.lots*of^weird#characters", "some_val-with.lots-of-weird-characters"),
	)
})
