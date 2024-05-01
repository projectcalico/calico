// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
