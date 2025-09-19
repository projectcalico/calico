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
	"os"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
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

// unit test for MTUFromFile
var _ = Describe("MTUFromFile", func() {
	It("should return the correct MTU value from a valid file", func() {
		// Create a temporary file with a valid MTU value
		file, err := os.CreateTemp("", "mtu_test")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = os.Remove(file.Name()) }()

		_, err = file.WriteString("1500")
		Expect(err).NotTo(HaveOccurred())
		_ = file.Close()

		// Call the function and check the result
		mtu, err := utils.MTUFromFile(file.Name(), types.NetConf{})
		Expect(err).NotTo(HaveOccurred())
		Expect(mtu).To(Equal(1500))
	})

	Context("Error when reading the MTU file", func() {
		It("should not return an error for a non-existent file", func() {
			_, err := utils.MTUFromFile("/non/existent/file", types.NetConf{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error for a non-existent file when RequireMTUFile is true", func() {
			_, err := utils.MTUFromFile("/non/existent/file", types.NetConf{RequireMTUFile: true})
			Expect(err).To(HaveOccurred())
		})

		It("should return an error if reading the file fails with error other than file not found", func() {
			// Create a temporary file with invalid permissions
			file, err := os.CreateTemp("", "mtu_test")
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = os.Remove(file.Name()) }()

			err = os.Chmod(file.Name(), 0o000) // Remove all permissions
			Expect(err).NotTo(HaveOccurred())
			_ = file.Close()

			// Call the function and check the result
			_, err = utils.MTUFromFile(file.Name(), types.NetConf{})
			Expect(err).To(HaveOccurred())
		})
	})
})
