// Copyright (c) 2018-2022 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main_test

import (
	"bytes"
	"encoding/json"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Windows CNI config template tests", func() {
	It("should be valid JSON", func() {
		f, err := os.ReadFile("../../windows-packaging/CalicoWindows/cni.conf.template")
		Expect(err).NotTo(HaveOccurred())

		// Swap out placeholders in the CNI config template for a valid JSON
		// value. These placeholders are replaced when the CNI config is copied
		// from the template.
		f = bytes.Replace(f, []byte("__VNI__"), []byte("0"), -1)
		f = bytes.Replace(f, []byte("__DNS_NAME_SERVERS__"), []byte("0"), -1)
		f = bytes.Replace(f, []byte("__DSR_SUPPORT__"), []byte("0"), -1)

		var data map[string]interface{}
		err = json.Unmarshal(f, &data)
		Expect(err).NotTo(HaveOccurred())
	})
})
