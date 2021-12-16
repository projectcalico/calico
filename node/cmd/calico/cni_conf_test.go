// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.

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
	"io/ioutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CNI config template tests", func() {
	It("should be valid JSON", func() {
		f, err := ioutil.ReadFile("../../windows-packaging/TigeraCalico/cni.conf.template")
		Expect(err).NotTo(HaveOccurred())

		// __VNI__ is a placeholder for a bare int so we need to swap it for something valid.
		f = bytes.Replace(f, []byte("__VNI__"), []byte("0"), -1)

		var data map[string]interface{}
		err = json.Unmarshal(f, &data)
		Expect(err).NotTo(HaveOccurred())
	})
})
