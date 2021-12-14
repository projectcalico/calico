// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
//
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

package hashutils_test

import (
	. "github.com/projectcalico/calico/felix/hashutils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Id", func() {
	It("should return the suffix if short enough", func() {
		Expect(GetLengthLimitedID("felix", "1234", 10)).To(Equal("felix1234"))
	})
	It("should return the suffix if exact length without _ prefix", func() {
		Expect(GetLengthLimitedID("felix", "123456", 11)).To(Equal("felix123456"))
	})
	It("should return the hash if exact length with _ prefix", func() {
		Expect(GetLengthLimitedID("felix", "_2345", 10)).To(Equal("felix_kMQI"))
	})
	It("should return the hash if too long prefix", func() {
		Expect(GetLengthLimitedID("felix", "12345678910", 13)).To(Equal("felix_Y2QCZIS"))
	})
})
