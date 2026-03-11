// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package syncclientutils_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/typha/pkg/syncclientutils"
)

var _ = Describe("Test TyphaConfig", func() {

	BeforeEach(func() {
		err := os.Setenv("FELIX_TYPHACAFILE", "cafile")
		Expect(err).NotTo(HaveOccurred())
		err = os.Setenv("FELIX_TYPHAREADTIMEOUT", "100")
		Expect(err).NotTo(HaveOccurred())

	})

	It("should be able to read all types", func() {
		typhaConfig := syncclientutils.ReadTyphaConfig([]string{"FELIX_"})
		Expect(typhaConfig.CAFile).To(Equal("cafile"))
		Expect(typhaConfig.ReadTimeout.Seconds()).To(Equal(100.))
	})
})
