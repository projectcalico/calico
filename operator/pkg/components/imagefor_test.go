// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package components

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ImageFor", func() {
	// The generated component lists are the source of truth, so a key that stops naming
	// an entry in either list would make ImageFor error at render time.
	It("names an entry in both lists, resolving to a different image in each", func() {
		for _, key := range ImageKeys {
			cal, calOK := byImage(CalicoImages)[key]
			Expect(calOK).To(BeTrue(), "Calico image for %q", key)

			ent, entOK := byImage(EnterpriseImages)[key]
			Expect(entOK).To(BeTrue(), "Enterprise image for %q", key)

			Expect(cal).NotTo(Equal(ent), "%q is the same image for both variants, so it needs no key", key)
		}
	})

	It("resolves the images this build ships when no variant registered", func() {
		img, err := ImageFor(ImageKeyNode)
		Expect(err).NotTo(HaveOccurred())
		Expect(img).To(Equal(ComponentCalicoNode))
	})

	It("resolves what the variant registered", func() {
		DeferCleanup(UseImages(EnterpriseImages))

		img, err := ImageFor(ImageKeyNode)
		Expect(err).NotTo(HaveOccurred())
		Expect(img).To(Equal(ComponentTigeraNode))
	})

	It("errors on an image the running variant does not supply", func() {
		DeferCleanup(UseImages(EnterpriseImages))

		_, err := ImageFor("whisker")
		Expect(err).To(HaveOccurred())
	})
})
