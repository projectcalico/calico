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

// variantImageList stands in for the list a variant registers at boot, so these specs
// cover the registry without this repo shipping another variant's components.
var variantImageList = []Component{
	{Image: ImageKeyNode, Version: "v9.9.9", variant: calicoVariant},
}

var _ = Describe("ImageFor", func() {
	// The component list is the source of truth, so a key that stops naming an entry in
	// it would make ImageFor error at render time.
	It("names an entry in the component list", func() {
		for _, key := range ImageKeys {
			_, ok := byImage(CalicoImages)[key]
			Expect(ok).To(BeTrue(), "Calico image for %q", key)
		}
	})

	It("resolves the images this build ships when no variant registered", func() {
		img, err := ImageFor(ImageKeyNode)
		Expect(err).NotTo(HaveOccurred())
		Expect(img).To(Equal(ComponentCalicoNode))
	})

	It("resolves what the variant registered", func() {
		DeferCleanup(UseImages(variantImageList))

		img, err := ImageFor(ImageKeyNode)
		Expect(err).NotTo(HaveOccurred())
		Expect(img).To(Equal(variantImageList[0]))
	})

	It("errors on an image the running variant does not supply", func() {
		DeferCleanup(UseImages(variantImageList))

		_, err := ImageFor("whisker")
		Expect(err).To(HaveOccurred())
	})
})
