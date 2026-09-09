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

	operator "github.com/projectcalico/calico/operator/api/v1"
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

var _ = Describe("RegisterVariant", func() {
	// A variant whose components are declared outside this package cannot name a
	// variant on them, so it supplies the defaults they resolve against instead.
	thing := Component{Image: "thing", Version: "v1.0.0"}

	build := VariantBuild{
		Images:    []Component{thing},
		Release:   "v9.9.9",
		Registry:  "example.com/",
		ImagePath: "myvariant/",
	}

	It("resolves registered images against the registered registry and image path", func() {
		DeferCleanup(UseVariant(build))

		img, err := ImageFor("thing")
		Expect(err).NotTo(HaveOccurred())

		ref, err := GetReference(img, "", "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(ref).To(Equal("example.com/myvariant/thing:v1.0.0"))
	})

	// The image path is also the key an ImageSet lists images under, so a wrong one
	// stops digests resolving rather than just changing the registry.
	It("looks an ImageSet digest up under the registered image path", func() {
		DeferCleanup(UseVariant(build))

		img, err := ImageFor("thing")
		Expect(err).NotTo(HaveOccurred())

		is := &operator.ImageSet{Spec: operator.ImageSetSpec{Images: []operator.Image{
			{Image: "myvariant/thing", Digest: "sha256:cafe"},
		}}}
		ref, err := GetReference(img, "", "", "", is)
		Expect(err).NotTo(HaveOccurred())
		Expect(ref).To(Equal("example.com/myvariant/thing@sha256:cafe"))
	})

	It("lets the installation override the registered defaults", func() {
		DeferCleanup(UseVariant(build))

		img, err := ImageFor("thing")
		Expect(err).NotTo(HaveOccurred())

		ref, err := GetReference(img, "registry.io/", "custom/", "", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(ref).To(Equal("registry.io/custom/thing:v1.0.0"))
	})

	It("reports the registered release, and the Calico one when nothing registered", func() {
		Expect(VariantRelease()).To(Equal(CalicoRelease))

		restore := UseVariant(build)
		DeferCleanup(restore)
		Expect(VariantRelease()).To(Equal("v9.9.9"))

		restore()
		Expect(VariantRelease()).To(Equal(CalicoRelease))
	})

	// Components declared in this package already name a variant, so a build that
	// carries a registry of its own must leave theirs alone.
	It("leaves images that name a variant resolving against that variant", func() {
		DeferCleanup(UseVariant(VariantBuild{
			Images:    []Component{thing, ComponentCalicoNode},
			Registry:  "example.com/",
			ImagePath: "myvariant/",
		}))

		img, err := ImageFor(ImageKeyNode)
		Expect(err).NotTo(HaveOccurred())

		ref, err := GetReference(img, "", "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(ref).To(HavePrefix(CalicoRegistry + CalicoImagePath))
	})
})
