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

// otherVariant is the variant a downstream build declares outside this repo.
var otherVariant = Variant{Registry: "example.com/", ImagePath: "myvariant/"}

// otherVariantNode stands in for the node image a variant supplies instead of this
// build's own.
var otherVariantNode = Component{Image: ImageKeyNode, Version: "v9.9.9", Variant: otherVariant}

var _ = Describe("ImageFor", func() {
	// The component list is the source of truth, so a key that stops naming an entry
	// in it would make ImageFor error at render time.
	It("names an entry in the list this build ships", func() {
		for _, key := range ImageKeys {
			_, ok := byImage(CalicoImages)[key]
			Expect(ok).To(BeTrue(), "image for %q", key)
		}
	})

	It("resolves the images this build ships when no variant registered", func() {
		img, err := ImageFor(ImageKeyNode)
		Expect(err).NotTo(HaveOccurred())
		Expect(img).To(Equal(ComponentCalicoNode))
	})

	It("resolves what the variant registered", func() {
		DeferCleanup(UseBuild(Build{Images: []Component{otherVariantNode}}))

		img, err := ImageFor(ImageKeyNode)
		Expect(err).NotTo(HaveOccurred())
		Expect(img).To(Equal(otherVariantNode))
	})

	It("errors on an image the running variant does not supply", func() {
		DeferCleanup(UseBuild(Build{Images: []Component{otherVariantNode}}))

		_, err := ImageFor("whisker")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("RegisterBuild", func() {
	// A variant declares its components outside this package, naming the registry and
	// image path they resolve against.
	thing := Component{Image: "thing", Version: "v1.0.0", Variant: otherVariant}

	build := Build{Images: []Component{thing}, Release: "v9.9.9"}

	It("resolves registered images against the variant they name", func() {
		DeferCleanup(UseBuild(build))

		img, err := ImageFor("thing")
		Expect(err).NotTo(HaveOccurred())

		ref, err := GetReference(img, "", "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(ref).To(Equal("example.com/myvariant/thing:v1.0.0"))
	})

	// The image path is also the key an ImageSet lists images under, so a wrong one
	// stops digests resolving rather than just changing the registry.
	It("looks an ImageSet digest up under the variant's image path", func() {
		DeferCleanup(UseBuild(build))

		img, err := ImageFor("thing")
		Expect(err).NotTo(HaveOccurred())

		is := &operator.ImageSet{Spec: operator.ImageSetSpec{Images: []operator.Image{
			{Image: "myvariant/thing", Digest: "sha256:cafe"},
		}}}
		ref, err := GetReference(img, "", "", "", is)
		Expect(err).NotTo(HaveOccurred())
		Expect(ref).To(Equal("example.com/myvariant/thing@sha256:cafe"))
	})

	It("lets the installation override the variant's defaults", func() {
		DeferCleanup(UseBuild(build))

		img, err := ImageFor("thing")
		Expect(err).NotTo(HaveOccurred())

		ref, err := GetReference(img, "registry.io/", "custom/", "", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(ref).To(Equal("registry.io/custom/thing:v1.0.0"))
	})

	It("reports the registered release, and the Calico one when nothing registered", func() {
		Expect(BuildRelease()).To(Equal(CalicoRelease))

		restore := UseBuild(build)
		DeferCleanup(restore)
		Expect(BuildRelease()).To(Equal("v9.9.9"))

		restore()
		Expect(BuildRelease()).To(Equal(CalicoRelease))
	})

	// A downstream declaring its components outside this package is the only caller,
	// so this is where a bad declaration is still cheap to find.
	DescribeTable("rejects an image it cannot resolve",
		func(c Component) {
			// A registration that wrongly succeeds would leak into the specs after this
			// one, hiding which of them the guard actually covers.
			DeferCleanup(UseBuild(Build{}))

			Expect(func() { RegisterBuild(Build{Images: []Component{c}}) }).To(Panic())
			Expect(BuildRelease()).To(Equal(CalicoRelease))
		},
		Entry("one naming no variant", Component{Image: "thing", Version: "v1.0.0"}),
		Entry("one with no name, which every other one would key over",
			Component{Version: "v1.0.0", Variant: otherVariant}),
	)
})
