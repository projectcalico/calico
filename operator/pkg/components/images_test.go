// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	op "github.com/projectcalico/calico/operator/api/v1"
)

func calicoImageEntries() []TableEntry {
	var entries []TableEntry
	for _, c := range CalicoImages {
		entries = append(entries, Entry(fmt.Sprintf("a %s image correctly", c.Image), c, CalicoRegistry, CalicoImagePath))
	}
	return entries
}

var _ = Describe("test GetReference", func() {
	Context("No registry override", func() {
		DescribeTable("should render",
			func(c Component, registry, imagePath string) {
				Expect(GetReference(c, "", "", "", nil)).To(Equal(fmt.Sprintf("%s%s%s:%s", registry, imagePath, c.Image, c.Version)))
			},
			append(
				calicoImageEntries(),
				Entry("an operator init image correctly", ComponentOperatorInit, OperatorRegistry, OperatorImagePath),
			),
		)
	})

	Context("UseDefault for registry and imagepath", func() {
		DescribeTable("should render",
			func(c Component, registry, imagePath string) {
				ud := "UseDefault"
				Expect(GetReference(c, ud, ud, "", nil)).To(Equal(fmt.Sprintf("%s%s%s:%s", registry, imagePath, c.Image, c.Version)))
			},
			append(
				calicoImageEntries(),
				Entry("an operator init image correctly", ComponentOperatorInit, OperatorRegistry, OperatorImagePath),
			),
		)
	})

	Context("registry override", func() {
		DescribeTable("should render",
			func(c Component, imagePath string) {
				Expect(GetReference(c, "quay.io/", "", "", nil)).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", imagePath, c.Image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, CalicoImagePath),
			Entry("an operator init image correctly", ComponentOperatorInit, OperatorImagePath),
		)
	})

	Context("registry override not ending with slash", func() {
		DescribeTable("should render",
			func(c Component, imagePath string) {
				Expect(GetReference(c, "quay.io", "", "", nil)).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", imagePath, c.Image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, CalicoImagePath),
			Entry("an operator init image correctly", ComponentOperatorInit, OperatorImagePath),
		)
	})

	Context("image prefix override", func() {
		DescribeTable("should render",
			func(c Component, image string) {
				Expect(GetReference(c, "quay.io/", "", "prefix-", nil)).To(Equal(fmt.Sprintf("quay.io/%s:%s", image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, "calico/prefix-node"),
			Entry("an operator init image correctly", ComponentOperatorInit, "calico/prefix-operator"),
		)
	})

	Context("imagepath override", func() {
		DescribeTable("should render",
			func(c Component, registry string) {
				Expect(GetReference(c, "", "userpath/", "", nil)).To(Equal(fmt.Sprintf("%suserpath/%s:%s", registry, c.Image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, CalicoRegistry),
			Entry("an operator init image correctly", ComponentOperatorInit, OperatorRegistry),
		)
	})

	Context("imagepath override not ending in slash", func() {
		DescribeTable("should render",
			func(c Component, registry string) {
				Expect(GetReference(c, "", "userpath", "", nil)).To(Equal(fmt.Sprintf("%suserpath/%s:%s", registry, c.Image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, CalicoRegistry),
			Entry("an operator init image correctly", ComponentOperatorInit, OperatorRegistry),
		)
	})

	Context("registry and imagepath override", func() {
		DescribeTable("should render",
			func(c Component) {
				Expect(GetReference(c, "quay.io/extra/", "userpath", "", nil)).To(Equal(fmt.Sprintf("quay.io/extra/userpath/%s:%s", c.Image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode),
			Entry("an operator init image correctly", ComponentOperatorInit),
		)
	})

	Context("with an ImageSet", func() {
		DescribeTable("should render",
			func(c Component, hash string) {
				is := &op.ImageSet{
					Spec: op.ImageSetSpec{
						Images: []op.Image{
							{Image: "calico/node", Digest: "sha256:caliconodehash"},
							{Image: "calico/operator", Digest: "sha256:tigeraoperatorhash"},
						},
					},
				}
				Expect(GetReference(c, "quay.io/extra/", "userpath", "", is)).To(Equal(fmt.Sprintf("quay.io/extra/userpath/%s%s", c.Image, hash)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, "@sha256:caliconodehash"),
			Entry("an operator init image correctly", ComponentOperatorInit, "@sha256:tigeraoperatorhash"),
		)
	})

	Context("component with development imagePath", func() {
		customCalicoComponent := ComponentCalicoNode
		customCalicoComponent.ImagePath = "customcalico/"
		DescribeTable("should render",
			func(c Component, registry, imagePath string) {
				Expect(GetReference(c, "", "", "", nil)).To(Equal(fmt.Sprintf("%s%s%s:%s", registry, imagePath, c.Image, c.Version)))
			},
			Entry("a calico image correctly", customCalicoComponent, CalicoRegistry, "customcalico/"),
		)
	})

	Context("component with development registry", func() {
		customCalicoComponent := ComponentCalicoNode
		customCalicoComponent.Registry = "calico.registry.io/"
		DescribeTable("should render",
			func(c Component, registry, imagePath string) {
				Expect(GetReference(c, "", "", "", nil)).To(Equal(fmt.Sprintf("%s%s%s:%s", registry, imagePath, c.Image, c.Version)))
			},
			Entry("a calico image correctly", customCalicoComponent, "calico.registry.io/", CalicoImagePath),
		)
	})
})
