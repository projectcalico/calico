// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package imageset

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	//"k8s.io/client-go/kubernetes/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/components"
)

var _ = Describe("imageset tests", func() {
	BeforeEach(func() {
		Expect(apis.AddToScheme(kscheme.Scheme, false)).NotTo(HaveOccurred())
	})

	Context("no imageset is fine", func() {
		var c client.Client
		BeforeEach(func() {
			c = fake.NewClientBuilder().WithScheme(kscheme.Scheme).Build()
		})
		It("should not error for Calico", func() {
			e := ApplyImageSet(context.Background(), c, operator.Calico)
			Expect(e).To(BeNil())
		})
		It("should not error for Enterprise", func() {
			e := ApplyImageSet(context.Background(), c, operator.CalicoEnterprise)
			Expect(e).To(BeNil())
		})
	})

	Context("Test imageset validation", func() {
		DescribeTable("", func(v operator.ProductVariant) {
			nm := fmt.Sprintf("calico-%s", components.CalicoRelease)
			if v.IsEnterprise() {
				nm = fmt.Sprintf("enterprise-%s", components.EnterpriseRelease)
			}
			c := fake.NewClientBuilder().WithScheme(kscheme.Scheme).WithObjects(
				&operator.ImageSet{
					ObjectMeta: metav1.ObjectMeta{
						Name: nm,
					},
					Spec: operator.ImageSetSpec{
						Images: []operator.Image{
							{Image: "calico/node", Digest: "sha256:xxxxxxxxx"},
							{Image: "tigera/calico", Digest: "sha256:xxxxxxxxx"},
							{Image: "calico/calico", Digest: "sha256:xxxxxxxxx"},
						},
					},
				},
			).Build()
			Expect(ApplyImageSet(context.Background(), c, v)).To(BeNil())
			c = fake.NewClientBuilder().WithScheme(kscheme.Scheme).WithObjects(
				&operator.ImageSet{
					ObjectMeta: metav1.ObjectMeta{
						Name: nm,
					},
					Spec: operator.ImageSetSpec{
						Images: []operator.Image{
							{Image: "calico/node", Digest: "sha256:xxxxxxxxx"},
							{Image: "tigera/calico", Digest: "sha256:xxxxxxxxx"},
							{Image: "calico/calico", Digest: "sha256:xxxxxxxxx"},
							{Image: "tigera/unknown", Digest: "sha256:xxxxxxxxx"},
						},
					},
				},
			).Build()
			err := ApplyImageSet(context.Background(), c, v)
			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(ContainSubstring("unexpected images"))
			c = fake.NewClientBuilder().WithScheme(kscheme.Scheme).WithObjects(
				&operator.ImageSet{
					ObjectMeta: metav1.ObjectMeta{
						Name: nm,
					},
					Spec: operator.ImageSetSpec{
						Images: []operator.Image{
							{Image: "calico/node", Digest: "xxxxxxxxx"},
						},
					},
				},
			).Build()
			err = ApplyImageSet(context.Background(), c, v)
			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(ContainSubstring("bad digest images"))
		},
			Entry("Calico variant", operator.Calico),
			Entry("Enterprise variant", operator.CalicoEnterprise),
		)
	})

	Context("Test imageset variant handling", func() {
		DescribeTable("", func(v operator.ProductVariant) {
			isName := fmt.Sprintf("calico-%s", components.CalicoRelease)
			nonVariantISName := fmt.Sprintf("enterprise-%s", components.EnterpriseRelease)
			isNameWrongVer := "calico-wrong"
			if v.IsEnterprise() {
				isName = fmt.Sprintf("enterprise-%s", components.EnterpriseRelease)
				nonVariantISName = fmt.Sprintf("calico-%s", components.CalicoRelease)
				isNameWrongVer = "enterprise-wrong"
			}
			isSpec := operator.ImageSetSpec{
				Images: []operator.Image{
					{Image: "calico/node", Digest: "sha256:xxxxxxxxx"},
					{Image: "tigera/calico", Digest: "sha256:xxxxxxxxx"},
					{Image: "calico/calico", Digest: "sha256:xxxxxxxxx"},
				},
			}
			c := fake.NewClientBuilder().WithScheme(kscheme.Scheme).WithObjects(
				&operator.ImageSet{
					ObjectMeta: metav1.ObjectMeta{
						Name: isNameWrongVer,
					},
					Spec: isSpec,
				},
			).Build()
			// Expect this to error because the ImageSet doesn't have the correct
			// version
			Expect(ApplyImageSet(context.Background(), c, v)).ToNot(BeNil())

			// With only a variant ImageSet check this returns false
			x, err := DoesNonVariantImageSetExist(context.Background(), c, v)
			Expect(err).To(BeNil())
			Expect(x).To(BeFalse())

			c = fake.NewClientBuilder().WithScheme(kscheme.Scheme).WithObjects().Build()
			// With no ImageSet check this returns false
			x, err = DoesNonVariantImageSetExist(context.Background(), c, v)
			Expect(err).To(BeNil())
			Expect(x).To(BeFalse())

			c = fake.NewClientBuilder().WithScheme(kscheme.Scheme).WithObjects(
				&operator.ImageSet{
					ObjectMeta: metav1.ObjectMeta{
						Name: nonVariantISName,
					},
					Spec: isSpec,
				},
			).Build()
			// Having an ImageSet for the other variant should not produce
			// an error
			Expect(ApplyImageSet(context.Background(), c, v)).To(BeNil())

			// With a non-variant ImageSet check this returns true
			x, err = DoesNonVariantImageSetExist(context.Background(), c, v)
			Expect(err).To(BeNil())
			Expect(x).To(BeTrue())

			c = fake.NewClientBuilder().WithScheme(kscheme.Scheme).WithObjects(
				&operator.ImageSet{
					ObjectMeta: metav1.ObjectMeta{
						Name: nonVariantISName,
					},
					Spec: isSpec,
				},
				&operator.ImageSet{
					ObjectMeta: metav1.ObjectMeta{
						Name: isNameWrongVer,
					},
					Spec: isSpec,
				},
			).Build()
			// Expect this to error because the ImageSet doesn't have the correct
			// version
			Expect(ApplyImageSet(context.Background(), c, v)).ToNot(BeNil())

			c = fake.NewClientBuilder().WithScheme(kscheme.Scheme).WithObjects(
				&operator.ImageSet{
					ObjectMeta: metav1.ObjectMeta{
						Name: isName,
					},
					Spec: isSpec,
				},
				&operator.ImageSet{
					ObjectMeta: metav1.ObjectMeta{
						Name: isNameWrongVer,
					},
					Spec: isSpec,
				},
			).Build()
			// Expect no error because a correct ImageSet exists
			Expect(ApplyImageSet(context.Background(), c, v)).To(BeNil())
		},
			Entry("Calico variant", operator.Calico),
			Entry("Enterprise variant", operator.CalicoEnterprise),
		)
	})
})
